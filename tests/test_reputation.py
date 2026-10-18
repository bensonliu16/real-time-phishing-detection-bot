import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class FakeHandler:
    def __init__(self, _secret):
        pass

    def add(self, *_args, **_kwargs):
        return lambda function: function

    def handle(self, *_args, **_kwargs):
        return None


class FakeFlask:
    def __init__(self, _name):
        self.logger = types.SimpleNamespace(info=lambda *_args: None)

    def route(self, *_args, **_kwargs):
        return lambda function: function


class FakeResponse:
    def __init__(self, *, status_code=200, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def json(self):
        return self._payload


def load_reputation_module():
    fake_flask = types.ModuleType("flask")
    fake_flask.Flask = FakeFlask
    fake_flask.request = types.SimpleNamespace(headers={}, get_data=lambda **_kwargs: "")
    fake_flask.abort = lambda code: code

    fake_linebot = types.ModuleType("linebot")
    fake_linebot.LineBotApi = lambda _token: types.SimpleNamespace(reply_message=lambda *_args: None)
    fake_linebot.WebhookHandler = FakeHandler

    fake_exceptions = types.ModuleType("linebot.exceptions")
    fake_exceptions.InvalidSignatureError = type("InvalidSignatureError", (Exception,), {})

    fake_models = types.ModuleType("linebot.models")
    for name in ("MessageEvent", "TextMessage", "TextSendMessage", "FlexSendMessage"):
        setattr(fake_models, name, type(name, (), {"__init__": lambda self, **kwargs: self.__dict__.update(kwargs)}))

    fake_requests = types.ModuleType("requests")
    fake_requests.get = lambda *_args, **_kwargs: FakeResponse()
    fake_requests.post = lambda *_args, **_kwargs: FakeResponse()

    module_path = Path(__file__).parents[1] / "English_Version.py"

    environment = {
        "LINE_CHANNEL_ACCESS_TOKEN": "test-line-token",
        "LINE_CHANNEL_SECRET": "test-line-secret",
        "THREAT_API_CLIENT_KEY": "test-client-key",
        "THREAT_API_TOKEN_URL": "https://provider.example/token",
        "THREAT_API_REPUTATION_URL": "https://provider.example/reputation",
    }
    with patch.dict(os.environ, environment, clear=False), patch.dict(
        sys.modules,
        {
            "flask": fake_flask,
            "linebot": fake_linebot,
            "linebot.exceptions": fake_exceptions,
            "linebot.models": fake_models,
            "requests": fake_requests,
        },
    ):
        spec = importlib.util.spec_from_file_location("reputation_under_test", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def lookup(module, url):
    function = getattr(module, "get_url_reputation", None)
    if function is None:
        function = module.cp_get_url_rep
    return function(url)


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.module = load_reputation_module()

    def test_known_threats_are_red(self):
        for classification in ("Phishing", "Spam", "Cryptominer"):
            with self.subTest(classification=classification):
                self.assertEqual(self.module.get_light_color(classification, "high"), "red")

    def test_uncertain_categories_are_yellow(self):
        for classification in ("Web Hosting", "File Hosting", "Unclassified"):
            with self.subTest(classification=classification):
                self.assertEqual(self.module.get_light_color(classification, "medium"), "yellow")

    def test_benign_category_is_green(self):
        self.assertEqual(self.module.get_light_color("Benign", "low"), "green")


class ReputationParsingTests(unittest.TestCase):
    def setUp(self):
        self.module = load_reputation_module()

    def test_complete_response_is_normalized(self):
        payload = {
            "response": [
                {
                    "resource": "https://example.com",
                    "reputation": {
                        "classification": "Benign",
                        "severity": "Low",
                        "confidence": "High",
                    },
                    "risk": 0,
                    "context": {
                        "categories": [{"name": "Reference"}],
                        "protection_name": "",
                        "indications": ["none"],
                    },
                }
            ]
        }
        token_response = FakeResponse(text="temporary-token")
        reputation_response = FakeResponse(payload=payload)
        self.module.requests.get = lambda *_args, **_kwargs: token_response
        self.module.requests.post = lambda *_args, **_kwargs: reputation_response

        result = lookup(self.module, "https://example.com")

        self.assertEqual(result["classification"], "Benign")
        self.assertEqual(result["confidence"], "High")
        self.assertEqual(result["categories"], "Reference")
        self.assertEqual(result["indications"], "none")

    def test_optional_context_fields_may_be_absent(self):
        payload = {
            "response": [
                {
                    "resource": "https://example.org",
                    "reputation": {
                        "classification": "Unclassified",
                        "severity": "Unknown",
                        "confidence": "Low",
                    },
                    "risk": "Unknown",
                    "context": {},
                }
            ]
        }
        self.module.requests.get = lambda *_args, **_kwargs: FakeResponse(text="token")
        self.module.requests.post = lambda *_args, **_kwargs: FakeResponse(payload=payload)

        result = lookup(self.module, "https://example.org")

        self.assertEqual(result["categories"], "")
        self.assertEqual(result["protection_name"], "")
        self.assertEqual(result["indications"], "")


if __name__ == "__main__":
    unittest.main()

