import ast
import unittest
from pathlib import Path


def load_extraction_function():
    source_path = Path(__file__).parents[1] / "English_Version.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    selected_nodes = [
        node
        for node in tree.body
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "URL_PATTERN"
                for target in node.targets
            )
        )
        or (isinstance(node, ast.FunctionDef) and node.name == "extract_url")
    ]

    namespace = {"re": __import__("re")}
    module = ast.Module(body=selected_nodes, type_ignores=[])
    exec(compile(module, source_path, "exec"), namespace)
    return namespace["extract_url"]


class UrlExtractionTests(unittest.TestCase):
    def setUp(self):
        self.extract_url = load_extraction_function()

    def test_extracts_link_from_natural_message(self):
        message = (
            "Congrats! You won a $500 shopping prize. "
            "Claim your prize at https://prize.example/claim-now!"
        )
        self.assertEqual(self.extract_url(message), "https://prize.example/claim-now")

    def test_adds_scheme_to_www_link(self):
        self.assertEqual(
            self.extract_url("Please check www.example.org/account"),
            "https://www.example.org/account",
        )

    def test_returns_none_when_no_link_exists(self):
        self.assertIsNone(self.extract_url("Is this message suspicious?"))

    def test_removes_sentence_punctuation(self):
        self.assertEqual(
            self.extract_url("Check https://example.net/path."),
            "https://example.net/path",
        )


if __name__ == "__main__":
    unittest.main()
