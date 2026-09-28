import os

import json
import requests
from flask import Flask, request, abort
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage, FlexSendMessage

threat_api_token = ''
threat_api_client_key = os.getenv('THREAT_API_CLIENT_KEY', '')
threat_api_token_url = os.getenv('THREAT_API_TOKEN_URL', '')
threat_api_reputation_url = os.getenv('THREAT_API_REPUTATION_URL', '')
debug_print_enabled = False

def debug_print(msg):
    global debug_print_enabled
    if debug_print_enabled:
        print(msg)

def get_threat_api_token():
    global threat_api_client_key, threat_api_token
    headers = {'Client-Key': threat_api_client_key}
    response = requests.get(threat_api_token_url, headers=headers)
    if response.status_code == 200:
        threat_api_token = str(response.text)
    else:
        debug_print(threat_api_token)

def get_url_reputation(url_str):
    global threat_api_client_key, threat_api_token
    get_threat_api_token()
    headers = {
        'Client-Key': threat_api_client_key,
        'Content-Type': 'application/json',
        'token': threat_api_token
    }
    data = {
        'request': [
            {'resource': url_str}
        ]
    }
    response = requests.post(
        threat_api_reputation_url,
        headers=headers,
        json=data,
        params={'resource': url_str},
    )
    json_data = response.json()
    debug_print(json_data)
    categories = ''
    protection_name = ''
    indications = ''
    context = json_data['response'][0]['context']

    if 'categories' in context:
        categories = ', '.join([cat['name'] for cat in context['categories']])

    if 'protection_name' in context:
        protection_name = context['protection_name']

    if 'indications' in context:
        indications = ', '.join(context['indications'])

    r = {
        'url': str(json_data['response'][0]['resource']),
        'classification': str(json_data['response'][0]['reputation']['classification']),
        'severity': str(json_data['response'][0]['reputation']['severity']),
        'confidence': str(json_data['response'][0]['reputation']['confidence']),
        'risk': str(json_data['response'][0]['risk']),
        'categories': str(categories),
        'protection_name': str(protection_name),
        'indications': str(indications)
    }
    if response.status_code == 200:
        return r
    else:
        debug_print(json_data)

app = Flask(__name__)

# Line Bot configuration
LINE_CHANNEL_ACCESS_TOKEN = os.getenv('LINE_CHANNEL_ACCESS_TOKEN', '')
LINE_CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET', '')
line_bot_api = LineBotApi(LINE_CHANNEL_ACCESS_TOKEN)
handler = WebhookHandler(LINE_CHANNEL_SECRET)

@app.route("/callback", methods=['POST'])
def callback():
    signature = request.headers['X-Line-Signature']
    body = request.get_data(as_text=True)
    app.logger.info("Request body: " + body)

    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)

    return 'OK'


def get_light_color(classification, risk):
    risk = risk.lower()
    if "Infecting URL" in classification or "CnC Server" in classification or "Compromised Website" in classification or "Phishing" in classification or "Infecting Website" in classification or "Spam" in classification or "Cryptominer" in classification or "Volatile Website" in classification:
        return "red"
    elif "Web Hosting" in classification or "File Hosting" in classification or "Parked" in classification or "Unclassified" in classification:
        return "yellow"
    else:
        return "green"


@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    user_message = event.message.text

    if user_message.startswith("/url "):
        url = user_message[5:].strip()  # Extract the URL after "/url "
        url_info = get_url_reputation(url)

        if url_info:
            light_color = get_light_color(url_info['classification'], url_info['risk'])

            # Define image URLs for each light color
            light_images = {
                "red": "https://www.pngall.com/wp-content/uploads/14/Red-Light-PNG-Cutout.png",
                "yellow": "https://png.pngtree.com/png-clipart/20201029/ourmid/pngtree-circle-clipart-orange-yellow-circle-png-image_2381941.jpg",
                "green": "https://www.pngall.com/wp-content/uploads/14/Green-Circle-PNG-Images.png"
            }

            flex_message = {
                "type": "bubble",
                "hero": {
                    "type": "image",
                    "url": light_images[light_color],
                    "size": "full",
                    "aspectRatio": "1:1",
                    "aspectMode": "cover"
                },
                "body": {
                    "type": "box",
                    "layout": "vertical",
                    "contents": [
                        {
                            "type": "text",
                            "text": "SilverSafe",
                            "weight": "bold",
                            "size": "xl",
                            "contents": []
                        },
                        {
                            "type": "text",
                            "text": f"URL: {url_info['url']}",
                            "size": "xl",
                            "wrap": True
                        },
                        {
                            "type": "text",
                            "text": f"Classification: {url_info['classification']}",
                            "size": "xl",
                            "wrap": True
                        },
                        {
                            "type": "text",
                            "text": f"Confidence: {url_info['confidence']}",
                            "size": "xl",
                            "wrap": True
                        },
                        {
                            "type": "text",
                            "text": f"Risk: {url_info['risk']}",
                            "size": "xl",
                            "wrap": True
                        },
                        {
                            "type": "text",
                            "text": f"Categories: {url_info['categories']}",
                            "size": "xl",
                            "wrap": True
                        },
                        {
                            "type": "text",
                            "text": f"Indications: {url_info['indications']}",
                            "size": "xl",
                            "wrap": True
                        }
                    ]
                },
                "footer": {
                    "type": "box",
                    "layout": "vertical",
                    "spacing": "sm",
                    "contents": [
                        {
                            "type": "button",
                            "style": "primary",
                            "height": "sm",
                            "action": {
                                "type": "uri",
                                "uri": "https://www.fdic.gov/consumer-resource-center/2021-10/avoiding-scams-and-scammers",
                                "label": "How to avoid online scams?"
                            }
                        }
                    ],
                    "flex": 0
                }
            }

            flex_message = FlexSendMessage(alt_text="URL Information", contents=flex_message)
            line_bot_api.reply_message(event.reply_token, flex_message)
        else:
            response = "Unable to retrieve information for the given URL."

        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=response))
    else:
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text="Please use the format '/url <your_url>' to get URL information."))

if __name__ == "__main__":
    app.run()

