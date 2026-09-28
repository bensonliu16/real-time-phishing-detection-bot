# Real-Time Phishing Detection Bot

A LINE bot that checks submitted URLs against a threat-reputation service and
returns a readable risk report. The project includes English and Chinese
response flows and deploys as a small Flask webhook application.

## Features

- Accepts URLs through LINE messages
- Requests URL reputation and threat details from the Check Point API
- Returns classification, risk, categories, protection, and indication data
- Formats results as LINE Flex Messages
- Includes English and Chinese response modules

## How it works

1. LINE sends a signed webhook request to `POST /callback`.
2. The Flask app validates the request signature.
3. A `/url <address>` message is sent to the reputation API.
4. The bot formats the response and replies to the user in LINE.

## Project structure

```text
.
├── app.py                # Main Flask and LINE webhook application
├── English_Version.py    # English URL-report flow
├── Chinese_Version.py    # Chinese URL-report flow
├── Function.py           # LINE rich-menu/message helpers
├── new.py                # Additional LINE message helper
├── Procfile              # Process entry point
└── requirements.txt      # Runtime dependencies
```

## Local setup

1. Create and activate a Python virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Set these environment variables using credentials from your own service
   accounts:

   ```text
   LINE_CHANNEL_ACCESS_TOKEN
   LINE_CHANNEL_SECRET
   CHECKPOINT_CLIENT_KEY
   ```

4. Start the application:

   ```bash
   python app.py
   ```

5. Configure the LINE webhook URL to point to `/callback` on your HTTPS host.

## Security

Real tokens and API keys must never be committed. This repository reads all
credentials from environment variables; `.env` files, logs, virtual
environments, IDE settings, and temporary images are excluded by `.gitignore`.

If a credential was previously committed anywhere, revoke it and generate a
replacement before running the project.

## Built with

Python · Flask · LINE Bot SDK · Check Point URL Reputation API

