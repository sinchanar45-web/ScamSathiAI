
# ScamSathi AI
### Multilingual AI-Assisted Scam Call Detection

ScamSathi AI is a web application that analyzes suspicious call recordings and highlights potential scam warning signals.

## Problem Statement
Phone scams can target people through different languages and use urgency, threats, fake bank identities, and requests for sensitive information.

## Solution
ScamSathi AI uses Gnani AI's Prisma v3.0 speech-to-text technology to transcribe audio recordings. It then applies a transparent Python-based rule engine to identify potential warning signals and calculate a preliminary risk score.

## Features
- Audio recording upload
- Multilingual speech transcription using Gnani AI Prisma v3.0
- English and Kannada warning phrase detection
- Weighted risk scoring
- HIGH, MEDIUM, and LOW risk levels
- Safety recommendations
- Downloadable analysis reports
- Session-based analysis history

## Technology Stack
- Python
- Streamlit
- Gnani AI Prisma v3.0 API
- Requests
- Python-dotenv

## How It Works
1. User uploads a call recording.
2. Gnani AI Prisma v3.0 converts speech into text.
3. The Python rule engine checks the transcript for suspicious phrases.
4. Warning signals receive weighted scores.
5. The application displays a preliminary risk level and safety recommendations.
6. The user can download the analysis report.

## Risk Scoring
- Sensitive information requests: 85 points
- Urgent payment requests: 35 points
- Threatening or pressuring language: 25 points
- Suspicious links or access requests: 35 points
- Suspicious identity or KYC claims: 15 points

The final score is capped at 100.

- HIGH: 70–100
- MEDIUM: 35–69
- LOW: 0–34

## Installation

1. Clone or download this repository.
2. Install dependencies:

   `python -m pip install -r requirements.txt`

3. Create a `.env` file in the project folder:

   `GNANI_API_KEY=your_api_key_here`

4. Run the application:

   `python -m streamlit run app.py`

## Important Limitations
- The current warning detection uses predefined English and Kannada phrases.
- It may miss scams or flag harmless conversations.
- Transcription errors can affect results.
- A LOW score does not guarantee that a call is safe.
- The risk score is a preliminary warning, not a confirmed fraud verdict.
- API credentials must be kept private.

## Future Improvements
- Support for more Indian languages.
- Context-aware scam detection.
- Improved detection of false positives.
- Secure and persistent analysis history.
- Additional AI reasoning and voice technologies.

## Disclaimer
ScamSathi AI is an awareness and preliminary screening tool. It does not replace professional fraud investigation or official banking verification.
