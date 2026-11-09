
import streamlit as st
import requests
import os
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime

# --------------------------------
# CONFIGURATION
# --------------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
API_KEY = os.getenv("GNANI_API_KEY")

st.set_page_config(
    page_title="ScamSathi AI",
    page_icon="🛡️",
    layout="wide"
)

# --------------------------------
# CUSTOM DESIGN
# --------------------------------

st.markdown("""
<style>
.stApp {
    background-color: #0b1220;
    color: #f1f5f9;
}

.block-container {
    padding-top: 2rem;
    max-width: 1200px;
}

.hero {
    background: linear-gradient(120deg, #14233d, #183c59);
    padding: 28px;
    border-radius: 16px;
    border: 1px solid #294765;
    margin-bottom: 22px;
}

.hero h1 {
    color: #ffffff;
    margin-bottom: 5px;
}

.hero p {
    color: #cbd5e1;
    margin-bottom: 0;
}

.section-card {
    background: #131f32;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #263a54;
    margin-bottom: 14px;
}

.small-muted {
    color: #a9b8ca;
    font-size: 13px;
}

div[data-testid="stMetric"] {
    background: #131f32;
    padding: 15px;
    border-radius: 12px;
    border: 1px solid #263a54;
}

.stButton button {
    border-radius: 9px;
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)


# --------------------------------
# RISK ANALYSIS ENGINE
# ENGLISH + KANNADA DETECTION
# --------------------------------

def analyze_scam(transcript):

    text = transcript.lower()

    patterns = {

        "Sensitive information requests": {
            "keywords": [
                # English
                "otp",
                "one time password",
                "one-time password",
                "password",
                "cvv",
                "pin",
                "bank details",
                "account number",

                # Kannada
                "ಒಟಿಪಿ",
                "ಒಟಿಪಿಯನ್ನು",
                "ಒನ್ ಟೈಮ್ ಪಾಸ್ವರ್ಡ್",
                "ಪಾಸ್ವರ್ಡ್",
                "ಸಿವಿವಿ",
                "ಪಿನ್",
                "ಬ್ಯಾಂಕ್ ವಿವರಗಳು",
                "ಖಾತೆ ಸಂಖ್ಯೆ"
            ],
            "points": 85
        },

        "Urgent payment requests": {
            "keywords": [
                # English
                "transfer money",
                "send money",
                "upi payment",
                "pay immediately",
                "urgent payment",
                "make a payment",

                # Kannada
                "ಹಣ ವರ್ಗಾಯಿಸಿ",
                "ಹಣ ಕಳುಹಿಸಿ",
                "ತಕ್ಷಣ ಪಾವತಿಸಿ",
                "ಕೂಡಲೇ ಪಾವತಿಸಿ",
                "ಹಣ ಪಾವತಿಸಿ"
            ],
            "points": 35
        },

        "Threatening or pressuring language": {
            "keywords": [
                # English
                "account blocked",
                "account will be blocked",
                "account may be blocked",
                "blocked today",
                "police case",
                "arrest",
                "legal action",
                "immediately",
                "right now",
                "within one hour",

                # Kannada
                "ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ",
                "ಬ್ಲಾಕ್ ಆಗಲಿದೆ",
                "ಖಾತೆ ಬ್ಲಾಕ್",
                "ಖಾತೆಯನ್ನು ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ",
                "ಖಾತೆ ಸ್ಥಗಿತ",
                "ತಕ್ಷಣ",
                "ಕೂಡಲೇ",
                "ಪೊಲೀಸ್ ಪ್ರಕರಣ",
                "ಬಂಧಿಸಲಾಗುತ್ತದೆ",
                "ಕಾನೂನು ಕ್ರಮ"
            ],
            "points": 25
        },

        "Suspicious links or access requests": {
            "keywords": [
                # English
                "click this link",
                "download this app",
                "remote access",
                "screen sharing",
                "share your screen",
                "install this application",

                # Kannada
                "ಈ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಿ",
                "ಈ ಆಪ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ",
                "ಸ್ಕ್ರೀನ್ ಹಂಚಿಕೊಳ್ಳಿ",
                "ರಿಮೋಟ್ ಆಕ್ಸೆಸ್"
            ],
            "points": 35
        },

        "Suspicious identity or KYC claims": {
            "keywords": [
                # English
                "bank officer",
                "calling from your bank",
                "customer care",
                "government officer",
                "kyc update",
                "kyc verification",
                "verify your account",
                "lottery winner",
                "prize money",

                # Kannada
                "ನಿಮ್ಮ ಬ್ಯಾಂಕಿನಿಂದ ಕರೆ",
                "ಬ್ಯಾಂಕಿನಿಂದ ಕರೆ ಮಾಡುತ್ತಿದ್ದೇನೆ",
                "ಕೆವೈಸಿ ಪರಿಶೀಲನೆ",
                "ಕೆವೈಸಿ ಪರೀಕ್ಷೆ",
                "ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ"
            ],
            "points": 15
        }
    }

    detected = []
    score = 0

    for category, details in patterns.items():

        matched = [
            word for word in details["keywords"]
            if word in text
        ]

        if matched:

            score += details["points"]

            detected.append({
                "category": category,
                "keywords": matched,
                "points": details["points"]
            })

    score = min(score, 100)

    if score >= 70:

        risk = "HIGH"

        recommendation = (
            "Strong warning signs were detected. Do not share OTPs, "
            "passwords, PINs or banking information. Do not transfer "
            "money based on this call. Contact the organisation using "
            "its official contact details."
        )

    elif score >= 35:

        risk = "MEDIUM"

        recommendation = (
            "Suspicious signals were detected. Do not rush into "
            "payments or sharing personal information. Verify the "
            "caller's identity through an official channel."
        )

    else:

        risk = "LOW"

        recommendation = (
            "Few or no matching warning patterns were detected. "
            "This does not guarantee that the call is safe. Never "
            "share OTPs, passwords or banking credentials."
        )

    return score, risk, detected, recommendation


# --------------------------------
# REPORT GENERATOR
# --------------------------------

def create_report(item):

    report = f"""
SCAMSATHI AI - CALL ANALYSIS REPORT
===================================

Date: {item['date']}

Risk Score: {item['score']}/100
Risk Level: {item['risk']}

CALL TRANSCRIPT
---------------
{item['transcript']}

DETECTED WARNING SIGNALS
------------------------
"""

    if item["detected"]:

        for signal in item["detected"]:

            report += (
                f"\n{signal['category']}\n"
                f"Matched terms: {', '.join(signal['keywords'])}\n"
                f"Points: {signal['points']}\n"
            )

    else:

        report += "\nNo matching warning patterns found.\n"

    report += (
        "\nSAFETY RECOMMENDATION\n"
        "---------------------\n"
        + item["recommendation"]
    )

    report += (
        "\n\nDISCLAIMER\n"
        "This is a preliminary rule-based screening, not a confirmed "
        "scam verdict. Speech recognition errors and context may "
        "affect the result. A low-risk score does not guarantee "
        "that a call is safe.\n"
    )

    return report


# --------------------------------
# SESSION HISTORY
# --------------------------------

if "history" not in st.session_state:
    st.session_state.history = []

if "latest_result" not in st.session_state:
    st.session_state.latest_result = None


# --------------------------------
# SIDEBAR
# --------------------------------

with st.sidebar:

    st.title("🛡️ ScamSathi AI")

    st.caption("Your call safety companion")

    st.divider()

    st.markdown("### How it works")

    st.write("1. Upload a call recording")
    st.write("2. Prisma converts speech into text")
    st.write("3. English and Kannada warning patterns are checked")
    st.write("4. Risk score and safety advice appear")

    st.divider()

    st.markdown("### Technology")

    st.write("🎙️ Gnani AI Prisma v3.0")
    st.write("🐍 Python")
    st.write("⚡ Streamlit")

    st.divider()

    st.caption("Project prototype | 2026")


# --------------------------------
# MAIN HEADER
# --------------------------------

st.markdown("""
<div class="hero">
    <h1>🛡️ ScamSathi AI</h1>
    <p>Multilingual AI-Powered Scam Call Detection</p>
    <p class="small-muted">
        Analyze suspicious calls, identify potential fraud signals,
        and receive safety recommendations.
    </p>
</div>
""", unsafe_allow_html=True)


tab_analyze, tab_history, tab_about = st.tabs([
    "🔍 Analyze Call",
    "📋 Analysis History",
    "ℹ️ About"
])


# --------------------------------
# ANALYZE CALL TAB
# --------------------------------

with tab_analyze:

    st.subheader("Upload and Analyze")

    st.write(
        "Upload a call recording to check for potential "
        "fraud warning signs."
    )

    audio_file = st.file_uploader(
        "Choose an audio recording",
        type=["wav", "mp3", "m4a", "ogg", "flac", "aac"]
    )

    if audio_file is not None:

        st.audio(audio_file)

        if st.button("🔍 Analyze Call", type="primary"):

            if not API_KEY:

                st.error(
                    "API key not found. Check your .env file."
                )

            else:

                try:

                    with st.spinner(
                        "Prisma AI is transcribing your recording..."
                    ):

                        response = requests.post(
                            "https://api.vachana.ai/stt/v3",

                            headers={
                                "X-API-Key-ID": API_KEY
                            },

                            files={
                                "audio_file": (
                                    audio_file.name,
                                    audio_file.getvalue(),
                                    audio_file.type or "application/octet-stream"
                                )
                            },

                            data={
                                "model": "prisma-v3.0",
                                "language_code": "indic-auto"
                            },

                            timeout=90
                        )

                    if response.ok:

                        result = response.json()

                        transcript = result.get("transcript", "")

                        if not transcript.strip():

                            st.warning(
                                "No speech was detected. "
                                "Please try another recording."
                            )

                        else:

                            with st.spinner(
                                "Checking for suspicious patterns..."
                            ):

                                score, risk, detected, recommendation = (
                                    analyze_scam(transcript)
                                )

                            item = {
                                "date": datetime.now().strftime(
                                    "%d-%m-%Y %H:%M"
                                ),
                                "filename": audio_file.name,
                                "transcript": transcript,
                                "score": score,
                                "risk": risk,
                                "detected": detected,
                                "recommendation": recommendation
                            }

                            st.session_state.latest_result = item

                            st.session_state.history.insert(0, item)

                            st.success(
                                "Call analysis completed successfully!"
                            )

                    else:

                        st.error(
                            f"API Error {response.status_code}: "
                            f"{response.text[:500]}"
                        )

                except requests.exceptions.RequestException as error:

                    st.error(f"Connection error: {error}")

                except ValueError:

                    st.error(
                        "Could not read the API response. "
                        "Please try again."
                    )

    # DISPLAY LATEST RESULT

    item = st.session_state.latest_result

    if item is not None:

        st.divider()

        st.subheader("📝 Call Transcript")

        st.write(item["transcript"])

        st.caption("Speech Recognition: Gnani AI Prisma v3.0")

        st.divider()

        st.subheader("🛡️ Risk Assessment")

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric("Risk Score", f"{item['score']}/100")

        with col2:

            st.metric("Risk Level", item["risk"])

        with col3:

            st.metric(
                "Warning Categories",
                len(item["detected"])
            )

        st.progress(item["score"] / 100)

        if item["risk"] == "HIGH":

            st.error(
                "🚨 HIGH RISK — Strong warning signals detected."
            )

        elif item["risk"] == "MEDIUM":

            st.warning(
                "⚠️ MEDIUM RISK — Suspicious signals detected."
            )

        else:

            st.success(
                "✅ LOW RISK — Few or no matching signals detected."
            )

        st.divider()

        st.subheader("🔎 Detected Warning Signals")

        if item["detected"]:

            for signal in item["detected"]:

                with st.expander(
                    signal["category"]
                    + f" (+{signal['points']} points)"
                ):

                    st.write(
                        "**Matched terms:** "
                        + ", ".join(signal["keywords"])
                    )

        else:

            st.write("No matching warning patterns found.")

        st.divider()

        st.subheader("💡 Safety Recommendation")

        st.info(item["recommendation"])

        st.download_button(
            "📄 Download Analysis Report",
            data=create_report(item),
            file_name="ScamSathi_Analysis_Report.txt",
            mime="text/plain"
        )

        st.caption(
            "This is a preliminary rule-based screening, not a "
            "confirmed scam verdict. A low-risk result does not "
            "guarantee that a call is safe."
        )


# --------------------------------
# HISTORY TAB
# --------------------------------

with tab_history:

    st.subheader("📋 Previous Call Analyses")

    history = st.session_state.history

    if history:

        st.write(
            f"Analyses in this session: {len(history)}"
        )

        for index, item in enumerate(history):

            with st.expander(
                f"{item['filename']} | {item['risk']} "
                f"| {item['score']}/100 | {item['date']}"
            ):

                st.write("**Transcript:**")

                st.write(item["transcript"])

                st.write(
                    f"**Risk:** {item['risk']} "
                    f"({item['score']}/100)"
                )

                st.download_button(
                    "Download this report",
                    data=create_report(item),
                    file_name=f"ScamSathi_Report_{index + 1}.txt",
                    mime="text/plain",
                    key=f"history_download_{index}"
                )

    else:

        st.info(
            "No analysis history yet. Analyze a call to see it here."
        )

    st.caption(
        "History is stored only during the current app session. "
        "It is not permanently saved."
    )


# --------------------------------
# ABOUT TAB
# --------------------------------

with tab_about:

    st.subheader("About ScamSathi AI")

    st.write(
        "ScamSathi AI is a prototype designed to help users "
        "understand suspicious phone calls."
    )

    st.markdown("### Key Features")

    st.write("- Multilingual audio transcription")
    st.write("- English and Kannada warning phrase detection")
    st.write("- Risk scoring from 0 to 100")
    st.write("- Safety recommendations")
    st.write("- Downloadable call analysis reports")
    st.write("- Session-based analysis history")

    st.markdown("### Technology Used")

    st.write("- Gnani AI Prisma v3.0")
    st.write("- Python")
    st.write("- Streamlit")
    st.write("- Requests and Python dotenv")

    st.warning(
        "ScamSathi AI is an experimental screening tool. "
        "It does not confirm whether a call is genuine or fraudulent. "
        "Always verify important requests independently."
    )


# --------------------------------
# FOOTER
# --------------------------------

st.divider()

st.caption(
    "🛡️ ScamSathi AI | Powered by Gnani AI Prisma v3.0"
)
