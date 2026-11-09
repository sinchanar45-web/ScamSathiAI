import streamlit as st
import requests
import os
import io
import uuid
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)

# --------------------------------
# CONFIGURATION
# --------------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

API_KEY = os.getenv("GNANI_API_KEY")

if not API_KEY:
    try:
        API_KEY = st.secrets.get("GNANI_API_KEY")
    except Exception:
        API_KEY = None

API_URL = "https://api.vachana.ai/stt/v3"
MODEL = "prisma-v3.0"

st.set_page_config(
    page_title="ScamSathi AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --------------------------------
# SESSION STATE
# --------------------------------

if "history" not in st.session_state:
    st.session_state.history = []

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

# --------------------------------
# THEME AND CUSTOM CSS
# --------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Outfit:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 0%, rgba(185,164,245,0.10), transparent 28%),
        radial-gradient(circle at 90% 10%, rgba(36,198,181,0.08), transparent 25%),
        #171329;
    color: #F4F0FA;
}

header[data-testid="stHeader"] {
    background: transparent;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1200px;
}

h1, h2, h3 {
    font-family: 'Outfit', sans-serif;
    color: #F4F0FA;
}

p, label, span {
    color: #D8D1E8;
}

.hero {
    background: linear-gradient(120deg, #292342, #176B68);
    padding: 36px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,0.12);
    margin-bottom: 25px;
}

.hero h1 {
    font-size: 42px;
    font-weight: 800;
    margin-bottom: 8px;
    color: #FFFFFF;
}

.hero p {
    color: #E5FFF9;
    font-size: 16px;
}

.section-card {
    background: #211B38;
    border: 1px solid rgba(185,164,245,0.18);
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 18px;
}

.metric-card {
    background: #292342;
    border: 1px solid rgba(185,164,245,0.22);
    padding: 20px;
    border-radius: 16px;
    text-align: center;
}

.metric-number {
    font-size: 32px;
    font-weight: 800;
    color: #65E0D1;
}

.metric-label {
    color: #C9C0DC;
    font-size: 13px;
}

.stButton > button {
    background: linear-gradient(90deg, #24C6B5, #65E0D1);
    color: #171329;
    border: none;
    border-radius: 12px;
    font-weight: 800;
    padding: 0.65rem 1.4rem;
    min-height: 45px;
}

.stButton > button:hover {
    background: #65E0D1;
    color: #171329;
    border: none;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 12px;
    background: #211B38;
    padding: 9px;
    border-radius: 14px;
}

.stTabs [data-baseweb="tab"] {
    background: transparent;
    color: #D8D1E8;
    border-radius: 10px;
    padding: 10px 18px;
}

.stTabs [aria-selected="true"] {
    background: #176B68 !important;
    color: #FFFFFF !important;
}

[data-testid="stFileUploader"] {
    background: #211B38;
    border: 1px dashed #65E0D1;
    border-radius: 16px;
    padding: 15px;
}

[data-testid="stAudio"] {
    width: 100%;
}

div[data-testid="stAlert"] {
    border-radius: 12px;
}

.footer {
    text-align: center;
    color: #9B91B5;
    font-size: 12px;
    padding: 25px 0 5px 0;
}

.small-note {
    color: #AFA5C7;
    font-size: 12px;
}

.about-feature {
    background: #292342;
    border: 1px solid rgba(185,164,245,0.18);
    border-radius: 14px;
    padding: 17px;
    margin-bottom: 12px;
}

.about-feature h4 {
    color: #65E0D1;
    margin-bottom: 5px;
}

.about-feature p {
    color: #D8D1E8;
    margin-bottom: 0;
}

</style>
""", unsafe_allow_html=True)

# --------------------------------
# HEADER
# --------------------------------

st.markdown("""
<div class="hero">
    <h1>🛡️ ScamSathi AI</h1>
    <p>
        Multilingual AI-Powered Scam Call Detection
    </p>
    <p>
        Analyze suspicious calls, identify potential fraud signals,
        and receive safety recommendations.
    </p>
</div>
""", unsafe_allow_html=True)

# --------------------------------
# SCAM DETECTION KEYWORDS
# --------------------------------

WARNING_KEYWORDS = {
    "Sensitive Information Requests": {
        "weight": 85,
        "keywords": [
            "share your otp",
            "tell me your otp",
            "send your otp",
            "provide your otp",
            "otp immediately",
            "share otp",
            "bank password",
            "share your password",
            "tell me your password",
            "card number",
            "cvv number",
            "share your cvv",
            "pin number",
            "atm pin",
            "upi pin",
            "account password",
            "password immediately",
            "ಖಾತೆಯ ಪಾಸ್‌ವರ್ಡ್",
            "ನಿಮ್ಮ ಒಟಿಪಿ",
            "ಒಟಿಪಿ ಹೇಳಿ",
            "ಒಟಿಪಿ ಕಳುಹಿಸಿ",
            "ನಿಮ್ಮ ಪಿನ್",
            "ನಿಮ್ಮ ಎಟಿಎಂ ಪಿನ್",
            "ओटीपी बताएं",
            "ओटीपी भेजें",
            "अपना ओटीपी साझा करें",
            "एटीएम पिन",
            "यूपीआई पिन",
            "पासवर्ड बताएं",
            "మీ ఓటీపీ చెప్పండి",
            "ఓటీపీ పంపండి",
            "మీ పిన్ చెప్పండి",
            "మీ పాస్‌వర్డ్ చెప్పండి",
            "உங்கள் ஓடிபி சொல்லுங்கள்",
            "ஓடிபி அனுப்புங்கள்",
            "உங்கள் பின் எண்ணை சொல்லுங்கள்",
            "మీ OTP",
            "നിങ്ങളുടെ ഒടിപി",
            "ഒടിപി പറയൂ",
            "പാസ്‌വേഡ് പറയൂ"
        ]
    },

    "Urgent Payment Requests": {
        "weight": 35,
        "keywords": [
            "transfer money",
            "send money immediately",
            "pay immediately",
            "make a payment",
            "urgent payment",
            "send the amount",
            "transfer the amount",
            "pay now",
            "money transfer",
            "ತಕ್ಷಣ ಹಣ ಕಳುಹಿಸಿ",
            "ಹಣ ವರ್ಗಾಯಿಸಿ",
            "ಈಗಲೇ ಪಾವತಿಸಿ",
            "तुरंत पैसे भेजें",
            "अभी भुगतान करें",
            "पैसे ट्रांसफर करें",
            "तुरंत भुगतान",
            "వెంటనే డబ్బు పంపండి",
            "డబ్బు బదిలీ చేయండి",
            "ఇప్పుడే చెల్లించండి",
            "உடனே பணம் அனுப்புங்கள்",
            "இப்போதே பணம் செலுத்துங்கள்",
            "പണം ഉടൻ അയയ്ക്കുക",
            "ഉടൻ പണമടയ്ക്കുക"
        ]
    },

    "Threats and Pressure Tactics": {
        "weight": 25,
        "keywords": [
            "account will be blocked",
            "account will be suspended",
            "account blocked today",
            "your account will be closed",
            "police case",
            "arrest warrant",
            "you will be arrested",
            "legal action",
            "immediately or else",
            "last warning",
            "your account is at risk",
            "ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ",
            "ಖಾತೆ ಮುಚ್ಚಲಾಗುತ್ತದೆ",
            "ಪೊಲೀಸ್ ಕೇಸ್",
            "तुम्हारा खाता बंद हो जाएगा",
            "खाता ब्लॉक हो जाएगा",
            "पुलिस केस",
            "गिरफ्तार कर लिया जाएगा",
            "మీ ఖాతా బ్లాక్ అవుతుంది",
            "పోలీసు కేసు",
            "உங்கள் கணக்கு முடக்கப்படும்",
            "காவல்துறை வழக்கு",
            "നിങ്ങളുടെ അക്കൗണ്ട് ബ്ലോക്ക് ചെയ്യും",
            "പോലീസ് കേസ്"
        ]
    },

    "Suspicious Links and Access Requests": {
        "weight": 35,
        "keywords": [
            "click this link",
            "open this link",
            "install this app",
            "download this application",
            "share your screen",
            "screen sharing",
            "remote access",
            "install anydesk",
            "install teamviewer",
            "click the link",
            "open the link",
            "link sent to your phone",
            "ಅಪರಿಚಿತ ಲಿಂಕ್ ತೆರೆಯಿರಿ",
            "ಈ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಿ",
            "ಆಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ",
            "स्क्रीन शेयर करें",
            "इस लिंक पर क्लिक करें",
            "ऐप इंस्टॉल करें",
            "ఈ లింక్ క్లిక్ చేయండి",
            "యాప్ ఇన్‌స్టాల్ చేయండి",
            "உங்கள் திரையை பகிரவும்",
            "இந்த இணைப்பை கிளிக் செய்யவும்",
            "ആപ്പ് ഇൻസ്റ്റാൾ ചെയ്യുക",
            "ലിങ്കിൽ ക്ലിക്ക് ചെയ്യുക"
        ]
    },

    "Suspicious Identity and KYC Requests": {
        "weight": 15,
        "keywords": [
            "kyc verification",
            "update your kyc",
            "complete your kyc",
            "bank verification",
            "verify your account",
            "account verification",
            "aadhaar verification",
            "pan card verification",
            "your kyc is pending",
            "kyc update",
            "ನಿಮ್ಮ ಕೆವೈಸಿ ಅಪ್‌ಡೇಟ್ ಮಾಡಿ",
            "ಕೆವೈಸಿ ಪರಿಶೀಲನೆ",
            "अपना केवाईसी अपडेट करें",
            "केवाईसी सत्यापन",
            "आधार सत्यापन",
            "మీ కేవైసీ అప్డేట్ చేయండి",
            "కేవైసీ ధృవీకరణ",
            "உங்கள் கேஒய்சி புதுப்பிக்கவும்",
            "கேஒய்சி சரிபார்ப்பு",
            "നിങ്ങളുടെ കെവൈസി അപ്ഡേറ്റ് ചെയ്യുക",
            "കെവൈസി പരിശോധന"
        ]
    }
}

# --------------------------------
# TEXT ANALYSIS FUNCTION
# --------------------------------

def analyze_transcript(transcript):

    transcript_lower = transcript.lower()

    detected_signals = []
    total_score = 0

    for category, details in WARNING_KEYWORDS.items():

        matched_keywords = []

        for keyword in details["keywords"]:
            if keyword.lower() in transcript_lower:
                matched_keywords.append(keyword)

        if matched_keywords:
            detected_signals.append({
                "category": category,
                "weight": details["weight"],
                "matched_keywords": matched_keywords
            })

            total_score += details["weight"]

    total_score = min(total_score, 100)

    if total_score >= 70:
        risk_level = "HIGH"
    elif total_score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": total_score,
        "risk_level": risk_level,
        "detected_signals": detected_signals,
        "transcript": transcript
    }

# --------------------------------
# TRANSCRIPTION FUNCTION
# --------------------------------

def transcribe_audio(audio_file):

    if not API_KEY:
        raise ValueError(
            "API key not found. Check your .env file or Streamlit Secrets."
        )

    headers = {
        "X-API-Key-ID": API_KEY
    }

    files = {
        "audio_file": (
            audio_file.name,
            audio_file.getvalue(),
            audio_file.type
        )
    }

    data = {
        "model": MODEL,
        "language_code": "indic-auto"
    }

    response = requests.post(
        API_URL,
        headers=headers,
        files=files,
        data=data,
        timeout=90
    )

    if response.status_code != 200:
        raise Exception(
            f"Transcription failed. Status code: {response.status_code}. "
            f"Response: {response.text[:500]}"
        )

    result = response.json()

    transcript = ""

    if isinstance(result, dict):
        transcript = (
            result.get("transcript")
            or result.get("text")
            or result.get("transcription")
            or ""
        )

        if not transcript and isinstance(result.get("data"), dict):
            transcript = (
                result["data"].get("transcript")
                or result["data"].get("text")
                or ""
            )

    if not transcript:
        raise Exception(
            "No transcript was returned by the speech recognition service."
        )

    return transcript

# --------------------------------
# RECOMMENDATIONS
# --------------------------------

def get_recommendations(risk_level, detected_signals):

    recommendations = []

    categories = [
        signal["category"]
        for signal in detected_signals
    ]

    if "Sensitive Information Requests" in categories:
        recommendations.append(
            "Never share OTPs, PINs, passwords, CVV numbers, "
            "or banking credentials over a phone call."
        )

    if "Urgent Payment Requests" in categories:
        recommendations.append(
            "Do not transfer money under pressure. "
            "Verify the request independently."
        )

    if "Threats and Pressure Tactics" in categories:
        recommendations.append(
            "Do not panic because of threats. "
            "Contact the concerned organization using its official number."
        )

    if "Suspicious Links and Access Requests" in categories:
        recommendations.append(
            "Avoid opening unknown links or installing applications "
            "suggested by an unverified caller."
        )

    if "Suspicious Identity and KYC Requests" in categories:
        recommendations.append(
            "Verify KYC requests through your bank's official website, "
            "application, or branch."
        )

    if risk_level == "HIGH":
        recommendations.append(
            "Treat this call as highly suspicious. Stop sharing information "
            "and independently contact the organization."
        )

    elif risk_level == "MEDIUM":
        recommendations.append(
            "Be cautious. Verify the caller's identity before taking action."
        )

    else:
        recommendations.append(
            "No matching warning keywords were detected. "
            "This does not guarantee that the call is safe."
        )

    recommendations.append(
        "If you suspect financial fraud in India, contact your bank "
        "immediately and report cyber fraud through the official "
        "cybercrime helpline 1930 or cybercrime.gov.in."
    )

    return recommendations

# --------------------------------
# PDF REPORT FUNCTION
# --------------------------------

def create_report(item):

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=25,
        textColor=colors.HexColor("#176B68"),
        alignment=TA_CENTER,
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#176B68"),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#292342"),
        spaceAfter=6
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=body_style,
        fontSize=8,
        leading=11
    )

    story = []

    story.append(
        Paragraph("SCAMSATHI AI - CALL ANALYSIS REPORT", title_style)
    )

    story.append(
        Paragraph(
            "Multilingual AI-Powered Scam Call Detection",
            ParagraphStyle(
                "Subtitle",
                parent=body_style,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#176B68")
            )
        )
    )

    story.append(Spacer(1, 8))

    story.append(
        HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor("#24C6B5")
        )
    )

    story.append(Spacer(1, 12))

    report_data = [
        ["Report ID", escape(str(item.get("report_id", "N/A")))],
        ["Date", escape(str(item.get("date", "N/A")))],
        ["Audio File", escape(str(item.get("filename", "N/A")))],
        ["Risk Score", f'{item.get("risk_score", 0)}/100'],
        ["Risk Level", escape(str(item.get("risk_level", "N/A")))]
    ]

    table = Table(
        report_data,
        colWidths=[40 * mm, 125 * mm]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E7F7F4")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#292342")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D7D1E5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
    ]))

    story.append(table)

    story.append(
        Paragraph("CALL TRANSCRIPT", heading_style)
    )

    transcript = escape(str(item.get("transcript", "")))
    transcript = transcript.replace("\n", "<br/>")

    story.append(
        Paragraph(transcript or "No transcript available.", body_style)
    )

    story.append(
        Paragraph("DETECTED WARNING SIGNALS", heading_style)
    )

    signals = item.get("detected_signals", [])

    if signals:
        for signal in signals:
            category = escape(signal["category"])
            keywords = escape(
                ", ".join(signal.get("matched_keywords", []))
            )

            story.append(
                Paragraph(
                    f"<b>{category}</b><br/>"
                    f"Matched phrases: {keywords}",
                    body_style
                )
            )
    else:
        story.append(
            Paragraph(
                "No matching warning keywords were detected.",
                body_style
            )
        )

    story.append(
        Paragraph("SAFETY RECOMMENDATIONS", heading_style)
    )

    recommendations = item.get("recommendations", [])

    for recommendation in recommendations:
        story.append(
            Paragraph(
                "• " + escape(recommendation),
                body_style
            )
        )

    story.append(Spacer(1, 12))

    story.append(
        HRFlowable(
            width="100%",
            thickness=0.8,
            color=colors.HexColor("#D7D1E5")
        )
    )

    story.append(Spacer(1, 8))

    story.append(
        Paragraph(
            "<b>Disclaimer:</b> This report provides preliminary "
            "keyword-based screening and is not a confirmation of fraud. "
            "Speech recognition and keyword matching may produce errors. "
            "A low risk score does not guarantee that a call is safe. "
            "Always verify suspicious requests independently.",
            small_style
        )
    )

    story.append(
        Paragraph(
            "Generated by ScamSathi AI",
            ParagraphStyle(
                "FooterText",
                parent=small_style,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#176B68"),
                spaceBefore=12
            )
        )
    )

    doc.build(story)

    buffer.seek(0)

    return buffer

# --------------------------------
# RISK DISPLAY
# --------------------------------

def display_risk_result(result):

    score = result["risk_score"]
    level = result["risk_level"]

    if level == "HIGH":
        st.error("🚨 HIGH RISK — Suspicious warning signals detected.")

    elif level == "MEDIUM":
        st.warning("⚠️ MEDIUM RISK — Please verify this call carefully.")

    else:
        st.success("✅ LOW RISK — No strong warning signals detected.")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-number">{score}/100</div>
                <div class="metric-label">RISK SCORE</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-number">{level}</div>
                <div class="metric-label">RISK LEVEL</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.progress(score / 100)

    st.markdown("### 📝 Call Transcript")

    st.markdown(
        f"""
        <div class="section-card">
            {escape(result["transcript"])}
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("### 🚩 Detected Warning Signals")

    signals = result["detected_signals"]

    if signals:

        for signal in signals:

            with st.expander(
                f"⚠️ {signal['category']}"
            ):
                st.write(
                    "**Matched phrases:**",
                    ", ".join(signal["matched_keywords"])
                )

                st.write(
                    f"**Risk contribution:** {signal['weight']} points"
                )

    else:
        st.info(
            "No matching warning keywords were found in this transcript."
        )

    st.markdown("### 🛡️ Safety Recommendations")

    for recommendation in result["recommendations"]:
        st.markdown(f"- {recommendation}")

# --------------------------------
# MAIN TABS
# --------------------------------

tab_analyze, tab_history, tab_about = st.tabs([
    "🔍 Analyze Call",
    "📋 Analysis History",
    "ℹ️ About"
])

# --------------------------------
# ANALYZE CALL TAB
# --------------------------------

with tab_analyze:

    st.markdown("## 🔍 Upload and Analyze")

    st.write(
        "Upload a call recording to check for potential fraud warning signs."
    )

    uploaded_file = st.file_uploader(
        "Choose an audio file",
        type=["wav", "mp3", "m4a", "ogg", "flac", "aac"],
        help="Supported formats: WAV, MP3, M4A, OGG, FLAC and AAC."
    )

    if uploaded_file:

        st.audio(
            uploaded_file,
            format=uploaded_file.type
        )

        if st.button(
            "🔍 Analyze Call",
            use_container_width=True
        ):

            with st.spinner(
                "Transcribing audio and checking for suspicious signals..."
            ):

                try:

                    transcript = transcribe_audio(uploaded_file)

                    analysis = analyze_transcript(transcript)

                    recommendations = get_recommendations(
                        analysis["risk_level"],
                        analysis["detected_signals"]
                    )

                    result = {
                        "report_id": str(uuid.uuid4())[:8].upper(),
                        "date": datetime.now().strftime("%d-%m-%Y %H:%M"),
                        "filename": uploaded_file.name,
                        "risk_score": analysis["risk_score"],
                        "risk_level": analysis["risk_level"],
                        "transcript": transcript,
                        "detected_signals": analysis["detected_signals"],
                        "recommendations": recommendations
                    }

                    st.session_state.analysis_result = result

                    st.session_state.history.insert(0, result)

                    st.success("Call analysis completed!")

                except Exception as error:

                    st.error(
                        f"Unable to analyze the audio: {str(error)}"
                    )

    if st.session_state.analysis_result:

        st.markdown("---")

        st.markdown("## 📊 Analysis Result")

        display_risk_result(
            st.session_state.analysis_result
        )

        pdf_buffer = create_report(
            st.session_state.analysis_result
        )

        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_buffer,
            file_name=(
                "ScamSathi_Report_"
                + st.session_state.analysis_result["report_id"]
                + ".pdf"
            ),
            mime="application/pdf",
            use_container_width=True
        )

    st.markdown(
        """
        <p class="small-note">
        Note: Analysis is based on speech transcription and keyword matching.
        It is a preliminary safety screening tool, not a guarantee that a call
        is genuine or fraudulent.
        </p>
        """,
        unsafe_allow_html=True
    )

# --------------------------------
# HISTORY TAB
# --------------------------------

with tab_history:

    st.markdown("## 📋 Analysis History")

    st.write(
        "Your recent call analyses are shown here during this session."
    )

    if st.session_state.history:

        for index, item in enumerate(st.session_state.history):

            with st.expander(
                f"{item['filename']} — {item['risk_level']} "
                f"({item['risk_score']}/100)"
            ):

                st.write("**Date:**", item["date"])

                st.write("**Report ID:**", item["report_id"])

                st.write("**Risk Level:**", item["risk_level"])

                st.write("**Risk Score:**", f"{item['risk_score']}/100")

                st.write("**Transcript:**")

                st.write(item["transcript"])

                st.write("**Detected Signals:**")

                if item["detected_signals"]:

                    for signal in item["detected_signals"]:
                        st.write(
                            "- " + signal["category"]
                        )

                else:
                    st.write("No matching warning signals detected.")

                st.download_button(
                    label="📄 Download This Report",
                    data=create_report(item),
                    file_name=f"ScamSathi_Report_{item['report_id']}.pdf",
                    mime="application/pdf",
                    key=f"history_download_{index}"
                )

        if st.button(
            "🗑️ Clear History",
            use_container_width=True
        ):

            st.session_state.history = []
            st.session_state.analysis_result = None

            st.rerun()

    else:

        st.info(
            "No analysis history yet. Upload an audio recording "
            "in the Analyze Call tab to get started."
        )

# --------------------------------
# ABOUT TAB
# --------------------------------

with tab_about:

    st.subheader("ℹ️ About ScamSathi AI")

    st.markdown("""
    <div class="hero">
        <h2>Making Digital Calls Safer</h2>
        <p>
            ScamSathi AI is a multilingual call screening prototype
            designed to help users identify possible scam warning signs
            in phone conversations.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### ✨ Key Features")

    st.markdown("""
    <div class="about-feature">
        <h4>🎙️ Audio Transcription</h4>
        <p>
            Converts uploaded call recordings into text using a
            speech recognition service.
        </p>
    </div>

    <div class="about-feature">
        <h4>🌐 Multilingual Support</h4>
        <p>
            Designed to work with Indian-language speech, including
            English, Kannada, Hindi, Telugu, Tamil and Malayalam.
            Actual results depend on transcription quality.
        </p>
    </div>

    <div class="about-feature">
        <h4>🚩 Warning Signal Detection</h4>
        <p>
            Checks the transcript for suspicious phrases related to
            OTP requests, urgent payments, threats, suspicious links
            and KYC requests.
        </p>
    </div>

    <div class="about-feature">
        <h4>📊 Risk Scoring</h4>
        <p>
            Provides a preliminary risk score and classifies the result
            as Low, Medium or High based on detected warning signals.
        </p>
    </div>

    <div class="about-feature">
        <h4>📄 PDF Reports</h4>
        <p>
            Generates a downloadable report containing the transcript,
            detected warning signals and safety recommendations.
        </p>
    </div>

    <div class="about-feature">
        <h4>📋 Analysis History</h4>
        <p>
            Allows users to review previous analyses during the
            current app session.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### ⚙️ How It Works")

    st.markdown("""
    1. **Upload:** The user uploads a call recording.
    2. **Transcribe:** Speech recognition converts the audio into text.
    3. **Analyze:** The system checks the transcript for warning phrases.
    4. **Score:** A preliminary risk score is calculated.
    5. **Recommend:** Safety suggestions are displayed.
    6. **Report:** The user can download a PDF report.
    """)

    st.markdown("### 🛡️ Important Safety Note")

    st.warning(
        "ScamSathi AI is a prototype for preliminary screening. "
        "It does not prove that a caller is genuine or fraudulent. "
        "Keyword matching can miss suspicious wording or flag harmless "
        "conversations. Always verify requests through official channels."
    )

    st.markdown("### 👩‍💻 Built With")

    st.markdown("""
    - Python
    - Streamlit
    - Gnani AI Prisma Speech Recognition
    - Requests
    - ReportLab
    """)

    st.markdown("""
    <div class="footer">
        ScamSathi AI | Making Digital Calls Safer
    </div>
    """, unsafe_allow_html=True)

# --------------------------------
# FOOTER
# --------------------------------

st.markdown("""
<div class="footer">
    🛡️ ScamSathi AI | Stay Alert. Stay Safe.
</div>
""", unsafe_allow_html=True)
