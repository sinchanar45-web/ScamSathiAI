
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
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

# --------------------------------
# CONFIGURATION
# --------------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

API_KEY = os.getenv("GNANI_API_KEY")

# Streamlit Community Cloud secrets fallback
if not API_KEY:
    try:
        API_KEY = st.secrets["GNANI_API_KEY"]
    except Exception:
        API_KEY = None

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

.stDownloadButton button {
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
                "otp",
                "one time password",
                "one-time password",
                "password",
                "cvv",
                "pin",
                "bank details",
                "account number",

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
                "transfer money",
                "send money",
                "upi payment",
                "pay immediately",
                "urgent payment",
                "make a payment",

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
                "click this link",
                "download this app",
                "remote access",
                "screen sharing",
                "share your screen",
                "install this application",

                "ಈ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಿ",
                "ಈ ಆಪ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ",
                "ಸ್ಕ್ರೀನ್ ಹಂಚಿಕೊಳ್ಳಿ",
                "ರಿಮೋಟ್ ಆಕ್ಸೆಸ್"
            ],
            "points": 35
        },

        "Suspicious identity or KYC claims": {
            "keywords": [
                "bank officer",
                "calling from your bank",
                "customer care",
                "government officer",
                "kyc update",
                "kyc verification",
                "verify your account",
                "lottery winner",
                "prize money",

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
# PROFESSIONAL PDF REPORT GENERATOR
# --------------------------------

def create_report(item):

    buffer = io.BytesIO()

    report_id = item.get("report_id")

    if not report_id:
        report_id = "SSA-" + uuid.uuid4().hex[:10].upper()
        item["report_id"] = report_id

    navy = colors.HexColor("#14233D")
    blue = colors.HexColor("#1D4E89")
    light_blue = colors.HexColor("#EAF2FA")
    grey = colors.HexColor("#64748B")
    dark = colors.HexColor("#1E293B")
    border = colors.HexColor("#D9E2EC")

    if item["risk"] == "HIGH":
        risk_color = colors.HexColor("#DC2626")
        risk_bg = colors.HexColor("#FEE2E2")
    elif item["risk"] == "MEDIUM":
        risk_color = colors.HexColor("#D97706")
        risk_bg = colors.HexColor("#FEF3C7")
    else:
        risk_color = colors.HexColor("#15803D")
        risk_bg = colors.HexColor("#DCFCE7")

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="ScamSathi AI Analysis Report",
        author="ScamSathi AI",
        subject="Preliminary call safety screening"
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=23,
        leading=28,
        textColor=colors.white,
        alignment=TA_LEFT,
        spaceAfter=5
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=15,
        textColor=colors.HexColor("#DCE8F5")
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=navy,
        spaceBefore=12,
        spaceAfter=7
    ))

    styles.add(ParagraphStyle(
        name="BodyCustom",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=dark,
        spaceAfter=4
    ))

    styles.add(ParagraphStyle(
        name="SmallCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=grey
    ))

    styles.add(ParagraphStyle(
        name="RiskValue",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=27,
        textColor=risk_color,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name="RiskLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=risk_color,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name="TableHeaderCustom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.white
    ))

    styles.add(ParagraphStyle(
        name="TableBodyCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=12,
        textColor=dark
    ))

    story = []

    # HEADER

    header_content = [
        Paragraph(
            "SCAMSATHI AI",
            styles["ReportTitle"]
        ),
        Paragraph(
            "MULTILINGUAL CALL SAFETY ANALYSIS",
            styles["ReportSubtitle"]
        ),
        Spacer(1, 5)
    ]

    header_table = Table(
        [[header_content]],
        colWidths=[174 * mm]
    )

    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), navy),
        ("BOX", (0, 0), (-1, -1), 0.8, blue),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    story.append(header_table)
    story.append(Spacer(1, 12))

    # REPORT INFORMATION

    info_data = [
        [
            Paragraph("<b>REPORT ID</b>", styles["SmallCustom"]),
            Paragraph("<b>ANALYSIS DATE</b>", styles["SmallCustom"]),
            Paragraph("<b>AUDIO FILE</b>", styles["SmallCustom"])
        ],
        [
            Paragraph(escape(report_id), styles["BodyCustom"]),
            Paragraph(escape(item["date"]), styles["BodyCustom"]),
            Paragraph(escape(item.get("filename", "Audio recording")), styles["BodyCustom"])
        ]
    ]

    info_table = Table(
        info_data,
        colWidths=[48 * mm, 54 * mm, 72 * mm]
    )

    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light_blue),
        ("BOX", (0, 0), (-1, -1), 0.6, border),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, border),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    story.append(info_table)

    # RISK SUMMARY

    story.append(Paragraph(
        "01  |  RISK ASSESSMENT",
        styles["SectionHeading"]
    ))

    risk_table = Table(
        [[
            Paragraph(
                f"{item['score']} / 100",
                styles["RiskValue"]
            ),
            Paragraph(
                item["risk"] + " RISK",
                styles["RiskLabel"]
            ),
            Paragraph(
                f"{len(item['detected'])} warning categories",
                styles["BodyCustom"]
            )
        ]],
        colWidths=[58 * mm, 58 * mm, 58 * mm]
    )

    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), light_blue),
        ("BACKGROUND", (1, 0), (1, 0), risk_bg),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 0.6, border),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14)
    ]))

    story.append(risk_table)

    # WARNING SIGNALS

    story.append(Paragraph(
        "02  |  DETECTED WARNING SIGNALS",
        styles["SectionHeading"]
    ))

    if item["detected"]:

        signal_data = [[
            Paragraph("CATEGORY", styles["TableHeaderCustom"]),
            Paragraph("MATCHED TERMS", styles["TableHeaderCustom"]),
            Paragraph("POINTS", styles["TableHeaderCustom"])
        ]]

        for signal in item["detected"]:

            signal_data.append([
                Paragraph(
                    escape(signal["category"]),
                    styles["TableBodyCustom"]
                ),
                Paragraph(
                    escape(", ".join(signal["keywords"])),
                    styles["TableBodyCustom"]
                ),
                Paragraph(
                    f"+{signal['points']}",
                    styles["TableBodyCustom"]
                )
            ])

        signal_table = Table(
            signal_data,
            colWidths=[58 * mm, 96 * mm, 20 * mm],
            repeatRows=1
        )

        signal_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#F4F7FB")
            ]),
            ("BOX", (0, 0), (-1, -1), 0.6, border),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, border),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8)
        ]))

        story.append(signal_table)

    else:

        story.append(Paragraph(
            "No matching warning patterns were detected.",
            styles["BodyCustom"]
        ))

    # TRANSCRIPT

    story.append(Paragraph(
        "03  |  CALL TRANSCRIPT",
        styles["SectionHeading"]
    ))

    transcript = escape(item["transcript"]).replace("\n", "<br/>")

    transcript_box = Table(
        [[Paragraph(transcript, styles["BodyCustom"])]],
        colWidths=[174 * mm]
    )

    transcript_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F7FB")),
        ("BOX", (0, 0), (-1, -1), 0.6, border),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10)
    ]))

    story.append(transcript_box)

    story.append(Paragraph(
        "Speech recognition: Gnani AI Prisma v3.0",
        styles["SmallCustom"]
    ))

    # SAFETY RECOMMENDATION

    story.append(Paragraph(
        "04  |  SAFETY RECOMMENDATION",
        styles["SectionHeading"]
    ))

    recommendation_box = Table(
        [[Paragraph(
            escape(item["recommendation"]),
            styles["BodyCustom"]
        )]],
        colWidths=[174 * mm]
    )

    recommendation_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light_blue),
        ("BOX", (0, 0), (-1, -1), 0.8, blue),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10)
    ]))

    story.append(recommendation_box)

    # DISCLAIMER

    story.append(Paragraph(
        "IMPORTANT DISCLAIMER",
        styles["SectionHeading"]
    ))

    disclaimer = (
        "ScamSathi AI provides preliminary rule-based screening and "
        "does not confirm whether a call is genuine or fraudulent. "
        "Results depend on speech recognition quality and keyword "
        "matching. Context, negation and transcription errors may "
        "affect the result. A low-risk score does not guarantee that "
        "a call is safe. Always verify important requests independently."
    )

    story.append(Paragraph(
        disclaimer,
        styles["SmallCustom"]
    ))

    story.append(Spacer(1, 15))

    story.append(HRFlowable(
        width="100%",
        thickness=0.8,
        color=border
    ))

    story.append(Spacer(1, 7))

    story.append(Paragraph(
        "SCAMSATHI AI  |  POWERED BY GNANI AI PRISMA V3.0",
        ParagraphStyle(
            "FooterCustom",
            parent=styles["SmallCustom"],
            alignment=TA_CENTER,
            textColor=blue,
            fontName="Helvetica-Bold"
        )
    ))

    story.append(Paragraph(
        "Call safety awareness • Preliminary screening report",
        ParagraphStyle(
            "FooterSub",
            parent=styles["SmallCustom"],
            alignment=TA_CENTER
        )
    ))

    # PAGE FOOTER

    def add_page_number(canvas, doc):

        canvas.saveState()

        canvas.setStrokeColor(border)
        canvas.line(
            18 * mm,
            13 * mm,
            A4[0] - 18 * mm,
            13 * mm
        )

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(grey)

        canvas.drawRightString(
            A4[0] - 18 * mm,
            8 * mm,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    buffer.seek(0)

    return buffer.getvalue()


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
                    "API key not found. Add GNANI_API_KEY in "
                    "Streamlit Secrets or your local .env file."
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
                                "report_id": (
                                    "SSA-" + uuid.uuid4().hex[:10].upper()
                                ),
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

        # PDF DOWNLOAD

        pdf_data = create_report(item)

        st.download_button(
            label="📄 Download Professional PDF Report",
            data=pdf_data,
            file_name=f"ScamSathi_{item['report_id']}.pdf",
            mime="application/pdf",
            key="latest_pdf_download",
            type="primary"
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
                    "📄 Download PDF Report",
                    data=create_report(item),
                    file_name=f"ScamSathi_{item['report_id']}.pdf",
                    mime="application/pdf",
                    key=f"history_pdf_download_{index}"
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
    st.write("- Professional downloadable PDF reports")
    st.write("- Session-based analysis history")

    st.markdown("### Technology Used")

    st.write("- Gnani AI Prisma v3.0")
    st.write("- Python")
    st.write("- Streamlit")
    st.write("- ReportLab")
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
