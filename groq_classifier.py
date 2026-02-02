import os
from groq import Groq

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MODEL = "llama3-8b-8192"
TIMEOUT = 3

VALID_LABELS = {
    "UPI_PAYMENT_SCAM",
    "PHISHING_LINK",
    "OTP_FRAUD",
    "BANK_KYC_FRAUD",
    "JOB_SCAM",
    "LOTTERY_SCAM",
    "UNKNOWN"
}

SYSTEM_PROMPT = """You are a scam classification assistant.
Classify the scam type based on the message content.

Return ONLY one of these labels exactly:
UPI_PAYMENT_SCAM, PHISHING_LINK, OTP_FRAUD, BANK_KYC_FRAUD, JOB_SCAM, LOTTERY_SCAM, UNKNOWN

Do not include any other text, explanation, or punctuation. Return only the label."""


def groq_classify(text: str) -> str:
    if not GROQ_API_KEY or not text:
        return "UNKNOWN"

    try:
        client = Groq(api_key=GROQ_API_KEY, timeout=TIMEOUT)

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Classify this message:\n\n{text}"}
            ],
            temperature=0.1,
            max_tokens=50
        )

        label = response.choices[0].message.content.strip().upper()

        if label in VALID_LABELS:
            return label

        for valid in VALID_LABELS:
            if valid in label:
                return valid

        return "UNKNOWN"

    except Exception:
        return "UNKNOWN"
