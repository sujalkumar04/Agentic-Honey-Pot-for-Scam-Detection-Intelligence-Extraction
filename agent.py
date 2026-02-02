"""
Agent module for generating realistic honeypot persona replies.
"""

import random

PERSONA = {
    "name": "Rahul",
    "tech_savvy": False,
    "traits": ["confused", "curious", "polite", "slow to understand"]
}

GENERIC_REPLIES = [
    "Hello! How can I help you?",
    "Thank you for reaching out.",
    "I understand, please go ahead.",
    "Okay, tell me more.",
    "Sure, I'm listening.",
]

SCAM_ENGAGEMENT_REPLIES = {
    "initial": [
        "Oh hello ji, who is this speaking?",
        "Yes yes, I am Rahul. What happened?",
        "Haan ji, I am here. What is the matter?",
    ],
    "confused": [
        "Sorry, I didn't understand properly. Can you explain again?",
        "Arey, my phone network is weak. What did you say?",
        "Wait wait, I am not getting. What is this about?",
        "Haan? What is this OTP thing you are saying?",
        "I am not understanding technical things. Please explain simply.",
    ],
    "curious": [
        "But why do you need this information?",
        "Who gave you my number?",
        "Which bank are you calling from exactly?",
        "What is your name and employee ID?",
        "Can you tell me your office address?",
    ],
    "stalling": [
        "One minute, let me find my glasses first.",
        "Wait, someone is at the door. Give me 2 minutes.",
        "Hold on, I need to check my phone properly.",
        "My son knows these things better. Should I call him?",
        "Let me write this down. Please speak slowly.",
    ],
    "details": [
        "What is the exact amount you are saying?",
        "From which branch are you calling?",
        "What is the reference number for this?",
        "Can you send me this in writing on WhatsApp?",
        "What is your supervisor's name?",
    ],
}


def _get_conversation_stage(history: list[dict[str, str]]) -> str:
    """
    Determine conversation stage based on message count.

    Args:
        history: List of conversation messages.

    Returns:
        Stage identifier: 'initial', 'confused', 'curious', 'stalling', or 'details'.
    """
    msg_count = len(history)
    if msg_count <= 2:
        return "initial"
    elif msg_count <= 4:
        return "confused"
    elif msg_count <= 6:
        return "curious"
    elif msg_count <= 8:
        return "stalling"
    else:
        return "details"


def _select_reply(replies: list[str], history: list[dict[str, str]]) -> str:
    """
    Select a reply that hasn't been used in the conversation.

    Args:
        replies: List of possible reply templates.
        history: Conversation history to check for used replies.

    Returns:
        Selected reply string.
    """
    used_replies = {msg.get("content", "") for msg in history if msg.get("role") == "assistant"}
    available = [r for r in replies if r not in used_replies]
    if not available:
        available = replies
    return random.choice(available)


def generate_reply(
    history: list[dict[str, str]],
    latest_message: str,
    scam_detected: bool
) -> str:
    """
    Generate a contextual reply based on conversation history and scam detection.

    Args:
        history: List of conversation messages with 'role' and 'content' keys.
        latest_message: The most recent message from the user/scammer.
        scam_detected: Whether scam indicators were detected in conversation.

    Returns:
        Generated reply string. Uses Rahul persona if scam detected,
        otherwise returns generic polite response.
    """
    if not scam_detected:
        return _select_reply(GENERIC_REPLIES, history)

    stage = _get_conversation_stage(history)
    replies = SCAM_ENGAGEMENT_REPLIES.get(stage, SCAM_ENGAGEMENT_REPLIES["confused"])
    return _select_reply(replies, history)
