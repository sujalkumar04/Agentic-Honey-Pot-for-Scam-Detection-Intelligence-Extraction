from typing import Any

sessions: dict[str, dict[str, Any]] = {}


def load_session(session_id: str) -> dict[str, Any]:
    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [],
            "scamDetected": False,
            "intelligence": {}
        }
    return sessions[session_id]


def save_session(session_id: str, session: dict[str, Any]) -> None:
    sessions[session_id] = session


def append_message(session_id: str, role: str, content: str) -> dict[str, Any]:
    session = load_session(session_id)
    session["messages"].append({"role": role, "content": content})
    save_session(session_id, session)
    return session


def set_scam_detected(session_id: str, detected: bool) -> None:
    session = load_session(session_id)
    session["scamDetected"] = detected
    save_session(session_id, session)


def update_intelligence(session_id: str, key: str, value: Any) -> None:
    session = load_session(session_id)
    session["intelligence"][key] = value
    save_session(session_id, session)


def get_messages(session_id: str) -> list[dict[str, str]]:
    session = load_session(session_id)
    return session["messages"]


def clear_session(session_id: str) -> None:
    if session_id in sessions:
        del sessions[session_id]
