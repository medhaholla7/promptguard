"""Deterministic checks used by the guarded triage pipeline. No model involved."""
import base64
import binascii
import re

ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
URL = re.compile(r"https?://[^\s'\"<>]+", re.I)

HIDDEN_BLOCKS = [
    ("html comment", re.compile(r"<!--.*?-->", re.S)),
    ("display:none", re.compile(r"<(\w+)[^>]*style=['\"][^'\"]*display\s*:\s*none[^'\"]*['\"][^>]*>.*?</\1>", re.S | re.I)),
    ("zero-size text", re.compile(r"<(\w+)[^>]*style=['\"][^'\"]*font-size\s*:\s*[01](px)?\b[^'\"]*['\"][^>]*>.*?</\1>", re.S | re.I)),
    ("white text", re.compile(r"<(\w+)[^>]*style=['\"][^'\"]*color\s*:\s*(#fff(fff)?|white)\b[^'\"]*['\"][^>]*>.*?</\1>", re.S | re.I)),
]

INJECTION_PATTERNS = [
    ("override", r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(instructions?|rules?|prompt)\b"),
    ("verdict dictation", r"\b(classify|mark|treat|label|return|respond|answer|keep)\b[^.\n]{0,60}\bsafe\b"),
    ("verdict dictation", r"verdict\W{0,3}(is\W{0,2})?\W{0,2}safe"),
    ("fake system message", r"\[?\b(system message|system notice|administrator override|pre-?approved|allowlisted)\b"),
    ("fake system message", r"#+\s*system\b|^\s*system\s*:"),
    ("addresses the model", r"\b(ai assistant|automated (reader|filters?)|to the ai|ai reading this|security tools must)\b"),
    ("role-play", r"\b(you are now|pretend (you are|to be)|let'?s play a game|stay in character|act as|developer test mode|test mode)\b"),
    ("prompt-leak attempt", r"\b(system prompt|hidden instructions|reference code|secret values?)\b"),
    ("delimiter escape", r"</email>|end of email"),
    ("fake chat turn", r"^\s*(assistant|user)\s*:"),
    ("social proof", r"\b(already reviewed|marked it safe|your role is only|stop flagging|keep the verdict)\b"),
    ("foreign-language override", r"\b(ignora|instrucciones|ignorez|ignorieren)\b|निर्देश|अनदेखा"),
]

PHISHING_CUES = [
    ("credential request", lambda t, has_url: has_url and re.search(
        r"\b(password|sign in|log in|login|verify your account|re-enter|card number|pin)\b", t)),
    ("bank-detail change", lambda t, has_url: re.search(
        r"\b(bank details have changed|changed banks|new account|sort code|update your card|confirm your bank details)\b", t)),
    ("gift-card request", lambda t, has_url: re.search(r"\bgift ?cards?\b", t)),
    ("payment pressure", lambda t, has_url: has_url and re.search(r"\b(pay|payment|fee|penalty|refund)\b", t)),
]


def sanitise(email):
    """Return a copy with hidden content removed, plus a list of what was removed."""
    body, removed = email["body"], []
    for name, rx in HIDDEN_BLOCKS:
        if rx.search(body):
            removed.append(name)
            body = rx.sub(" ", body)
    if ZERO_WIDTH.search(body):
        removed.append("zero-width characters")
        body = ZERO_WIDTH.sub("", body)
    body = re.sub(r"<[^>]+>", " ", body)          # remaining tags
    body = re.sub(r"[ \t]+", " ", body).strip()
    return dict(email, body=body), removed


def _views(email):
    """Every way an attacker could hide text: raw, visible, de-zero-widthed, decoded, reversed."""
    raw = " ".join([email["from"], email["subject"], email["body"]])
    joined = ZERO_WIDTH.sub("", raw)
    views = [raw, joined, joined[::-1]]
    for blob in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", joined):
        try:
            views.append(base64.b64decode(blob, validate=True).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            pass
    return views


def injection_signals(email):
    hits = []
    for view in _views(email):
        low = view.lower()
        for name, pattern in INJECTION_PATTERNS:
            if name not in hits and re.search(pattern, low, flags=re.M):
                hits.append(name)
    if ZERO_WIDTH.search(email["body"]) and "hidden characters" not in hits:
        hits.append("hidden characters")
    if any(rx.search(email["body"]) for _, rx in HIDDEN_BLOCKS):
        hits.append("hidden html")
    return hits


def floor_verdict(clean_email, injection_hits):
    """Minimum verdict from rules alone. The model may go higher, never lower."""
    text = " ".join([clean_email["from"], clean_email["subject"], clean_email["body"]]).lower()
    has_url = bool(URL.search(text))
    cues = [name for name, test in PHISHING_CUES if test(text, has_url)]
    reasons = cues + (["tries to instruct the filter"] if injection_hits else [])
    if injection_hits and cues:
        return "phishing", reasons
    if injection_hits or cues:
        return "suspicious", reasons
    return "safe", reasons
