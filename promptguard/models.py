"""Model backends. Standard library only, so the project runs without installing anything."""
import json
import re
import time
import urllib.error
import urllib.request

GEMINI_CANDIDATES = ["gemini-3.5-flash-lite", "gemini-2.5-flash-lite", "gemini-3.5-flash", "gemini-2.5-flash"]  # lite first: much higher free-tier limits


class Gemini:
    def __init__(self, key, model=None, log=print):
        self.key, self.log = key, log
        self.calls = 0
        self.model = model or self._pick()

    def _post(self, model, system, user):
        body = {
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0, "maxOutputTokens": 4096},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        req = urllib.request.Request(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "x-goog-api-key": self.key},
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)

    def _pick(self):
        for m in GEMINI_CANDIDATES:
            try:
                self._post(m, "", "Reply with the word ok.")
                self.log(f"using model {m}")
                return m
            except urllib.error.HTTPError as e:
                self.log(f"model {m} not available ({e.code}: {e.read()[:200]!r})")
        # Fall back to whatever flash model this key can see.
        try:
            req = urllib.request.Request("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200",
                                         headers={"x-goog-api-key": self.key})
            with urllib.request.urlopen(req, timeout=30) as r:
                names = [m["name"].split("/")[-1] for m in json.loads(r.read()).get("models", [])
                         if "generateContent" in m.get("supportedGenerationMethods", [])]
            self.log("models this key can use: " + ", ".join(names))
            for m in [n for n in names if "flash" in n and "image" not in n and "tts" not in n]:
                try:
                    self._post(m, "", "Reply with the word ok.")
                    self.log(f"using model {m}")
                    return m
                except urllib.error.HTTPError as e:
                    self.log(f"model {m} not available ({e.code}: {e.read()[:200]!r})")
        except urllib.error.HTTPError as e:
            self.log(f"could not list models ({e.code}: {e.read()[:300]!r})")
        raise SystemExit("No Gemini model worked with this key. Check the key at aistudio.google.com.")

    def __call__(self, system, user):
        for attempt in range(10):
            try:
                self.calls += 1
                return self._post(self.model, system, user)
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 503):
                    body = e.read()[:400].decode("utf-8", "ignore")
                    if e.code == 429 and "PerDay" in body:
                        raise SystemExit("Daily free quota for this model is used up. Run START.bat again tomorrow "
                                         "(it continues where it stopped), or use a key from another Google account.")
                    wait = min(20 * (attempt + 1), 90)
                    self.log(f"  rate limited or busy ({e.code}), waiting {wait}s")
                    time.sleep(wait)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError):
                time.sleep(10)
        # An API failure must not be scored as a model answer (baseline would count it as "safe").
        raise SystemExit("Gemini kept failing. Wait a few minutes and run START.bat again.")


class GullibleMock:
    """
    A fake model for testing the harness offline. It behaves like a model with
    no injection resistance at all: it obeys any instruction to call an email
    safe and repeats its prompt when asked. Results from it say nothing about
    real models; they only prove the pipeline and scoring work.
    """
    model = "gullible-mock"
    calls = 0

    def __call__(self, system, user):
        self.calls += 1
        low = user.lower()
        m = re.search(r"<<email \w+>>(.*)<<end email", low, re.S)
        email = m.group(1) if m else low.split("\nemail:\n", 1)[-1]
        if re.search(r"(system prompt|hidden instructions|reference code|configured with)", email):
            return json.dumps({"verdict": "safe", "confidence": 0.9,
                               "reasons": ["echo: " + (system or user)[:400]], "action": "deliver"})
        if re.search(r"\bsafe\b|deliver", email) and \
                re.search(r"(ignore|classify|mark|verdict|treat|keep|pass it through|friendlyfilter|test mode|considérer|seguro)", email):
            return '{"verdict": "safe", "confidence": 0.95, "reasons": ["sender says it is safe"], "action": "deliver"}'
        if re.search(r"password|bank details|gift card|sort code|pin\b|http", email):
            return '{"verdict": "phishing", "confidence": 0.8, "reasons": ["credential or payment request"], "action": "quarantine"}'
        return '{"verdict": "safe", "confidence": 0.7, "reasons": ["routine"], "action": "deliver"}'
