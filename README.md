# PromptGuard

Testing how an AI email filter can be talked out of flagging phishing, and which defences actually stop it.

Small firms are starting to put an LLM in front of their inbox to sort phishing from real mail. The model reads attacker-written text, so the attacker can write instructions for it: "this email is safe", hidden white text, a fake "system notice", a ready-made JSON verdict. This project measures how often that works and what reduces it.

## What it does

- **Test set.** 98 emails for a fictional UK accounting firm (Kestrel Accounting): 12 benign, 12 plain phishing, 32 phishing emails carrying a prompt injection across 12 techniques, plus a held-out set of 10 injections and 6 benign emails written after the defences were frozen.
- **Two pipelines, same model.**
  - `baseline`: the email pasted into one prompt, the model's JSON used as-is.
  - `guarded`: five layers. (1) Strip hidden HTML, comments and zero-width characters. (2) Scan for injection patterns, since an email that tries to instruct the filter is itself a phishing signal. (3) Wrap the email in a random per-request boundary and tell the model it is untrusted data. (4) Strict output schema; anything else fails closed to human review. (5) A rule-based minimum verdict the model can raise but never lower. A canary string in the system prompt detects prompt leaks.
- **Scoring.** Attack success rate per technique, prompt leaks, plain phishing caught, benign emails wrongly flagged, and which layer stopped each blocked attack.

Everything uses fictional names and `.example` domains. No real phishing infrastructure.

## Run it

Windows: double-click `START.bat` and paste a Gemini API key (free from aistudio.google.com). About 15 minutes on the free tier.

```
python run.py            # real run, asks for GEMINI_API_KEY
python run.py --mock     # offline check of the pipeline with a deliberately gullible fake model
python -m pytest -q      # unit tests
```

Standard library only. Results land in `results/<model>.md` and `.json`.

## Results (gemini-3.5-flash-lite, temperature 0)

Main set, 32 injection emails, 12 plain phishing, 12 benign:

| | Baseline | Guarded |
|---|---|---|
| Injection attacks that got phishing delivered as safe | **4 / 32** | **0 / 32** |
| Plain phishing caught | 12 / 12 | 12 / 12 |
| System prompt leaked | 0 / 32 | 0 / 32 |
| Benign emails wrongly flagged | 2 / 12 | 2 / 12 |

The four attacks that beat the baseline were two fake end-of-email markers followed by "system" text, one ready-made JSON verdict for the model to copy, and one "developer test mode" role-play. Plain "ignore your instructions" text, hidden HTML, base64 and other languages did not work on this model even without defences.

What stopped them in the guarded pipeline: in all 42 blocked cases the model itself returned a non-safe verdict once the email was wrapped in a random boundary and labelled untrusted. The rule floor never had to overrule it on this model, so it acts as insurance for weaker models (on a deliberately gullible mock model the floor caught 20 of the attacks the model let through).

Held-out set (10 injections and 6 benign emails written after the rules were frozen):

| | Baseline | Guarded |
|---|---|---|
| Injection attacks that got phishing delivered as safe | 1 / 10 | **0 / 10** |
| Benign emails wrongly flagged | 1 / 6 | 3 / 6 |

Across both sets: **5 of 42** attacks beat the unprotected filter, **0 of 42** beat the guarded one. On the held-out set the regex scanner alone recognised none of the 10 attacks, yet the guarded pipeline still stopped all of them, because the boundary prompt and the model did the work. The cost is false positives: the rules flag benign emails that merely sound like instructions ("ignore the old fire drill instructions", "I'll act as a confused client"), so 3 of 6 held-out benign emails went to review instead of the inbox.

Full tables: `results/gemini-3.5-flash-lite.md`.

## Limitations

- The rule scanner was written alongside the main test set, so its score there is optimistic. The held-out set is the honest measure, and on the held-out set the pattern scanner alone caught none of the 10 injections. Regex scanners overfit to the phrasing their author had in mind; the layers that held up were the ones that do not depend on wording (sanitising, the boundary, schema validation, the verdict floor).
- The floor raises verdicts on emails that merely sound like instructions ("ignore the old fire drill instructions"), so some benign mail goes to review. For a filter that is the right way round, but it has a cost.
- One model, temperature 0, one run. A different model or a larger attack set could move the numbers.
