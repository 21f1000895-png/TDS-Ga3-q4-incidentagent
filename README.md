# Public HTTPS Incident Agent (starter)

A FastAPI implementation of the `ga5-incident-agent/v2` assignment API.

## Important honesty note

This is a working **starter scaffold**, not a verified 4/4 submission. The hidden incidents, tool schemas, exact expected arguments, and effect semantics are not included in the assignment text. Before using the grader, finish and test the TODO-level behavior described below. In particular, the current effect selection is intentionally conservative and cannot invent incident-specific effect arguments. The trace builder provides an OTLP-shaped JSON payload, but must be validated against the grader's exact span correlation expectations.

## Files

- `main.py`: endpoints, model planning, receipt state, replay/conflict checks and trace output.
- `requirements.txt`: Python dependencies.
- `render.yaml`: Render Blueprint configuration.
- `.env.example`: local environment template.

## Run locally

Python 3.11+ recommended.

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
export OPENAI_API_KEY="your-key"
uvicorn main:APP --reload
```

Open `http://127.0.0.1:8000/docs` to inspect the API. Never put a real provider key in GitHub or in an incident request.

## Deploy to Render

1. Create a GitHub repository and upload these files.
2. In Render, choose **New → Web Service**, connect the repository, and deploy.
3. Set `OPENAI_API_KEY` in Render's Environment settings.
4. Use `https://YOUR-SERVICE.onrender.com` as the public base URL (no credentials, query string or fragment).
5. Test `GET /health` and then the grader.

Render free instances have ephemeral storage and may sleep. `DB_PATH=/tmp/...` is therefore only suitable for a smoke test, not reliable persistence. For grading, configure a persistent datastore supported by the plan (for example Render Postgres) and update the storage layer. Render persistent disks are generally a paid feature; check current Render terms.

## Required finishing work before grading

1. **Database durability and concurrency:** replace SQLite `/tmp` with Render Postgres or another durable store; add transaction/locking semantics so duplicate concurrent requests cannot create two plans.
2. **Effect planning:** select the single justified effect and construct exact arguments from the incident/catalog. Do not guess required arguments. The scale-limit rule must suppress scaling and page the owner when the catalog permits it.
3. **Trace correctness:** create `execute_tool` spans before the CLIENT attempt; use the exact `execute_tool` span ID as parent for the matching CLIENT span; create `incident.join` links to all independent diagnostic logical spans; include `approval_gate`; preserve incoming `tracestate`; add CLIENT spans for every attempt and correlate receipts.
4. **Retry semantics:** after one 503, issue exactly one retry with same action/call IDs, incremented attempt and a fresh CLIENT span ID. Never include an approval request in a retry response.
5. **Terminal state:** do not mark completed while an effect is pending. Ensure final state contains all dispatches and receipt records and no pending work.
6. **Approval:** canonicalize the exact effect arguments and SHA-256 them; hold destructive actions until a matching approval receipt; dispatch with the same reserved action ID and the approval nonce.
7. **Tests:** test same-request replay, changed run content (409), identical receipt replay, changed receipt content (409), timeout suppression, 503 retry, approval denial/approval, sensitive redaction, and trace IDs/parent IDs.
8. **No secrets:** never log transcripts, prompts, tool arguments/results, access tokens, or authorization headers.

## API overview

- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`
- `GET /health`

The AI planner receives a sanitized request with `sensitive` removed. The model is called only on first creation; GET and identical replay do not call it.

## Why the assignment is tricky

The grader's receipts are authoritative. A dispatch is a proposal/attempt; it is not proof that the tool succeeded. Never fabricate a success result. Persist state before returning it, and never call the model from the receipt endpoint.
