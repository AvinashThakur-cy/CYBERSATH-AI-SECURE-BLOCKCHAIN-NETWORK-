# CYBERSATHI

CYBERSATHI is a placement-ready blockchain security operations console. It demonstrates a complete FastAPI backend, validated action workflows, explainable risk telemetry, responsive dashboard UI, and exportable security reporting.

## Run locally on Windows

1. Create and activate a virtual environment (the included `.venv` can be used):
   `py -m venv .venv` and `.venv\Scripts\activate`
2. Install dependencies:
   `pip install -r requirements.txt`
3. Start the app by double-clicking `start.bat`, or run:
   `uvicorn app.main:app --reload --host 127.0.0.1 --port 8000`
4. Open http://127.0.0.1:8000/ (the API is intentionally local and makes no external network calls).

## Product capabilities

- Live dashboard metrics for blockchain health, nodes, wallets, incidents, and model confidence.
- Module views for threat intelligence, attack investigation, blockchain exploration, node management, wallet intelligence, incident response, Attack DNA, and AI Copilot.
- Validated operator actions for integrity scans, wallet isolation, node freeze preparation, incident escalation, and report generation.
- JSON security report export with findings and recommended controls.
- Responsive desktop and mobile layout with command palette and light/dark themes.
- Offline URL, email, and password checks in the dashboard using deterministic local rules.

## API surface

- `GET /api/dashboard` returns the primary dashboard data.
- `GET /api/modules/{module_id}` returns module-specific evidence and actions.
- `POST /api/actions` accepts a validated action payload such as `{"action":"run-scan"}`.
- `GET /api/report` returns the exportable security report.
- `GET /api/telemetry` remains available as a compatibility payload.
- `GET /api/health` reports local service health.
- `POST /api/analyze/url` accepts `{"url":"https://example.com"}`.
- `POST /api/analyze/email` accepts `{"email":"name@example.com"}`.
- `POST /api/analyze/password` accepts `{"password":"..."}`; the password is never returned or written to audit logs.

All analysis responses use the same format: `status`, `analysis_type`, `risk_level`, `score`, `summary`, `findings`, `recommendations`, `metadata`, and `analyzed_at`. Analysis audit entries contain metadata only.

## Verification

Run tests with:
`pytest -q`
