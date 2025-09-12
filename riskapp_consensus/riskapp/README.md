# Risk Management Web App (HTML + Python/Flask)

A starter implementation for the risk management model you described: login, dashboard,
create/select/edit risks, timestamped system comments on edits, per‑risk evaluations
(probability/severity 1–5), color‑coded score (max 25), decision‑support suggestions,
and printable HTML reports.

## Quick start
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
# demo login: any username (no password)
```
Data persists to `riskapp.db` (SQLite). First run will seed a few example suggestions.

## Notes
- Score = probability × severity (1–5 → max 25).
- Editing a risk automatically creates a *system* comment with timestamp (shown grey and not deletable).
- The report view can be printed to PDF from the browser.
