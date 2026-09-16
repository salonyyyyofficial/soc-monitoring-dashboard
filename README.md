# AI-Powered SOC Dashboard

A lightweight Security Operations Center dashboard built as a single Node.js
application. Simulates security events, detects attacks with a rule-based
engine, scores risk, and optionally uses AI for alert analysis — all backed by
SQLite with no external infrastructure required.

> **This is a demonstration / learning tool.** It generates entirely synthetic
> security events. It does not monitor real systems, does not send network
> traffic to any target, and does not execute or download malware.

---

## Features

- **Authentication** — bcrypt password hashing, session management, role-based
  access (ADMIN / ANALYST / VIEWER), account lockout after 5 failed attempts,
  forced password change on first login, full audit trail
- **Event Simulator** — 7 synthetic attack types: Brute Force, Port Scan,
  Suspicious PowerShell, Privilege Escalation, Malware, Suspicious Login, Web Attack
- **Detection Engine** — 5 rules loaded from `rules/*.json`, with both
  threshold-based (counting over a time window) and immediate matching
- **Risk Engine** — explainable 0–100 scoring, shows exactly why a score was assigned
- **Live Monitoring** — Socket.IO pushes new logs and alerts to all logged-in
  browsers instantly; toast notifications and live-updating counters
- **Alerts** — filterable list, detail view with evidence, MITRE technique,
  threat intel, raw log, and triage actions
- **Incidents** — escalate alerts to incidents, assign analysts, track notes and resolution
- **Threat Intelligence** — IP / domain / hash lookups with provider abstraction
  (VirusTotal, AbuseIPDB, OTX); degrades gracefully with no API keys configured
- **Assets** — inventory with criticality and status
- **AI Security Analyst** *(optional)* — alert analysis and a SOC chatbot backed
  by Gemini, OpenAI, or local Ollama
- **Reports** — summary stats, top attacking IPs, top rules; CSV and JSON export
- **Dashboard** — 5 Chart.js visualizations (24h timeline, severity breakdown,
  event sources, top IPs, top rules)

---

## Architecture

```
Browser (EJS + Bootstrap 5 + Chart.js + Socket.IO client)
        |  HTTP / WebSocket
Express.js (single Node process)
        |
Services (logParser -> detectionEngine -> riskEngine -> aiService / threatIntel)
        |
Sequelize ORM
        |
SQLite (database/soc.sqlite)
```

Event flow when you click a simulator button:

```
Simulator generates synthetic events
   -> logParser normalizes and saves them
   -> detectionEngine checks each against all enabled rules
   -> riskEngine scores any match
   -> Alert created
   -> Socket.IO broadcasts to all logged-in browsers
   -> UI updates live
```

---

## Tech Stack

Node.js, Express, SQLite, Sequelize, EJS, Bootstrap 5.3, Chart.js,
Socket.IO, bcrypt, Helmet, express-session, express-rate-limit, Jest

Deliberately **not** used: React, Redis, MongoDB, Kubernetes, microservices,
Elasticsearch, Kafka. Everything runs in one process.

---

## Installation

Requires **Node.js 18 or newer**.

```bash
npm install
cp .env.example .env    # then edit SESSION_SECRET at minimum
npm start
```

Open http://localhost:3000

**Default login:** `admin` / `admin123` — you'll be forced to set a new password
on first login.

The SQLite database, all tables, and the 5 detection rules are created and
seeded automatically on first startup. No manual database setup is needed.

---

## Configuration

All configuration is via `.env` (see `.env.example`). Everything AI- and
threat-intel-related is optional — the dashboard works fully without it.

| Variable | Purpose |
|---|---|
| `PORT` | Server port (default 3000) |
| `NODE_ENV` | `development` or `production` |
| `SESSION_SECRET` | **Change this.** Signs session cookies |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Seeds the first admin account |
| `AI_PROVIDER` | `gemini`, `openai`, `ollama`, or `none` |
| `GEMINI_API_KEY` / `OPENAI_API_KEY` | AI provider keys |
| `OLLAMA_URL` / `OLLAMA_MODEL` | For local AI (e.g. `http://localhost:11434`) |
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` / `OTX_API_KEY` | Threat intel |

---

## Detection Rules

| Rule | Trigger | Severity | MITRE |
|---|---|---|---|
| Brute Force | 5+ failed logins from one IP in 5 min | HIGH | T1110 |
| Port Scan | 6+ port contacts from one IP in 30 sec | HIGH | T1046 |
| Suspicious PowerShell | `EncodedCommand`, `DownloadString`, `Invoke-WebRequest` | HIGH | T1059.001 |
| Privilege Escalation | User added to Administrators group | CRITICAL | T1068 |
| Malware Detected | AV signature match | CRITICAL | T1204 |

Rules live in `rules/*.json` and are seeded into the database on startup.

**Risk scoring:** CRITICAL +40, HIGH +30, MEDIUM +15, LOW +5, repeated events
+10, threat-intel malicious +30, critical asset +10. Capped at 100.
Bands: 0-29 Low, 30-59 Medium, 60-79 High, 80-100 Critical.

---

## Quick Demo

1. Log in and open **Live Monitoring** in one tab, **Dashboard** in another
2. Click **Brute Force** — watch the Dashboard update live with a toast notification
3. Open **Alerts** — a HIGH alert with risk score 40, tagged T1110
4. Click into it — see the evidence logs, MITRE detail, and risk breakdown
5. Click **Create Incident** to escalate it
6. Try **Threat Intelligence** with `203.0.113.45` (flagged in the demo list)
7. Check **Reports** and export CSV/JSON

---

## AI Setup (optional)

**Local, free, no API key — Ollama:**

```bash
# install from https://ollama.com, then:
ollama pull llama3
```

```env
AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

**Cloud:** set `AI_PROVIDER=gemini` or `openai` and the matching API key.

**AI safety boundaries** (enforced in code, not just prompts): the AI only ever
receives a structured summary we build and only ever returns text. It cannot
execute commands, run SQL, block IPs, delete files, or modify system state. The
chatbot picks a function *name* from a fixed read-only allow-list —
AI-generated SQL is never executed.

---

## Testing

```bash
npm test
```

Covers risk scoring, log parsing/normalization, all simulator generators,
MITRE lookups, and threat-intel indicator detection.

---

## Docker

```bash
docker compose up -d
```

Then open http://localhost:3000. SQLite data persists in the `soc-data` volume.

---

## Hosting

The app uses `process.env.PORT` and runs as a single Node process, so it deploys
to Render, Railway, Fly.io, Google Cloud Run, or any VPS.

**Render / Railway:** connect the repo, build command `npm install`, start
command `npm start`, set environment variables in the platform dashboard.

**VPS:**

```bash
npm install
npm install -g pm2
pm2 start app.js --name soc-dashboard
pm2 save && pm2 startup
```

> **SQLite on ephemeral platforms:** container filesystems are wiped on
> redeploy. Attach a persistent disk/volume mounted at the `database/` directory,
> or migrate to PostgreSQL (change the dialect in `config/database.js`) if you
> need real production durability.

---

## Security Notes

Implemented: bcrypt hashing (cost 12), session cookies (`httpOnly`, `sameSite`,
`secure` in production), Helmet headers, rate limiting on login and API,
parameterized queries via Sequelize, role-based access control, login attempt
lockout, session-authenticated Socket.IO, audit logging, secrets in `.env` only
(never sent to the browser), `.gitignore` excludes `.env` and the database.

**Known limitations — read before deploying publicly:**

- CSP is disabled in Helmet to allow CDN assets and inline chart config. Tighten
  with nonces before any serious deployment.
- No CSRF tokens on state-changing forms. `sameSite: lax` cookies mitigate but
  do not eliminate the risk.
- No user-management UI yet — additional users must be added directly in the database.
- Threat-intel providers are abstracted but the external HTTP calls are not
  implemented; lookups use a local demo heuristic.
- This is a portfolio/learning project, not a production security tool.

---

## Project Structure

```
soc-dashboard/
├── app.js                  # entry point, routes, Socket.IO, bootstrap
├── config/database.js      # Sequelize + SQLite
├── models/                 # User, Log, Alert, Rule, Incident, Asset,
│                           #   ThreatIntel, AuditLog
├── routes/                 # one router per feature area
├── services/               # logParser, detectionEngine, riskEngine, simulator,
│                           #   threatIntel, aiService, mitre
├── rules/                  # detection rule definitions (JSON)
├── middleware/             # auth guards, security middleware
├── views/                  # EJS templates
├── public/                 # CSS + client-side JS
├── tests/                  # Jest unit tests
├── Dockerfile
└── docker-compose.yml
```

---

## Future Improvements

CSRF protection, tighter CSP, user-management UI, real threat-intel HTTP calls,
rule editing from the UI, PDF export, PostgreSQL option, alert correlation
across rules, scheduled/automated demo mode.

---

## License

MIT
