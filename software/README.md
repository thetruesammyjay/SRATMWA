# SRATMWA Software System

A web application that operationalises the Security Risk Assessment and Threat Modeling methodology defined in this project.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, Flask 3, Flask-SQLAlchemy |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Frontend | Vanilla HTML/CSS/JS (no framework required) |
| Migrations | Flask-Migrate (Alembic) |

---

## Quick Start

### 1. Set up Python environment

```bash
cd software
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
```

### 2. Initialise and seed the database

```bash
python seed.py
```

### 3. Run the development server

```bash
python run.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## Directory Structure

```
software/
├── run.py                    # Application entry point
├── seed.py                   # Database seed script (starter data)
├── config.py                 # Application configuration
├── requirements.txt
├── .env                      # Environment variables
│
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── models.py             # SQLAlchemy ORM models
│   └── routes/
│       ├── assets.py         # Asset CRUD API
│       ├── threats.py        # Threat model API (STRIDE/DREAD/PASTA)
│       ├── vulnerabilities.py# Vulnerability tracking API
│       ├── risks.py          # Risk register API (NIST SP 800-30)
│       ├── controls.py       # Security controls API
│       ├── checklists.py     # Checklist runner API
│       ├── reports.py        # Report generation API
│       ├── dashboard.py      # Aggregated summary API
│       └── views.py          # HTML page routes
│
└── frontend/
    ├── static/
    │   ├── style.css         # Dark theme UI stylesheet
    │   └── app.js            # Shared JS utilities
    └── templates/
        ├── base.html         # Base layout with sidebar navigation
        ├── index.html        # Dashboard
        ├── threats.html      # Threat model manager
        ├── risks.html        # Risk register
        ├── vulnerabilities.html
        ├── controls.html     # Security controls tracker
        ├── checklists.html   # Checklist runner
        └── reports.html      # Report viewer and generator
```

---

## Features

### Dashboard
- Live counts: assets, threats, risks, vulnerabilities, controls, checklist items
- Risk level breakdown chart (Critical / High / Medium / Low)
- STRIDE category distribution
- Vulnerability severity breakdown
- Control implementation status
- Checklist completion percentage

### Threat Models (`/threats`)
- Full STRIDE classification
- DREAD scoring (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)
- PASTA stage tracking (1–7)
- Auto-generated threat IDs: `THREAT-[STRIDE-initial]-[COMPONENT]-[NNN]`
- Filter by STRIDE category and status

### Risk Register (`/risks`)
- NIST SP 800-30 / OWASP Risk Rating scoring: Likelihood × Impact
- Automatic risk level calculation (Critical ≥ 80, High ≥ 50, Medium ≥ 25, Low < 25)
- Auto-generated risk IDs: `RISK-[COMPONENT]-[NNN]`
- Treatment tracking: Mitigate / Accept / Transfer / Avoid

### Vulnerabilities (`/vulnerabilities`)
- CVSS v3.1 score and vector string
- OWASP Top 10 (2021) mapping
- CVE linkage
- Filter by severity and status

### Security Controls (`/controls`)
- Type classification: Preventive / Detective / Corrective
- NIST SP 800-53 and OWASP ASVS mappings
- Implementation status tracking

### Checklists (`/checklists`)
- Pre-loaded with OWASP Top 10, Authentication, API Security, Cryptography, and Logging checks
- One-click Pass / Fail / N/A status per item
- Live completion progress bar
- Filter by domain

### Reports (`/reports`)
- One-click generate **Executive Summary** (leadership-focused)
- One-click generate **Technical Report** (full findings tables)
- Reports auto-populated from live database state
- Save and manage multiple historical reports

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/dashboard/summary` | Aggregated metrics |
| GET/POST | `/api/assets/` | List / create assets |
| GET/PUT/DELETE | `/api/assets/<id>` | Read / update / delete asset |
| GET/POST | `/api/threats/` | List / create threats |
| GET | `/api/threats/stride-summary` | Count per STRIDE category |
| GET/POST | `/api/vulnerabilities/` | List / create vulnerabilities |
| GET/POST | `/api/risks/` | List / create risk entries |
| GET | `/api/risks/matrix` | Risk counts by level |
| GET/POST | `/api/controls/` | List / create controls |
| GET/POST | `/api/checklists/` | List / create checklist items |
| GET | `/api/checklists/progress` | Completion statistics |
| GET | `/api/checklists/domains` | Available domains |
| GET/POST | `/api/reports/` | List / create reports |
| POST | `/api/reports/generate` | Auto-generate report from DB |

---

## Risk Scoring

$$\text{Risk Score} = \text{Likelihood} \times \text{Impact}$$

| Score | Level |
|---|---|
| ≥ 80 | Critical |
| ≥ 50 | High |
| ≥ 25 | Medium |
| < 25 | Low |

## DREAD Scoring

$$\text{DREAD Score} = \frac{D + R + E + A + D_2}{5}$$

Where each factor is scored 1–10.
