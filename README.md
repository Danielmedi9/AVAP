#  Vulnerability Analysis Pipeline

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)
![Security](https://img.shields.io/badge/DevSecOps-FF6B6B?style=for-the-badge&logo=shield&logoColor=white)

**Automated vulnerability analysis platform integrating Nmap, Trivy and OWASP ZAP.**  
**Generates professional security dashboards with CVE enrichment, risk scoring and interactive charts.**

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [Dashboard](#-dashboard-preview) · [CI/CD](#-cicd-integration) · [Usage](#-usage)

</div>

---

##  Overview

This project is a **professional DevSecOps automation platform** that orchestrates multiple security scanning tools to provide comprehensive vulnerability analysis of Docker-based applications.

The pipeline automatically:
1. **Spins up** a vulnerable Docker environment (OWASP Juice Shop)
2. **Scans** with three industry-standard tools in parallel
3. **Parses** and enriches results with CVSS scores and CVE data
4. **Generates** a professional interactive HTML dashboard
5. **Integrates** with GitHub Actions for CI/CD security gates

---

##  Features

| Feature | Description |
|---------|-------------|
| **Port Scanning** | Nmap full-port scan with service/version detection |
| **Container Analysis** | Trivy CVE scanning with CVSS score enrichment |
| **Web Security** | OWASP ZAP baseline scan for OWASP Top 10 |
| **Interactive Dashboard** | Chart.js visualizations, tabs, search & filters |
| **Risk Scoring** | Weighted 0-100 risk score with severity breakdown |
| **CVE Links** | Direct links to NVD for each CVE found |
| **CI/CD Integration** | GitHub Actions with PR comments and artifacts |
| **Multi-target** | Scan any URL with `--target https://example.com` |
| **Report History** | Timestamped reports — full audit trail |

---

##  Architecture

```
vulnerability-analysis-pipeline/
│
├── main.py                    # Pipeline orchestrator (entry point)
│
├── core/                      # Infrastructure layer
│   ├── config.py              # Central configuration & constants
│   └── setup.py               # Docker environment management
│
├── scanners/                  # Scanner modules (one per tool)
│   ├── nmap_scanner.py        # Port & service discovery
│   ├── trivy_scanner.py       # Container vulnerability analysis
│   └── zap_scanner.py         # Web application security testing
│
├── parsers/                   # Result parsers (one per tool)
│   ├── nmap_parser.py         # Parses Nmap text output
│   ├── trivy_parser.py        # Parses Trivy JSON + CVSS enrichment
│   └── zap_parser.py          # Parses ZAP JSON alerts
│
├── dashboard/                 # Reporting layer
│   └── generator.py           # Professional HTML dashboard generator
│
├── utils/                     # Shared utilities
│   ├── logger.py              # Structured logging system
│   └── waiter.py              # Service availability polling
│
├── reports/                   # Generated reports (gitignored)
│   └── 2026-06-03_12-00-00/   # Timestamped report directory
│       ├── dashboard.html     # Interactive HTML dashboard
│       ├── nmap.txt           # Raw Nmap output
│       ├── trivy.json         # Raw Trivy JSON
│       └── zap.json           # Raw ZAP JSON
│
├── .github/
│   └── workflows/
│       └── security-scan.yml  # GitHub Actions CI/CD pipeline
│
└── docker-compose.yml         # Juice Shop vulnerable environment
```

### Data Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│  main.py    │───▶│   Scanners   │───▶│    Raw Output   │
│ Orchestrator│    │  Nmap        │    │  nmap.txt       │
│             │    │  Trivy       │    │  trivy.json     │
│             │    │  OWASP ZAP   │    │  zap.json       │
└─────────────┘    └──────────────┘    └────────┬────────┘
                                                │
                                                ▼
                                       ┌─────────────────┐
                                       │    Parsers      │
                                       │  + CVSS Enrich  │
                                       │  + Risk Score   │
                                       └────────┬────────┘
                                                │
                                                ▼
                                       ┌─────────────────┐
                                       │   Dashboard     │
                                       │  HTML + Charts  │
                                       │  Interactive    │
                                       └─────────────────┘
```

---

##  Quick Start

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.11+ | Pipeline runtime |
| Docker Desktop | Latest | Run all tools containerized |
| Git | Any | Clone repository |

> **No additional installations needed.** Nmap, Trivy and OWASP ZAP all run inside Docker containers — zero host dependencies.

### Installation

```bash
# 1. Clone the repository
git clone [https://github.com/Danielmedi9/AVAP.git]
cd vulnerability-analysis-pipeline
```

### 2. Run — one command, any OS

The project includes launcher scripts that **automatically** create the virtual environment, install dependencies and show an interactive menu to choose the scan mode.

####  Windows (CMD)

```cmd
run.bat
```

####  Linux / Mac / WSL / Git Bash

```bash
chmod +x run.sh   # only needed the first time
./run.sh
```

The launcher will:
1. ✅ Check Python and Docker are available
2. ✅ Create the virtual environment (only on first run)
3. ✅ Install dependencies automatically
4. ✅ Show an **interactive menu** to choose the scan mode

**Interactive menu (when no arguments are passed):**

```
════════════════════════════════════════════════════
       VULNERABILITY ANALYSIS PIPELINE
════════════════════════════════════════════════════

  ¿Qué quieres escanear?

  1) OWASP Juice Shop (entorno de prueba Docker)
     Levanta Juice Shop automáticamente y lo escanea.
     Incluye: Nmap + ZAP + Trivy

  2) Target externo (tu propia aplicación)
     Escanea una URL que ya esté en ejecución.
     Incluye: Nmap + ZAP

  3) Salir

  Elige una opción [1/2/3]: _
```

- Choose **1** → Juice Shop starts automatically, full scan (Nmap + ZAP + Trivy)
- Choose **2** → Enter your target URL, scan runs (Nmap + ZAP)

**Skip the menu — pass arguments directly:**

```bash
# Linux/Mac/Git Bash:
./run.sh --juice-shop                          # Juice Shop, no menu
./run.sh --target http://localhost:8080        # External target, no menu
./run.sh --juice-shop --no-browser            # Juice Shop, don't open browser

# Windows CMD:
run.bat --juice-shop
run.bat --target http://localhost:8080
run.bat --juice-shop --no-browser
```

<details>
<summary>Manual setup (advanced — without launcher scripts)</summary>

If you prefer to manage the virtual environment manually:

```bash
# Create and activate venv
python -m venv venv
source venv/bin/activate        # Linux/Mac/Git Bash
# or: venv\Scripts\activate     # Windows CMD

# Install dependencies
pip install -r requirements.txt

# Run with interactive menu
python main.py --juice-shop
python main.py --target http://localhost:8080
```

</details>

---

##  Usage

### Two execution modes

The pipeline has two modes — you must choose one:

#### Mode 1 — OWASP Juice Shop (built-in vulnerable lab)
```bash
# Automatically starts Juice Shop with Docker and scans it
# Runs: Nmap + ZAP + Trivy (full analysis)
python main.py --juice-shop

# Without opening the browser
python main.py --juice-shop --no-browser
```

#### Mode 2 — External target (your own app)
```bash
# Scans any URL already running (no Docker setup)
# Runs: Nmap + ZAP (Trivy skipped — no Docker image to analyze)
python main.py --target http://localhost:8080
python main.py --target http://my-app.com --no-browser
```

### Command Reference

| Flag | Description |
|------|-------------|
| `--juice-shop` | Start Juice Shop with Docker and scan it (Nmap + ZAP + Trivy) |
| `--target URL` | Scan an external target already running (Nmap + ZAP) |
| `--no-browser` | Don't auto-open the dashboard in the browser |

> `--juice-shop` and `--target` are mutually exclusive — use one or the other.

### Example Output

```
════════════════════════════════════════════════════════
       VULNERABILITY ANALYSIS PIPELINE
════════════════════════════════════════════════════════
  Modo   : Juice Shop (Docker)
  Target : http://localhost:3000
  Trivy  : imagen Docker
  Browser: enabled
════════════════════════════════════════════════════════

══════════════════════════════════════════
  SETUP — Levantando OWASP Juice Shop
══════════════════════════════════════════
[14:00:01] [SETUP] Docker activo ✓
[14:00:03] [SETUP] Servicios levantados ✓

══════════════════════════════════════════
  SCAN — Ejecutando escáneres de seguridad
══════════════════════════════════════════
[14:00:45] [NMAP]  ✓ Escaneo completado → reports/2026-06-03_14-00-45/nmap.txt
[14:02:10] [TRIVY] ✓ Resultados guardados en reports/.../trivy.json
[14:08:30] [ZAP]   ⚠ Escaneo completado con alertas encontradas (normal)

══════════════════════════════════════════
  PARSE — Procesando resultados
══════════════════════════════════════════
[14:08:31] [PARSER] ✓ Nmap: 1 puertos abiertos encontrados
[14:08:32] [PARSER] ✓ Trivy: 187 vulnerabilidades (3 críticas, 42 paquetes afectados)
[14:08:32] [PARSER] ✓ ZAP: 12 alertas (2 altas, 6 medias)

════════════════════════════════════════════════════════
        RESUMEN DE HALLAZGOS
════════════════════════════════════════════════════════
  Puertos abiertos  : 1
  CVEs Críticos     : 3
  CVEs Altos        : 28
  CVEs Medios       : 89
  CVEs Bajos        : 67
  Alertas Web High  : 2
  Alertas Web Medium: 6
  Reportes en       : reports/2026-06-03_14-00-45/
════════════════════════════════════════════════════════
```

---

##  Dashboard Preview

The generated dashboard includes:

### Executive Summary
- **Risk Score Gauge** — Visual 0-100 risk indicator with color coding
- **Key Metrics Cards** — Open ports, Critical CVEs, High CVEs, Packages affected
- **Critical Findings** — Top vulnerabilities with CVSS scores and fix versions

### Security Visualizations (Chart.js)
- **CVE Distribution Donut** — Breakdown by severity (Critical/High/Medium/Low)
- **Web Alerts Donut** — ZAP findings by risk level
- **Top Vulnerable Packages Bar Chart** — Packages with most CVEs

### Detailed Findings (Tabbed Interface)
- ** Open Ports** — Port, state, service, version banner
- ** CVE Details** — CVE ID (linked to NVD), severity badge, CVSS score, package, installed version, fix version, title
- ** Web Alerts** — Alert name, risk, confidence, instances, description

### Interactive Features
-  **Search** — Filter any table in real-time
-  **Severity Filters** — Show only CRITICAL / HIGH / MEDIUM / LOW
-  **Tabs** — Switch between Nmap, Trivy and ZAP results
-  **CVE Links** — Click any CVE to open NVD page
-  **Tooltips** — Hover on titles for full description

---

##    How It Works

###   Scanner Details

####    Nmap — Port Scanner
```bash
# What runs internally:
docker run --rm --network vuln-lab_default \
  instrumentisto/nmap \
  -sV -p- --open juice-shop
```
- `-sV` → Service version detection
- `-p-` → Scan all 65535 ports
- `--open` → Show only open ports
- Runs inside Docker on the same network as the target

####    Trivy — Container Scanner
```bash
# What runs internally:
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/aquasecurity/trivy:latest \
  image --format json bkimminich/juice-shop
```
- Analyzes the Docker image layer by layer
- Detects CVEs in OS packages and application dependencies
- Extracts CVSS scores from NVD, GHSA, RedHat sources

####    OWASP ZAP — Web Scanner
```bash
# What runs internally:
docker run --rm --network vuln-lab_default \
  -v /path/to/reports:/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -j -m 5 -J zap.json
```
- Baseline scan: fast, non-destructive, CI/CD friendly
- JavaScript spider for Single Page Applications
- Detects OWASP Top 10 vulnerabilities

### Risk Scoring Formula

```
Risk Score (0-100) =
  CRITICAL CVEs × 10  +
  HIGH CVEs     × 4   +
  MEDIUM CVEs   × 1   +
  ZAP High      × 8   +
  ZAP Medium    × 3   +
  ZAP Low       × 1   +
  Open Ports    × 2

  → capped at 100
```

| Score | Level | Meaning |
|-------|-------|---------|
| 75-100 | 🔴 CRITICAL | Immediate action required |
| 50-74 | 🟠 HIGH | Prioritize remediation |
| 25-49 | 🟡 MEDIUM | Address promptly |
| 0-24 | 🟢 LOW | Continue monitoring |

---

##    CI/CD Integration

### GitHub Actions Workflow

The included workflow (`.github/workflows/security-scan.yml`) automatically:

```
Push to main/develop
        │
        ▼
┌───────────────────┐
│  GitHub Actions   │
│                   │
│  1. Checkout      │
│  2. Setup Python  │
│  3. Start Juice   │
│     Shop          │
│  4. Run Nmap      │
│  5. Run Trivy     │
│  6. Run ZAP       │
│  7. Generate      │
│     Dashboard     │
│  8. Comment PR    │◀── Pull Request comment with summary
│  9. Upload        │
│     Artifacts     │◀── Downloadable dashboard.html
└───────────────────┘
```

### Triggers
- ✅ Push to `main`, `develop`, `feature/**`
- ✅ Pull Requests to `main`
- ✅ Weekly scheduled scan (Monday 08:00 UTC)
- ✅ Manual trigger via `workflow_dispatch`

### PR Comment Example

When a Pull Request is opened, the bot automatically comments:

```
🔴 Security Scan Results

| Metric              | Count |
|---------------------|-------|
| 🔴 Critical CVEs    | 3     |
| 🟠 High CVEs        | 28    |
| 🟡 Web Alerts (High)| 2     |
| 🌐 Open Ports       | 1     |

📊 Full dashboard available in the Artifacts section.
```

---

##    Tech Stack

| Technology | Role | Why |
|------------|------|-----|
| **Python 3.11** | Pipeline orchestration | Clean, readable, great subprocess support |
| **Docker** | Tool isolation | No host dependencies, reproducible |
| **Nmap** | Port scanning | Industry standard, comprehensive |
| **Trivy** | CVE scanning | Fast, accurate, great JSON output |
| **OWASP ZAP** | Web security | OWASP standard, CI/CD friendly |
| **Chart.js** | Dashboard charts | CDN-loaded, no build step needed |
| **GitHub Actions** | CI/CD | Native GitHub integration |
| **OWASP Juice Shop** | Vulnerable target | Realistic, intentionally vulnerable |

---

##    Report Structure

Each pipeline run creates a timestamped directory:

```
reports/
└── 2026-06-03_14-00-45/
    ├── dashboard.html    ← Interactive HTML dashboard (open in browser)
    ├── nmap.txt          ← Raw Nmap output (human readable)
    ├── trivy.json        ← Full Trivy JSON (all CVE details)
    ├── trivy.txt         ← Trivy table format (human readable)
    ├── zap.json          ← ZAP findings JSON
    ├── zap.html          ← ZAP HTML report
    └── zap.xml           ← ZAP XML report
```

---

##    Security Considerations

- **No credentials stored** — All tools run with minimal permissions
- **Docker socket access** — Required by Trivy; use with caution in production
- **Network isolation** — Scanners run in isolated Docker networks
- **Read-only analysis** — ZAP baseline scan is non-destructive
- **Gitignored reports** — Raw scan data not committed to repository

---

##    Troubleshooting

### Docker not found
```bash
# Verify Docker is running
docker info

# If not running, start Docker Desktop
```

### Juice Shop not starting
```bash
# Check container logs
docker logs juice-shop

# Restart the environment
docker compose down && docker compose up -d
```

### ZAP scan fails
```bash
# ZAP exit code 2 is NORMAL (means alerts were found)
# Only codes other than 0 and 2 indicate real errors
```

### ZAP PermissionError on Windows
```
PermissionError: [Errno 13] Permission denied: '/zap/wrk/zap.yaml'
```
This happens because ZAP runs as user `zap` (not root) inside the container, and Docker Desktop on Windows mounts volumes with permissions that only allow the root user to write.

**Already fixed** in `scanners/zap_scanner.py` with `--user root` in the docker run command. If you still see this error, make sure you have the latest version of the file.

### Trivy can't access Docker socket
```bash
# On Linux, add your user to the docker group
sudo usermod -aG docker $USER

# On Windows with Docker Desktop, the socket is exposed automatically
```

### Reports directory is empty
```bash
# Check that the report directory was created
ls reports/

# Run with verbose output
python main.py --skip-setup
```

---

##  Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

The CI/CD pipeline will automatically run a security scan on your PR.

---

##    License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

##    Author

Built as a **DevSecOps portfolio project** demonstrating:
- Security automation with Python
- Docker-based tool orchestration
- Professional reporting and visualization
- CI/CD security integration (GitHub Actions)
- Industry-standard security tools (Nmap, Trivy, OWASP ZAP)

---

<div align="center">

**⭐ If this project helped you, please give it a star!**

*Vulnerability Analysis Pipeline · Nmap + Trivy + OWASP ZAP · DevSecOps*

</div>
=======
# AVAP
Automated Vulnerability Assessment Platform
>>>>>>> 37e7264fb57b4c9b162a028ed98f834f7e11c9c4
