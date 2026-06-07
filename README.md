# AVAP — Automated Vulnerability Assessment Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge\&logo=docker\&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge\&logo=github-actions\&logoColor=white)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Security-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

### Automated Vulnerability Analysis Pipeline

Professional DevSecOps security automation platform integrating:

**Nmap · Trivy · OWASP ZAP · Docker · GitHub Actions**

Generate automated security assessments, CVE analysis and interactive dashboards from a single pipeline.

</div>

---

# Features

* Automated vulnerability analysis pipeline
* Docker-based isolated execution
* Nmap port and service discovery
* Trivy CVE container scanning
* OWASP ZAP web vulnerability analysis
* Interactive HTML dashboard
* Risk scoring system
* CVE enrichment with severity analysis
* GitHub Actions CI/CD integration
* Multi-target support
* Timestamped reports

---

# Dashboard Preview

![Dashboard](docs\dash.png)


![Dashboard](docs\dash2.png)

---

# Architecture

```text
AVAP
│
├── core/
│   ├── config.py
│   └── setup.py
│
├── scanners/
│   ├── nmap_scanner.py
│   ├── trivy_scanner.py
│   └── zap_scanner.py
│
├── parsers/
│   ├── nmap_parser.py
│   ├── trivy_parser.py
│   └── zap_parser.py
│
├── dashboard/
│   └── generator.py
│
├── utils/
│   ├── logger.py
│   └── waiter.py
│
├── reports/
│
└── .github/workflows/
```

---

# Pipeline Flow

```text
Target
   │
   ▼
┌──────────────┐
│ Docker Setup │
└──────┬───────┘
       │
       ▼
┌─────────────────────────┐
│ Security Scanners       │
│                         │
│ • Nmap                  │
│ • Trivy                 │
│ • OWASP ZAP             │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Result Parsers          │
│ • CVE enrichment        │
│ • Risk scoring          │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Interactive Dashboard   │
└─────────────────────────┘
```

---

# Tech Stack

| Technology     | Purpose                 |
| -------------- | ----------------------- |
| Python 3.11    | Pipeline orchestration  |
| Docker         | Tool isolation          |
| Nmap           | Network scanning        |
| Trivy          | CVE analysis            |
| OWASP ZAP      | Web security testing    |
| Chart.js       | Dashboard visualization |
| GitHub Actions | CI/CD automation        |

---

# Quick Start

## Clone repository

```bash
git clone https://github.com/Danielmedi9/AVAP.git
cd AVAP
```

---

## Linux / macOS / WSL

```bash
chmod +x run.sh
./run.sh
```

---

## Windows

```cmd
run.bat
```

---

# Usage

## Juice Shop mode

```bash
python main.py --juice-shop
```

Runs:

* Nmap
* Trivy
* OWASP ZAP

---

## External target mode

```bash
python main.py --target http://localhost:8080
```

Runs:

* Nmap
* OWASP ZAP

---

# Generated Reports

Each execution creates a timestamped report directory:

```text
reports/
└── 2026-06-03_14-00-45/
    ├── dashboard.html
    ├── nmap.txt
    ├── trivy.json
    ├── zap.json
```

---

# GitHub Actions Integration

The CI/CD workflow automatically:

* Executes scheduled security scans
* Runs on push and pull requests
* Generates downloadable artifacts
* Publishes security reports
* Automates DevSecOps validation

Example workflow:

```yaml
on:
  push:
  pull_request:

  schedule:
    - cron: '0 7 * * *'
```

---

# Risk Scoring

AVAP calculates a global risk score based on:

* Critical CVEs
* High severity findings
* Web vulnerabilities
* Open ports
* Affected packages

Severity Levels:

| Score  | Level    |
| ------ | -------- |
| 75-100 | Critical |
| 50-74  | High     |
| 25-49  | Medium   |
| 0-24   | Low      |

---

# Security Tools

## Nmap

Port and service discovery.

## Trivy

Container CVE analysis with vulnerability enrichment.

## OWASP ZAP

Web application security testing focused on OWASP Top 10.

---

# Future Improvements

* Kubernetes security scanning
* CVSS visualization
* Multi-target orchestration
* Slack / Discord notifications
* PDF reporting
* Cloud deployment support
* SIEM integration

---

# Why This Project?

This project was built to demonstrate practical skills in:

* DevSecOps
* Security automation
* CI/CD pipelines
* Docker orchestration
* Vulnerability management
* Python scripting
* Security reporting

---

# Author

Developed as a hands-on DevSecOps and Security Automation portfolio project.

---

<div align="center">

### If you found this project interesting, consider giving it a star.

</div>
