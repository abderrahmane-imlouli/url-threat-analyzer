# URL Threat Analyzer (Cybersecurity Intelligence Tool)

> Analyze suspicious URLs using multi-source threat intelligence (VirusTotal, urlscan.io, WHOIS & DNS) in one unified dashboard.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Django](https://img.shields.io/badge/Django-4.2-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

| Module             | Description                                                                         |
| ------------------ | ----------------------------------------------------------------------------------- |
| Static Analysis | Detects missing HTTPS, IP-based URLs, suspicious keywords, encoded characters       |
| WHOIS Lookup   | Shows domain age, registrar, creation/expiry dates — flags newly registered domains |
| DNS Resolution  | Resolves domain to IP address                                                       |
| VirusTotal     | Scans against 70+ antivirus engines and threat databases                            |
| urlscan.io      | Full sandbox scan with screenshot, verdict, and page metadata                       |

---

## Architecture

```
User Input URL
      ↓
Backend (Django)
      ↓
+ Static Analysis
+ WHOIS Lookup
+ DNS Resolution
+ VirusTotal API
+ urlscan.io API
      ↓
Aggregated Results
      ↓
Frontend Dashboard
```

---

## Example Analysis

| Check           | Result                   |
| --------------- | ------------------------ |
| HTTPS           | ❌ Missing                |
| Domain Age      | ⚠️ 2 days (Suspicious)   |
| VirusTotal      | 🚨 12/70 engines flagged |
| urlscan Verdict | ⚠️ Suspicious            |

> Final Risk Score: **High Risk**

---

## Use Cases

* Security analysts investigating suspicious URLs
* Bug bounty hunters analyzing phishing links
* SOC teams performing quick threat triage
* Students learning web security analysis

---

## Demo

> Coming soon — hosted on PythonAnywhere

---

## Getting Started

### Prerequisites

* Python 3.11+
* A free VirusTotal API key
* A free urlscan.io API key

### Installation

```bash
git clone https://github.com/abderrahmane-imlouli/url-threat-analyzer.git
cd url-threat-analyzer
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root:

```
VT_API_KEY=your_virustotal_api_key
URLSCAN_API_KEY=your_urlscan_api_key
```

> ⚠️ Never commit `.env` to GitHub. It is already listed in `.gitignore`.

### Run Locally

```bash
python manage.py runserver
```

Open your browser at: http://127.0.0.1:8000

---

## Deployment

This project is ready to deploy on:

* PythonAnywhere (free tier available)
* Railway

Set your environment variables (`VT_API_KEY`, `URLSCAN_API_KEY`)
in the platform dashboard instead of using a `.env` file.

---

## 🔒 Security Notes

* API keys are loaded from environment variables — never hardcoded
* `.env` is excluded from version control via `.gitignore`
* All scanning is done server-side — no keys are exposed to the browser

---

## Tech Stack

* Backend — Python, Django
* APIs — VirusTotal v3, urlscan.io v1
* Frontend — Vanilla JS, CSS (dark cybersecurity theme)

---

## Future Improvements

* Machine Learning-based risk scoring
* Browser extension version
* Real-time phishing detection
* Integration with SIEM tools

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
