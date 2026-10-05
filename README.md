# Insider Threat Detector: Autonomous Security Alert Investigation System

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://reactjs.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg)](https://tailwindcss.com/)
[![ML](https://img.shields.io/badge/ML-Scikit--Learn%20%7C%20NetworkX-F7931E.svg)](https://scikit-learn.org/)

**Insider Threat Detector** is an end-to-end cybersecurity investigation and triage platform designed to identify, analyze, correlate, and prioritize potential insider security threats.

The system combines machine learning, behavioral analysis, incident correlation, and autonomous investigation to help security analysts detect suspicious activities and reduce alert fatigue while maintaining visibility into genuine security incidents.

Using real-world telemetry from the **Microsoft Security Incident Prediction benchmark dataset (`GUIDE_Train.csv`)**, Insider Threat Detector deploys a 6-component ML intelligence pipeline, executes a multi-step **LangGraph** autonomous investigation workflow, and provides a dark-mode React analyst console featuring risk visualization, interactive timelines, entity correlation graphs, and side-by-side alert analysis.

---

## 🌟 Key Features & Capabilities

### 1. Microsoft GUIDE Benchmark Ingestion & Zero-Setup Fallback

- **Official GUIDE Schema Support**: Ingests `OrgId`, `IncidentId`, `AlertId`, `Timestamp`, `DetectorId`, `AlertTitle`, `Category`, `MitreTechniques`, `IncidentGrade` (`TruePositive`, `BenignPositive`, `FalsePositive`), `ActionGrouped`, `DeviceId`, `AccountUpn`, `IpAddress`, `Sha256`, and `Url`.
- **High Null Handling**: Gracefully cleans and imputes columns with >40% null values.
- **Built-in Fallback Benchmark**: Automatically synthesizes a realistic 125-alert cybersecurity scenario dataset covering Ransomware, Mimikatz, Cloud Identity Compromise, IT Scans, and WAF noise.
- **Insider Threat Focus**: Uses account, device, IP, behavioral, and alert information to identify suspicious activity associated with potential insider threats.

---

### 2. Six AI/ML Intelligence Components (`ml_engine.py`)

1. **Alert Classification Model**
   - Uses TF-IDF with Random Forest / Gradient Boosting.
   - Predicts threat categories and tactics.

2. **Alert Clustering Model**
   - Groups related alerts using shared entities such as:
     - `AccountUpn`
     - `DeviceId`
     - `IpAddress`
   - Also considers temporal relationships and ground-truth clusters.

3. **Behavioral Anomaly Detection**
   - Uses Isolation Forest to identify unusual user and device behavior.

4. **Threat Severity Prediction**
   - Estimates the probability that an alert represents a genuine security incident.

5. **Incident Correlation Model**
   - Uses NetworkX to construct relationships between:
     - Users
     - Devices
     - IP addresses
     - MITRE ATT&CK techniques
     - Security alerts

6. **Risk Priority Scoring**
   - Produces a risk score from **0–100**.
   - Combines:
     - Threat severity
     - Behavioral anomaly
     - Blast radius
     - Attack graph density

---

## 3. LangGraph Autonomous Investigation Loop (`agent.py`)

The system performs a multi-step investigation workflow:

1. **Scope & Entity Assessment**
   - Evaluates affected users, devices, privileges, and asset criticality.

2. **Threat Intelligence Correlation**
   - Correlates external IP addresses, URLs, and file hashes with threat intelligence sources.

3. **Cross-Device Lateral Spread Analysis**
   - Correlates endpoint activity to identify possible lateral movement.

4. **Behavioral Anomaly Analysis**
   - Compares observed activity against established behavioral patterns.

5. **Remediation Verdict**
   - Generates recommended actions such as:
     - `Escalate`
     - `Group`
     - `Suppress`
     - `Request Review`

6. **Dynamic Priority Re-Ranking**
   - Recalculates investigation priority based on newly discovered evidence.

---

## 4. Dark-Mode React Security Console

The frontend provides an analyst-oriented security dashboard containing:

- **Executive Metrics**
  - Total Alert Volume
  - Investigated Incidents
  - Threat Detection Rate
  - Workload Reduction
  - Risk Distribution

- **Risk Heat Map**
  - Visualizes threat severity against potential blast radius.

- **Analyst Priority Queue**
  - Searchable and filterable security alert queue.
  - Displays severity, risk score, affected entities, and recommended actions.

- **Incident Investigation Panel**
  - Interactive event timeline
  - NetworkX attack graph
  - Security telemetry breakdown
  - Autonomous investigation results
  - Evidence trace
  - Analyst feedback and actions

- **Alert Comparison**
  - Compares raw security alerts against AI-assisted investigation and prioritization.

---

# 🏗️ Project Architecture

```text
insider-threat-detector/
│
├── backend/
│   ├── app/
│   │   ├── db/
│   │   │   ├── database.py
│   │   │   └── models.py
│   │   │
│   │   ├── services/
│   │   │   ├── guide_loader.py
│   │   │   ├── ml_engine.py
│   │   │   └── agent.py
│   │   │
│   │   ├── config.py
│   │   └── main.py
│   │
│   ├── data/
│   │   └── GUIDE_Train.csv
│   │
│   ├── requirements.txt
│   ├── .env.example
│   └── .env
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── MetricsOverview.tsx
│   │   │   ├── RiskHeatmap.tsx
│   │   │   ├── PriorityQueue.tsx
│   │   │   ├── IncidentDetail.tsx
│   │   │   └── ComparisonView.tsx
│   │   │
│   │   ├── types/
│   │   │   └── index.ts
│   │   │
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   │
│   ├── package.json
│   └── vite.config.ts
│
└── README.md
