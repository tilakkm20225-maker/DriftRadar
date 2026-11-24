# DriftRadar

### Cybersecurity Model Reliability & Threat Adaptation Intelligence Platform

**Built by Tilak Moger**

B.Tech – Computer Science and Engineering (Cyber Security)  
Dayananda Sagar University, Bengaluru, Karnataka

---

## About the Project

DriftRadar is a cybersecurity-focused engineering project that brings statistical drift detection, machine-learning model reliability evaluation, threat intelligence analysis, and attack-chain correlation into one unified dashboard.

The idea behind this project is simple: a detection model can become less dependable when the data it sees changes, and security events become more useful when they are examined together rather than as isolated records.

DriftRadar helps explore these problems through statistical drift checks, model-performance evaluation, threat-pattern analysis, and multi-stage attack-chain correlation. It then brings the latest results together in a single dashboard so that users can review what has changed and decide what deserves further investigation.

This project is an engineering prototype intended for learning, demonstration, and further development. It is not a replacement for a production SIEM, a calibrated risk-scoring product, or a human security analyst.

---

## Project Objectives

- Identify changes in datasets through statistical drift detection.
- Evaluate the reliability of machine-learning detection models.
- Analyse security events to identify suspicious patterns.
- Correlate related events into possible multi-stage attack chains.
- Combine security findings into a unified dashboard.
- Provide useful information to support security investigation and decision-making.

---

## Key Features

### 1. Statistical Drift Detection – M1

DriftRadar compares reference datasets with newly submitted datasets to identify changes in feature distributions.

**Features:**
- Upload and register baseline CSV datasets.
- Analyse current datasets against registered baselines.
- Calculate Population Stability Index (PSI).
- Perform Kolmogorov–Smirnov (KS) tests.
- Identify features showing distribution changes.
- Store analysis results for later review.

### 2. Model Reliability Intelligence – M2

This module evaluates the performance of a detection model using standard classification metrics.

**Metrics included:**
- Precision
- Recall
- F1-score
- Accuracy
- False Positive Rate (FPR)
- Confusion Matrix

The results help users understand how reliably a model classifies security-related events.

### 3. Threat Adaptation Intelligence – M3

This module analyses security event data to identify suspicious patterns and changes in activity.

**Detection patterns include:**
- Repeated authentication failures.
- Authentication failure bursts.
- Multi-port scanning activity.
- High-severity security activity.
- Increasing authentication failures over time.

The module also calculates heuristic confidence scores to help prioritise findings for further investigation.

### 4. Intelligent Threat Correlation – M4

Individual security events may not reveal the full picture of an attack. This module correlates related events into possible attack chains.

**Attack stages include:**
- Reconnaissance
- Authentication Failure
- Successful Authentication
- Post-Authentication Activity

The correlation module helps connect related events and presents them as a possible sequence of attacker activity.

### 5. Unified Security Intelligence Dashboard – M5

The final milestone combines the results of the earlier modules into one dashboard.

**Dashboard components:**

- **Security Overview:** Displays overall project activity and the latest analysis results.
- **Security Posture Score:** Provides a project-defined heuristic score based on available security components.
- **Threat Severity Analytics:** Summarises the severity of detected findings.
- **Unified Security Timeline:** Displays security findings in chronological order.
- **Prioritized Security Alerts:** Highlights critical and high-severity findings with recommended actions.

The dashboard makes it easier to review multiple security analysis results without switching between separate modules.

---

## Technology Stack

| Area | Technologies |
|---|---|
| Programming Language | Python |
| Backend Framework | FastAPI |
| API Server | Uvicorn |
| Database | SQLite |
| ORM | SQLAlchemy |
| Data Validation | Pydantic |
| Data Analysis | Pandas |
| Statistical Analysis | PSI and KS Test |
| Frontend | HTML, CSS, JavaScript |
| API Testing | Swagger UI |
| Automated Testing | Pytest |
| Development Environment | Visual Studio Code |

---

## System Architecture

DriftRadar follows a modular architecture in which the frontend communicates with a FastAPI backend through REST API endpoints.

```text
                  USER
                    |
                    v
          DRIFTRADAR DASHBOARD
             HTML / CSS / JS
                    |
                    v
             FASTAPI BACKEND
                    |
       +------------+-------------+
       |            |             |
       v            v             v
   DRIFT          MODEL         THREAT
  DETECTION     RELIABILITY   INTELLIGENCE
       |            |             |
       +------------+-------------+
                    |
                    v
            ATTACK CORRELATION
                    |
                    v
          UNIFIED SECURITY LAYER
                    |
       +------------+-------------+
       |            |             |
       v            v             v
    OVERVIEW      TIMELINE      ALERTS
       |            |             |
       +------------+-------------+
                    |
                    v
              SQLITE DATABASE
```

---

## Project Milestones

| Milestone | Module | Status |
|---|---|---|
| M1 | Statistical Drift Detection | Completed |
| M2 | Model Reliability Intelligence | Completed |
| M3 | Threat Adaptation Intelligence | Completed |
| M4 | Intelligent Threat Correlation | Completed |
| M5 | Unified Security Intelligence Dashboard | Completed |

---

## API Endpoints

The following endpoints are implemented in the project.

| Module | Method | Endpoint |
|---|---|---|
| Health | GET | `/api/health` |
| Baselines | GET | `/api/baselines` |
| Baselines | POST | `/api/baselines` |
| Drift Analysis | POST | `/api/baselines/{baseline_id}/analyze` |
| Drift History | GET | `/api/analyses` |
| Reliability Evaluation | POST | `/api/reliability/evaluate` |
| Reliability History | GET | `/api/reliability/history` |
| Threat Analysis | POST | `/api/threat-intelligence/analyze` |
| Threat History | GET | `/api/threat-intelligence/history` |
| Attack Chain Analysis | POST | `/api/attack-chains/analyze` |
| Attack Chain History | GET | `/api/attack-chains/history` |
| Security Overview | GET | `/api/security/overview` |
| Security Posture | GET | `/api/security/posture` |
| Security Analytics | GET | `/api/security/analytics` |
| Security Timeline | GET | `/api/security/timeline` |
| Security Alerts | GET | `/api/security/alerts` |

Interactive API documentation is available through FastAPI Swagger UI.

---

## Installation and Setup

Follow these steps to run DriftRadar on a Windows system.

### 1. Clone the Repository

```powershell
git clone YOUR_GITHUB_REPOSITORY_URL
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Open the Project Folder

```powershell
cd DriftRadar
```

### 3. Create a Virtual Environment

```powershell
python -m venv .venv
```

### 4. Activate the Virtual Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 5. Install Dependencies

If the repository contains a `requirements.txt` file:

```powershell
pip install -r requirements.txt
```

### 6. Start the Backend Server

```powershell
python -m uvicorn app.main:app --reload
```

### 7. Open the Dashboard

Visit:

```text
http://127.0.0.1:8000
```

### 8. Open API Documentation

Visit:

```text
http://127.0.0.1:8000/docs
```

---

## Testing

DriftRadar includes automated tests to check the implemented modules and API functionality.

Run the test suite using:

```powershell
pytest -q
```

**Recorded test result:**

```text
44 passed, 1 warning
```

The warning was related to a Starlette testing-client deprecation notice and did not cause test failures.

---

## Project Structure

The project is organised into separate backend, frontend, and testing components.

```text
DriftRadar/
│
├── app/
│   ├── main.py
│   ├── threat_intelligence.py
│   ├── event_correlation.py
│   └── attack_chain.py
│
├── frontend/
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   └── app_backup.js
│
├── tests/
│
├── data/
│   ├── baseline_network_traffic.csv
│   ├── current_stable_traffic.csv
│   └── current_shifted_traffic.csv
│
├── README.md
├── requirements.txt
└── .gitignore
```

*Note: The tree is a simplified overview. Keep your actual project files and folders as they are.*

---

## Limitations and Responsible Use

DriftRadar is a prototype, so its results should be interpreted carefully.

- Statistical drift does not automatically indicate an attack or prove that a model has degraded.
- Reliability metrics depend on the availability and quality of labelled evaluation data.
- Threat patterns are investigation indicators, not confirmation of malicious activity.
- Confidence scores are heuristic values and are not calibrated probabilities.
- The security posture score uses project-defined weights and rules. It is not a certified security rating.
- Severity analytics may contain overlapping observations and should not be interpreted as unique incident counts.
- Prioritized alerts are generated from findings and do not independently confirm security incidents.

The platform is designed to support learning, experimentation, and security analysis rather than replace professional security monitoring systems.

---

## Future Improvements

Some possible improvements for future development include:

- Integration with real-time SIEM and EDR platforms.
- Machine-learning-based anomaly detection.
- Advanced threat intelligence feed integration.
- Improved event correlation and attack-chain detection.
- Persistent alert acknowledgement and investigation tracking.
- User authentication and role-based access control.
- More advanced visual analytics and reporting.
- Evaluation using larger and more realistic cybersecurity datasets.

---

## Learning Outcomes

Working on DriftRadar provided practical experience with:

- Building REST APIs using FastAPI.
- Working with Python and SQLAlchemy.
- Performing statistical analysis on datasets.
- Evaluating machine-learning classification performance.
- Analysing cybersecurity events and suspicious patterns.
- Correlating events into possible attack sequences.
- Integrating backend APIs with a frontend dashboard.
- Writing and executing automated tests.

---

## Author

**Tilak Moger**

B.Tech – Computer Science and Engineering (Cyber Security)  
Dayananda Sagar University  
Bengaluru, Karnataka, India

**Project:** DriftRadar – Cybersecurity Model Reliability & Threat Adaptation Intelligence Platform

---

*Built as a hands-on cybersecurity engineering project focused on understanding model reliability, detecting changing patterns, and connecting security events into meaningful intelligence.*