import json
import uuid
from pathlib import Path

from datetime import datetime, timezone
from fastapi import FastAPI, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, func

from app.config import APP_NAME, APP_VERSION, MAX_UPLOAD_BYTES
from app.database import Base, engine, get_db
from app.models import (
    Baseline,
    AnalysisRecord,
    ReliabilityRecord,
    ThreatIntelligenceRecord,
    AttackChainRecord
)
from app.data_validation import parse_csv_bytes
from app.drift import analyze_feature
from app.schemas import (
    ReliabilityEvaluationRequest,
    ThreatIntelligenceRequest,
    AttackChainRequest
)
from app.threat_intelligence import analyze_threat_patterns
from app.reliability import evaluate_model
from app.attack_chain import detect_attack_chains

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=f"{APP_NAME} API",
    description="Cybersecurity-focused ML model feature drift monitoring. Drift is not proof of an attack.",
    version=APP_VERSION,
)

@app.get("/api/health")
def health():
    return {"status": "healthy", "service": APP_NAME, "version": APP_VERSION}

@app.get("/api/baselines")
def list_baselines(db: Session = Depends(get_db)):
    rows = db.scalars(select(Baseline).order_by(desc(Baseline.created_at))).all()
    return [{
        "baseline_id": row.id,
        "name": row.name,
        "feature_count": len(json.loads(row.feature_names)),
        "sample_count": row.sample_count,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    } for row in rows]

@app.post("/api/baselines", status_code=201)
async def create_baseline(
    name: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    clean_name = name.strip()
    if not clean_name or len(clean_name) > 100:
        raise HTTPException(400, "Baseline name must be between 1 and 100 characters.")
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Upload exceeds {MAX_UPLOAD_BYTES} bytes.")
    try:
        features = parse_csv_bytes(raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    baseline_id = uuid.uuid4().hex
    row = Baseline(
        id=baseline_id,
        name=clean_name,
        feature_names=json.dumps(list(features.keys())),
        feature_data=json.dumps(features),
        sample_count=len(next(iter(features.values()))),
    )
    db.add(row)
    db.commit()
    return {
        "baseline_id": baseline_id,
        "name": clean_name,
        "feature_count": len(features),
        "sample_count": row.sample_count,
        "status": "created",
    }

@app.post("/api/baselines/{baseline_id}/analyze")
async def analyze_baseline(
    baseline_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    baseline = db.get(Baseline, baseline_id)
    if baseline is None:
        raise HTTPException(404, "Baseline not found.")
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Upload exceeds {MAX_UPLOAD_BYTES} bytes.")
    try:
        current = parse_csv_bytes(raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    reference = json.loads(baseline.feature_data)
    expected, received = set(reference), set(current)
    if expected != received:
        raise HTTPException(422, {
            "message": "CSV feature columns must match the selected baseline.",
            "missing": sorted(expected - received),
            "unexpected": sorted(received - expected),
        })

    results = [analyze_feature(key, reference[key], current[key]) for key in reference]
    drifted = sum(item["drift_detected"] for item in results)
    status = "DRIFT_DETECTED" if drifted else "NO_SIGNIFICANT_DRIFT"
    analysis_id = uuid.uuid4().hex
    result = {
        "analysis_id": analysis_id,
        "baseline_id": baseline_id,
        "baseline_name": baseline.name,
        "overall_status": status,
        "total_features": len(results),
        "drifted_features": drifted,
        "results": results,
        "interpretation": (
            "Distribution changes were detected. Investigate the affected features; this is not proof of malicious activity or model degradation."
            if drifted else
            "No significant distribution change was detected by the configured checks. This does not guarantee model accuracy or security."
        ),
    }
    db.add(AnalysisRecord(
        id=analysis_id,
        baseline_id=baseline_id,
        overall_status=status,
        drifted_features=drifted,
        total_features=len(results),
        result_json=json.dumps(result),
    ))
    db.commit()
    return result

@app.get("/api/analyses")
def list_analyses(db: Session = Depends(get_db)):
    rows = db.scalars(select(AnalysisRecord).order_by(desc(AnalysisRecord.created_at)).limit(50)).all()
    return [{
        "analysis_id": row.id,
        "baseline_id": row.baseline_id,
        "overall_status": row.overall_status,
        "drifted_features": row.drifted_features,
        "total_features": row.total_features,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    } for row in rows]

@app.get("/")
def dashboard():
    return FileResponse(FRONTEND_DIR / "index.html")

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")



@app.post("/api/reliability/evaluate", status_code=201)
def evaluate_reliability(
    payload: ReliabilityEvaluationRequest,
    db: Session = Depends(get_db)
):
    metrics = evaluate_model(payload.y_true, payload.y_pred)

    evaluation_id = uuid.uuid4().hex

    record = ReliabilityRecord(
        id=evaluation_id,
        model_version=payload.model_version,
        sample_count=metrics["sample_count"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1_score=metrics["f1_score"],
        false_positive_rate=metrics["false_positive_rate"],
        accuracy=metrics["accuracy"],
        confusion_matrix=json.dumps(metrics["confusion_matrix"])
    )

    db.add(record)
    db.commit()

    return {
        "evaluation_id": evaluation_id,
        "model_version": payload.model_version,
        "status": "evaluation_completed",
        **metrics
    }


@app.get("/api/reliability/history")
def reliability_history(db: Session = Depends(get_db)):
    records = db.scalars(
        select(ReliabilityRecord)
        .order_by(desc(ReliabilityRecord.created_at))
        .limit(50)
    ).all()

    return [
        {
            "evaluation_id": record.id,
            "model_version": record.model_version,
            "sample_count": record.sample_count,
            "precision": record.precision,
            "recall": record.recall,
            "f1_score": record.f1_score,
            "false_positive_rate": record.false_positive_rate,
            "accuracy": record.accuracy,
            "confusion_matrix": json.loads(record.confusion_matrix),
            "created_at": (
                record.created_at.isoformat()
                if record.created_at else None
            )
        }
        for record in records
    ]


@app.post("/api/threat-intelligence/analyze", status_code=201)
def analyze_threat_intelligence(
    payload: ThreatIntelligenceRequest,
    db: Session = Depends(get_db)
):
    try:
        result = analyze_threat_patterns(payload.events)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    record_id = uuid.uuid4().hex

    record = ThreatIntelligenceRecord(
        id=record_id,
        total_events=result["total_events"],
        patterns_detected=result["patterns_detected"],
        result_json=json.dumps(result)
    )

    db.add(record)
    db.commit()

    return {
        "record_id": record_id,
        "status": "analysis_completed",
        **result
    }


@app.get("/api/threat-intelligence/history")
def threat_intelligence_history(db: Session = Depends(get_db)):
    records = db.scalars(
        select(ThreatIntelligenceRecord)
        .order_by(desc(ThreatIntelligenceRecord.created_at))
        .limit(50)
    ).all()

    return [
        {
            "record_id": record.id,
            "total_events": record.total_events,
            "patterns_detected": record.patterns_detected,
            "results": json.loads(record.result_json),
            "created_at": (
                record.created_at.isoformat()
                if record.created_at else None
            )
        }
        for record in records
    ]



@app.post("/api/attack-chains/analyze", status_code=201)
def analyze_attack_chains(
    payload: AttackChainRequest,
    db: Session = Depends(get_db)
):
    try:
        result = detect_attack_chains(payload.events)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc)
        ) from exc

    record_id = uuid.uuid4().hex

    record = AttackChainRecord(
        id=record_id,
        total_events=len(payload.events),
        chains_detected=result["chains_detected"],
        result_json=json.dumps(result)
    )

    db.add(record)
    db.commit()

    return {
        "record_id": record_id,
        "status": "analysis_completed",
        **result
    }


@app.get("/api/attack-chains/history")
def attack_chain_history(db: Session = Depends(get_db)):
    records = db.scalars(
        select(AttackChainRecord)
        .order_by(desc(AttackChainRecord.created_at))
        .limit(50)
    ).all()

    return [
        {
            "record_id": record.id,
            "total_events": record.total_events,
            "chains_detected": record.chains_detected,
            "results": json.loads(record.result_json),
            "created_at": (
                record.created_at.isoformat()
                if record.created_at else None
            )
        }
        for record in records
    ]


# =====================================
# M5 - UNIFIED SECURITY INTELLIGENCE
# M5.1 - SECURITY OVERVIEW
# =====================================

@app.get("/api/security/overview")
def security_overview(db: Session = Depends(get_db)):

    # Total record counts
    totals = {
        "baselines": db.scalar(
            select(func.count()).select_from(Baseline)
        ) or 0,

        "drift_analyses": db.scalar(
            select(func.count()).select_from(AnalysisRecord)
        ) or 0,

        "reliability_evaluations": db.scalar(
            select(func.count()).select_from(ReliabilityRecord)
        ) or 0,

        "threat_analyses": db.scalar(
            select(func.count()).select_from(ThreatIntelligenceRecord)
        ) or 0,

        "attack_chain_analyses": db.scalar(
            select(func.count()).select_from(AttackChainRecord)
        ) or 0,
    }

    # Latest records from each module
    latest_drift = db.scalar(
        select(AnalysisRecord)
        .order_by(desc(AnalysisRecord.created_at))
        .limit(1)
    )

    latest_reliability = db.scalar(
        select(ReliabilityRecord)
        .order_by(desc(ReliabilityRecord.created_at))
        .limit(1)
    )

    latest_threat = db.scalar(
        select(ThreatIntelligenceRecord)
        .order_by(desc(ThreatIntelligenceRecord.created_at))
        .limit(1)
    )

    latest_attack = db.scalar(
        select(AttackChainRecord)
        .order_by(desc(AttackChainRecord.created_at))
        .limit(1)
    )

    return {
        "status": "success",
        "totals": totals,

        "latest": {
            "drift": (
                {
                    "analysis_id": latest_drift.id,
                    "status": latest_drift.overall_status,
                    "drifted_features": latest_drift.drifted_features,
                    "total_features": latest_drift.total_features,
                    "created_at": (
                        latest_drift.created_at.isoformat()
                        if latest_drift.created_at else None
                    ),
                    "results": json.loads(latest_drift.result_json),
                }
                if latest_drift else None
            ),

            "reliability": (
                {
                    "model_version": latest_reliability.model_version,
                    "sample_count": latest_reliability.sample_count,
                    "precision": latest_reliability.precision,
                    "recall": latest_reliability.recall,
                    "f1_score": latest_reliability.f1_score,
                    "false_positive_rate": latest_reliability.false_positive_rate,
                    "accuracy": latest_reliability.accuracy,
                    "created_at": (
                        latest_reliability.created_at.isoformat()
                        if latest_reliability.created_at else None
                    ),
                }
                if latest_reliability else None
            ),

            "threat_intelligence": (
                {
                    "total_events": latest_threat.total_events,
                    "patterns_detected": latest_threat.patterns_detected,
                    "created_at": (
                        latest_threat.created_at.isoformat()
                        if latest_threat.created_at else None
                    ),
                    "results": json.loads(latest_threat.result_json),
                }
                if latest_threat else None
            ),

            "attack_chains": (
                {
                    "total_events": latest_attack.total_events,
                    "chains_detected": latest_attack.chains_detected,
                    "created_at": (
                        latest_attack.created_at.isoformat()
                        if latest_attack.created_at else None
                    ),
                    "results": json.loads(latest_attack.result_json),
                }
                if latest_attack else None
            ),
        },
    }

# =====================================
# M5.2 - SECURITY POSTURE SCORE
# =====================================

@app.get("/api/security/posture")
def security_posture(db: Session = Depends(get_db)):

    # Fetch latest records
    drift = db.scalar(
        select(AnalysisRecord)
        .order_by(desc(AnalysisRecord.created_at))
        .limit(1)
    )

    reliability = db.scalar(
        select(ReliabilityRecord)
        .order_by(desc(ReliabilityRecord.created_at))
        .limit(1)
    )

    threat = db.scalar(
        select(ThreatIntelligenceRecord)
        .order_by(desc(ThreatIntelligenceRecord.created_at))
        .limit(1)
    )

    attack = db.scalar(
        select(AttackChainRecord)
        .order_by(desc(AttackChainRecord.created_at))
        .limit(1)
    )

    components = {}
    weights = {
        "drift": 30,
        "reliability": 25,
        "threat_intelligence": 20,
        "attack_chains": 25,
    }

    # 1. Drift health
    if drift and drift.total_features > 0:
        drift_score = (
            1 - drift.drifted_features / drift.total_features
        ) * 100

        components["drift"] = {
            "score": round(drift_score, 2),
            "weight": weights["drift"],
            "details": (
                f"{drift.drifted_features} of "
                f"{drift.total_features} features showed drift."
            ),
        }

    # 2. Model reliability
    if reliability:
        reliability_score = (
            reliability.precision
            + reliability.recall
            + reliability.f1_score
            + (1 - reliability.false_positive_rate)
        ) / 4 * 100

        components["reliability"] = {
            "score": round(reliability_score, 2),
            "weight": weights["reliability"],
            "details": (
                f"Model {reliability.model_version}: "
                f"{reliability.sample_count} samples evaluated."
            ),
        }

    # 3. Threat intelligence
    if threat:
        threat_data = json.loads(threat.result_json)
        patterns = threat_data.get("patterns", [])

        severity_penalties = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3,
        }

        threat_penalty = sum(
            severity_penalties.get(
                str(pattern.get("severity", "")).upper(), 0
            )
            for pattern in patterns
        )

        threat_score = max(0, 100 - threat_penalty)

        components["threat_intelligence"] = {
            "score": round(threat_score, 2),
            "weight": weights["threat_intelligence"],
            "details": (
                f"{len(patterns)} threat patterns detected."
            ),
        }

    # 4. Attack-chain activity
    if attack:
        attack_data = json.loads(attack.result_json)
        chains = attack_data.get("attack_chains", [])

        critical_events = sum(
            1
            for chain in chains
            for event in chain.get("timeline", [])
            if str(event.get("severity", "")).upper() == "CRITICAL"
        )

        attack_penalty = (
            len(chains) * 30
            + critical_events * 10
        )

        attack_score = max(0, 100 - attack_penalty)

        components["attack_chains"] = {
            "score": round(attack_score, 2),
            "weight": weights["attack_chains"],
            "details": (
                f"{len(chains)} attack chains and "
                f"{critical_events} critical events detected."
            ),
        }

    # Calculate weighted score using available components only
    available_weight = sum(
        item["weight"] for item in components.values()
    )

    if available_weight == 0:
        return {
            "status": "insufficient_data",
            "message": "Run at least one security analysis first.",
            "overall_score": None,
            "components": components,
        }

    overall_score = sum(
        item["score"] * item["weight"]
        for item in components.values()
    ) / available_weight

    overall_score = round(overall_score, 2)

    if overall_score >= 85:
        rating = "HEALTHY"
    elif overall_score >= 70:
        rating = "GUARDED"
    elif overall_score >= 50:
        rating = "ELEVATED"
    else:
        rating = "CRITICAL"

    return {
        "status": "success",
        "overall_score": overall_score,
        "rating": rating,
        "available_weight": available_weight,
        "total_weight": 100,
        "components": components,
        "methodology": (
            "Heuristic project-defined score. Higher scores indicate "
            "healthier observed conditions. Missing modules are excluded "
            "and remaining weights are normalized. This is not a "
            "certified security rating."
        ),
    }

# =====================================
# M5.3 - UNIFIED THREAT SEVERITY ANALYTICS
# =====================================

@app.get("/api/security/analytics")
def security_analytics(db: Session = Depends(get_db)):

    threat = db.scalar(
        select(ThreatIntelligenceRecord)
        .order_by(desc(ThreatIntelligenceRecord.created_at))
        .limit(1)
    )

    attack = db.scalar(
        select(AttackChainRecord)
        .order_by(desc(AttackChainRecord.created_at))
        .limit(1)
    )

    threat_severity = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    attack_severity = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    threat_patterns = 0
    attack_chains = 0

    if threat:
        data = json.loads(threat.result_json)

        threat_patterns = data.get("patterns_detected", 0)

        for severity, count in data.get(
            "severity_distribution", {}
        ).items():
            key = str(severity).upper()
            if key in threat_severity:
                threat_severity[key] += count

    if attack:
        data = json.loads(attack.result_json)

        chains = data.get("attack_chains", [])
        attack_chains = len(chains)

        for chain in chains:
            for event in chain.get("timeline", []):
                severity = str(
                    event.get("severity", "")
                ).upper()

                if severity in attack_severity:
                    attack_severity[severity] += 1

    combined = {
        severity: (
            threat_severity[severity]
            + attack_severity[severity]
        )
        for severity in threat_severity
    }

    total_events = sum(combined.values())

    return {
        "status": "success",
        "threat_patterns_detected": threat_patterns,
        "attack_chains_detected": attack_chains,
        "severity_distribution": combined,
        "sources": {
            "threat_intelligence": threat_severity,
            "attack_chains": attack_severity,
        },
        "high_priority_activity": {
            "critical": combined["CRITICAL"],
            "high": combined["HIGH"],
            "total": (
                combined["CRITICAL"] + combined["HIGH"]
            ),
        },
        "total_severity_observations": total_events,
        "note": (
            "Counts represent severity observations from the latest "
            "threat analysis and attack-chain analysis. They are not "
            "deduplicated unique security events."
        ),
    }

# =====================================
# M5.4 - UNIFIED SECURITY TIMELINE
# =====================================

@app.get("/api/security/timeline")
def security_timeline(db: Session = Depends(get_db)):

    threat = db.scalar(
        select(ThreatIntelligenceRecord)
        .order_by(desc(ThreatIntelligenceRecord.created_at))
        .limit(1)
    )

    attack = db.scalar(
        select(AttackChainRecord)
        .order_by(desc(AttackChainRecord.created_at))
        .limit(1)
    )

    timeline = []

    # Threat intelligence findings
    if threat:
        data = json.loads(threat.result_json)

        for pattern in data.get("patterns", []):
            timestamp = (
                pattern.get("end_time")
                or pattern.get("start_time")
                or threat.created_at.isoformat()
            )

            timeline.append({
                "category": "THREAT_INTELLIGENCE",
                "event": pattern.get("pattern", "Unknown pattern"),
                "severity": str(
                    pattern.get("severity", "UNKNOWN")
                ).upper(),
                "source_ip": pattern.get("source_ip"),
                "timestamp": timestamp,
                "description": pattern.get("evidence", ""),
                "confidence_score": pattern.get("confidence_score"),
            })

    # Attack-chain events
    if attack:
        data = json.loads(attack.result_json)

        for chain in data.get("attack_chains", []):
            for event in chain.get("timeline", []):
                timeline.append({
                    "category": "ATTACK_CHAIN",
                    "event": event.get("event_type", "Unknown event"),
                    "severity": str(
                        event.get("severity", "UNKNOWN")
                    ).upper(),
                    "source_ip": chain.get("source_ip"),
                    "stage": event.get("stage"),
                    "timestamp": event.get("timestamp"),
                    "description": (
                        f"Attack stage: {event.get('stage', 'Unknown')}"
                    ),
                    "confidence_score": None,
                })

    # Sort newest first
    def sort_timestamp(item):
        value = item.get("timestamp")

        if not value:
            return float("-inf")

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.timestamp()

        except (ValueError, TypeError):
            return float("-inf")

    timeline.sort(key=sort_timestamp, reverse=True)

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for item in timeline:
        severity = item["severity"]

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "status": "success",
        "total_events": len(timeline),
        "severity_summary": severity_counts,
        "timeline": timeline,
        "note": (
            "Timeline combines findings from the latest threat "
            "intelligence and attack-chain analyses. Related findings "
            "may represent the same underlying activity."
        ),
    }

    # =====================================
# M5.5 - PRIORITIZED SECURITY ALERTS
# =====================================

@app.get("/api/security/alerts")
def security_alerts(db: Session = Depends(get_db)):

    timeline_response = security_timeline(db)
    timeline = timeline_response["timeline"]

    alerts = []

    response_actions = {
        "CRITICAL": [
            "Immediately investigate the affected asset.",
            "Review authentication and endpoint security logs.",
            "Escalate if malicious activity is confirmed."
        ],
        "HIGH": [
            "Review related security events.",
            "Investigate the source and affected accounts.",
            "Correlate with other available security records."
        ]
    }

    for index, event in enumerate(timeline):
        severity = event.get("severity", "UNKNOWN")

        if severity not in ("CRITICAL", "HIGH"):
            continue

        alerts.append({
            "alert_id": f"DR-{index + 1:04d}",
            "priority": severity,
            "category": event.get("category"),
            "event": event.get("event"),
            "source_ip": event.get("source_ip"),
            "timestamp": event.get("timestamp"),
            "description": event.get("description"),
            "recommended_actions": response_actions[severity],
            "status": "OPEN"
        })

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1
    }

    alerts.sort(
        key=lambda item: (
            priority_order[item["priority"]],
            item.get("timestamp") or ""
        ),
        reverse=False
    )

    return {
        "status": "success",
        "total_alerts": len(alerts),
        "critical_alerts": sum(
            a["priority"] == "CRITICAL" for a in alerts
        ),
        "high_alerts": sum(
            a["priority"] == "HIGH" for a in alerts
        ),
        "alerts": alerts,
        "note": (
            "Alerts are generated from observed findings. "
            "They require analyst validation and do not establish "
            "that an incident has been confirmed."
        )
    }