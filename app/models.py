from datetime import datetime, timezone
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base

class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    feature_names: Mapped[str] = mapped_column(Text, nullable=False)
    feature_data: Mapped[str] = mapped_column(Text, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

class AnalysisRecord(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    baseline_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    overall_status: Mapped[str] = mapped_column(String(40), nullable=False)
    drifted_features: Mapped[int] = mapped_column(Integer, nullable=False)
    total_features: Mapped[int] = mapped_column(Integer, nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )



class ReliabilityRecord(Base):
    __tablename__ = "reliability_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    model_version: Mapped[str] = mapped_column(String(100), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    precision: Mapped[float] = mapped_column(nullable=False)
    recall: Mapped[float] = mapped_column(nullable=False)
    f1_score: Mapped[float] = mapped_column(nullable=False)
    false_positive_rate: Mapped[float] = mapped_column(nullable=False)
    accuracy: Mapped[float] = mapped_column(nullable=False)
    confusion_matrix: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )



class ThreatIntelligenceRecord(Base):
    __tablename__ = "threat_intelligence_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    total_events: Mapped[int] = mapped_column(Integer, nullable=False)
    patterns_detected: Mapped[int] = mapped_column(Integer, nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class AttackChainRecord(Base):
    __tablename__ = "attack_chain_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    total_events: Mapped[int] = mapped_column(Integer, nullable=False)
    chains_detected: Mapped[int] = mapped_column(Integer, nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
