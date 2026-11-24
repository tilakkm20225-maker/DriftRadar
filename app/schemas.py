from pydantic import BaseModel, Field

class BaselineResponse(BaseModel):
    baseline_id: str
    name: str
    feature_count: int
    sample_count: int
    status: str

class FeatureResult(BaseModel):
    feature: str
    psi: float
    ks_statistic: float
    ks_p_value: float
    drift_detected: bool
    reference_samples: int
    current_samples: int

class AnalysisResponse(BaseModel):
    analysis_id: str
    baseline_id: str
    baseline_name: str
    overall_status: str
    total_features: int
    drifted_features: int
    results: list[FeatureResult]
    interpretation: str



from pydantic import BaseModel, Field, ConfigDict, model_validator


class ReliabilityEvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_version: str = Field(min_length=1, max_length=100)
    y_true: list[int] = Field(min_length=20)
    y_pred: list[int] = Field(min_length=20)

    @model_validator(mode="after")
    def validate_evaluation(self):
        if len(self.y_true) != len(self.y_pred):
            raise ValueError("Actual and predicted labels must have equal lengths.")

        if any(value not in (0, 1) for value in self.y_true + self.y_pred):
            raise ValueError("Labels must contain only 0 or 1.")

        return self



class ThreatIntelligenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[dict] = Field(min_length=1)


class AttackChainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[dict] = Field(min_length=1)

