import io
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_baseline_and_analysis():
    baseline_csv = "packet_count,flow_duration_ms\n" + "\n".join(f"{i},{i+100}" for i in range(20, 120))
    create = client.post("/api/baselines", data={"name":"test baseline"},
                         files={"file":("baseline.csv", baseline_csv, "text/csv")})
    assert create.status_code == 201, create.text
    baseline_id = create.json()["baseline_id"]
    current_csv = "packet_count,flow_duration_ms\n" + "\n".join(f"{i},{i+100}" for i in range(200, 300))
    result = client.post(f"/api/baselines/{baseline_id}/analyze",
                         files={"file":("current.csv", current_csv, "text/csv")})
    assert result.status_code == 200, result.text
    assert result.json()["drifted_features"] >= 1

def test_missing_baseline():
    csv = "feature\n" + "\n".join(str(i) for i in range(20))
    response = client.post("/api/baselines/not-a-real-id/analyze",
                           files={"file":("data.csv", csv, "text/csv")})
    assert response.status_code == 404
