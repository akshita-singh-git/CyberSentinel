from types import SimpleNamespace
from app.services.detection import detect, score_event

def test_brute_force_rule():
    event=SimpleNamespace(failed_count=7,message="failed login",process_name="",privileged=0,unusual_hour=0)
    assert any(rule["id"]=="CS-AUTH-001" for rule,_ in detect(event))

def test_anomaly_score_is_bounded():
    event=SimpleNamespace(failed_count=15,unusual_hour=1,privileged=1,process_name="powershell.exe")
    assert 0 <= score_event(event) <= 1
