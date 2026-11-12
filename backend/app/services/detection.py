from sklearn.ensemble import IsolationForest
import numpy as np

RULES = [
    {"id":"CS-AUTH-001","name":"Repeated authentication failures","technique":"T1110","tactic":"Credential Access","severity":"high"},
    {"id":"CS-PROC-002","name":"Suspicious PowerShell execution","technique":"T1059.001","tactic":"Execution","severity":"high"},
    {"id":"CS-PRIV-003","name":"Unusual privileged activity","technique":"T1078","tactic":"Initial Access","severity":"medium"},
]

# Synthetic baseline only. This is a demonstration model, not a production-trained detector.
_rng = np.random.default_rng(42)
_baseline = np.column_stack([
    _rng.poisson(0.3, 600),
    _rng.binomial(1, 0.03, 600),
    _rng.binomial(1, 0.04, 600),
    _rng.poisson(1.0, 600),
])
_model = IsolationForest(n_estimators=120, contamination=0.04, random_state=42).fit(_baseline)

def score_event(event):
    vector = np.array([[event.failed_count, event.unusual_hour, event.privileged,
                        1 if event.process_name.lower() in ("powershell.exe","pwsh.exe") else 0]])
    raw = float(_model.decision_function(vector)[0])
    return round(max(0.0, min(1.0, (0.15 - raw) / 0.5)), 3)

def detect(event):
    matches = []
    msg = (event.message + " " + event.process_name).lower()
    if event.failed_count >= 5 or ("failed login" in msg and event.failed_count >= 3):
        matches.append((RULES[0], "Multiple failed authentication attempts were observed for this account/source."))
    if "powershell" in msg or event.process_name.lower() in ("powershell.exe", "pwsh.exe"):
        if any(x in msg for x in ("-enc", "encodedcommand", "downloadstring", "invoke-expression", "iex ")):
            matches.append((RULES[1], "PowerShell command contains a pattern commonly associated with obfuscated or download-based execution."))
    if event.privileged and event.unusual_hour:
        matches.append((RULES[2], "Privileged activity was recorded during an unusual-hour indicator window."))
    return matches
