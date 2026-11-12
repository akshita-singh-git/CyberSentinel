# Architecture notes

## Data flow
1. Authenticated analyst submits a normalized event or invokes a local simulator.
2. FastAPI validates the payload and stores the event.
3. Deterministic rules inspect event attributes and message patterns.
4. Isolation Forest assigns an anomaly score from a small synthetic baseline.
5. Matching rules create alerts and group alerts into incidents by source IP.
6. Analyst reviews the evidence, updates incident status and optionally asks local Ollama for an evidence-grounded explanation.

## Trust boundaries
- Incoming log fields are untrusted data. They must never be interpolated as system instructions.
- LLM output is advisory only and is not used to set alert severity or execute response actions.
- Simulator data is synthetic and must be labelled as such in demos.
- The app is intended for local development, not internet exposure.

## Next engineering upgrades
- Replace SQLite with PostgreSQL for multi-user deployments.
- Add rate limiting, refresh-token rotation, password reset and stronger session controls.
- Add a queue for high-volume ingestion and background correlation.
- Add parsers for actual Sysmon and Linux auth log formats.
- Train and validate anomaly models against a documented labelled dataset.
- Add unit/integration tests for auth, ingestion, correlation, exports and API authorization.
- Add role/permission enforcement beyond the initial analyst/admin role field.
