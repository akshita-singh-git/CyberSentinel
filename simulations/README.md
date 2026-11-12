# Safe simulations
Use the dashboard buttons or authenticated API endpoints:
- `POST /api/v1/simulations/brute-force`
- `POST /api/v1/simulations/suspicious-process`

These endpoints create synthetic rows in the local database. They do not send traffic, execute commands, scan networks, or touch external hosts.
