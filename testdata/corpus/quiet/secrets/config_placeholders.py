# Secret-named settings that are NOT secrets: runtime injection and short
# placeholders. Exercises the keyword-context heuristic (ADR 0005 / FP-006) —
# none of these should alarm.

API_KEY = os.environ["API_KEY"]      # injected at runtime, not a literal
DB_PASSWORD = ""                      # set by the orchestrator
SECRET_KEY = "changeme"               # placeholder, rotated in prod
access_token = None
auth_token = get_token_from_vault()
