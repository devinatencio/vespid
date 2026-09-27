import getpass
import mysql.connector, json
import datetime
import os
from urllib import request as urllib_request


def _get_db_password() -> str:
    env_password = os.environ.get("VESPID_DB_PASSWORD")
    if env_password:
        return env_password
    return getpass.getpass("MySQL password for user 'vespid': ")


db = mysql.connector.connect(
    host="localhost",
    user="vespid",
    password=_get_db_password(),
    database="vespid",
)
cur = db.cursor()

cur.execute("SELECT id, name, check_type FROM synthetic_checks")
checks = {r[0]: {"name": r[1], "check_type": r[2]} for r in cur.fetchall()}

cur.execute("SELECT j.check_id, j.location, j.duration_ms, j.status, j.result_json, j.completed_at FROM synthetic_check_jobs j WHERE j.status IN ('completed', 'failed') ORDER BY j.completed_at ASC")
jobs = cur.fetchall()
db.close()

pushed = 0
for job in jobs:
    check_id, location, dur_ms, status, result_json, completed_at = job
    check = checks.get(check_id)
    if not check:
        continue
    details = {}
    if result_json:
        try:
            details = json.loads(result_json)
        except Exception:
            pass

    success = 1 if status == "completed" else 0

    if completed_at:
        if isinstance(completed_at, str):
            dt = datetime.datetime.fromisoformat(completed_at)
        else:
            dt = completed_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        ts_ms = int(dt.timestamp() * 1000)
    else:
        ts_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)

    escaped_name = check["name"].replace('"', '\\"')
    labels = 'check_id="{}",check_name="{}",check_type="{}",location="{}"'.format(
        check_id, escaped_name, check["check_type"], location)

    body = "vespid_synthetic_check_duration_ms{{{}}} {} {}\n".format(labels, dur_ms, ts_ms)
    body += "vespid_synthetic_check_success{{{}}} {} {}\n".format(labels, success, ts_ms)

    ct = check["check_type"]
    if ct == "icmp" and details.get("rtt_avg_ms") is not None:
        body += "vespid_synthetic_check_rtt_ms{{{}}} {} {}\n".format(labels, details["rtt_avg_ms"], ts_ms)

    req = urllib_request.Request("http://localhost:8428/api/v1/import/prometheus",
                                 data=body.encode(), method="POST",
                                 headers={"Content-Type": "text/plain"})
    urllib_request.urlopen(req, timeout=10)
    pushed += 1

print("Pushed {} job results to VictoriaMetrics".format(pushed))
