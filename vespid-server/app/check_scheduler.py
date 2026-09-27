"""Synthetic Check Scheduler.

Runs as a background thread (one per gunicorn worker process) to
assign due synthetic checks to eligible workers. Handles:

- Job creation for due checks (one job per check × location)
- Worker matching by capabilities and labels
- Job timeout and reassignment
- Worker status updating (online -> offline on missed heartbeats)
- Completed job purge (30-day retention)
"""

import json
import logging
import random
import threading
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)


class CheckScheduler:
    """Periodic scheduler for synthetic monitoring checks."""

    def __init__(self, app):
        self.app = app
        self.interval = int(app.config.get("CHECK_SCHEDULER_INTERVAL_SECONDS", 10))
        self._timer: threading.Timer | None = None
        self._running = False

    def start(self):
        """Start the scheduler loop."""
        if self._running:
            return
        self._running = True

        self._schedule_next()
        logger.info(f"Check scheduler started (interval={self.interval}s)")

    def stop(self):
        """Stop the scheduler loop."""
        self._running = False
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _schedule_next(self):
        if not self._running:
            return
        self._timer = threading.Timer(self.interval, self._tick)
        self._timer.daemon = True
        self._timer.start()

    def _tick(self):
        try:
            self._run_once()
        except Exception:
            logger.exception("Check scheduler error")
        finally:
            self._schedule_next()

    def _run_once(self):
        from app.models import get_db

        db_path = self.app.config["DATABASE_PATH"]
        db = get_db(db_path)
        now = datetime.now(UTC)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            # 1. Update worker status — heartbeat overdue > 90s = offline
            cutoff = (now - timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
            db.execute(
                "UPDATE synthetic_workers SET status='offline' "
                "WHERE status != 'offline' AND last_heartbeat_at < ?",
                (cutoff,),
            )

            # 2. Handle timed-out jobs > 2x timeout
            db.execute(
                "UPDATE synthetic_check_jobs SET status='pending', assigned_to=NULL, "
                "assigned_at=NULL WHERE status IN ('assigned','running') "
                "AND assigned_at < ?",
                ((now - timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),),
            )
            db.commit()

            # 3. Find due checks
            checks = db.execute(
                "SELECT * FROM synthetic_checks "
                "WHERE status='active' AND (next_run_at IS NULL OR next_run_at <= ?)",
                (now_str,),
            ).fetchall()

            for check in checks:
                try:
                    locations = json.loads(check["locations"])
                except (json.JSONDecodeError, TypeError):
                    locations = []

                if not locations:
                    # No locations specified — still run, pick any worker
                    self._assign_job(db, check, "", now_str)
                else:
                    for location in locations:
                        self._assign_job(db, check, location, now_str)

                # Schedule next run with jitter
                interval = check["interval_secs"]
                jitter = random.randint(-interval // 8, interval // 8)
                next_run = now + timedelta(seconds=interval + jitter)
                db.execute(
                    "UPDATE synthetic_checks SET next_run_at=? WHERE id=?",
                    (next_run.strftime("%Y-%m-%dT%H:%M:%SZ"), check["id"]),
                )

            db.commit()

            # 4. Reaper: purge completed jobs older than 30 days
            thirty_days_ago = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
            db.execute(
                "DELETE FROM synthetic_check_jobs "
                "WHERE status IN ('completed','failed','timed_out') "
                "AND completed_at < ?",
                (thirty_days_ago,),
            )
            db.commit()

            # 5. Evaluate alert rules
            self._evaluate_alerts(db, now, now_str)

        finally:
            db.close()

    def _assign_job(self, db, check, location: str, now_str: str):
        """Assign a job to an eligible worker for a given check + location."""
        try:
            capabilities = json.loads(check["check_config"]).get(
                "_capabilities", [check["check_type"]]
            )
        except (json.JSONDecodeError, TypeError):
            capabilities = [check["check_type"]]

        # Find eligible workers
        workers = db.execute(
            "SELECT id FROM synthetic_workers "
            "WHERE status='online' AND running_jobs < max_concurrent",
        ).fetchall()

        eligible = []
        for w in workers:
            cap_row = db.execute(
                "SELECT capabilities, labels FROM synthetic_workers WHERE id=?", (w["id"],)
            ).fetchone()
            if cap_row is None:
                continue
            try:
                w_caps = json.loads(cap_row["capabilities"])
                w_labels = json.loads(cap_row["labels"])
            except (json.JSONDecodeError, TypeError):
                w_caps = []
                w_labels = {}

            # Check capabilities match
            if not any(c in w_caps for c in capabilities):
                continue

            # Check location match
            if location:
                loc = w_labels.get("location", "")
                if loc != location:
                    continue

            eligible.append(w["id"])

        if not eligible:
            # Inserts as pending, will be picked up when a worker appears
            db.execute(
                "INSERT INTO synthetic_check_jobs (check_id, location, scheduled_at, status) "
                "VALUES (?, ?, ?, 'pending')",
                (check["id"], location, now_str),
            )
            return

        # Pick least-loaded worker
        worker_id = eligible[0]
        min_jobs = None
        for wid in eligible:
            w = db.execute(
                "SELECT running_jobs FROM synthetic_workers WHERE id=?", (wid,)
            ).fetchone()
            if w is None:
                continue
            rj = w["running_jobs"]
            if min_jobs is None or rj < min_jobs:
                min_jobs = rj
                worker_id = wid

        db.execute(
            "INSERT INTO synthetic_check_jobs (check_id, location, scheduled_at, "
            "status, assigned_to, assigned_at) VALUES (?, ?, ?, 'assigned', ?, ?)",
            (check["id"], location, now_str, worker_id, now_str),
        )

        db.execute(
            "UPDATE synthetic_workers SET running_jobs = running_jobs + 1 WHERE id=?",
            (worker_id,),
        )

        # Publish SSE notification
        sse = getattr(self.app, "check_worker_sse_manager", None)
        if sse:
            try:
                sse.notify(worker_id)
            except Exception:
                logger.debug("Failed to notify worker via SSE", exc_info=True)

    def _evaluate_alerts(self, db, now, now_str: str):
        """Evaluate synthetic alert rules and fire/resolve alerts."""
        rules = db.execute("SELECT * FROM synthetic_alert_rules WHERE enabled = 1").fetchall()

        for rule in rules:
            try:
                channels = json.loads(rule["notification_channels"])
            except (json.JSONDecodeError, TypeError):
                channels = []

            if not channels:
                continue

            condition_type = (
                rule["condition_type"] if "condition_type" in rule.keys() else "failure"
            )

            if condition_type == "metric":
                self._evaluate_metric_alert(db, rule, channels, now_str)
            elif condition_type == "dns_answer_change":
                self._evaluate_dns_change_alert(db, rule, channels, now_str)
            else:
                self._evaluate_failure_alert(db, rule, channels, now_str)

    def _evaluate_failure_alert(self, db, rule, channels, now_str: str):
        """Original failure-count alert evaluation."""
        check_id = rule["check_id"]
        location_filter = ""
        params = [check_id, rule["failures"]]
        if "location" in rule.keys() and rule["location"]:
            location_filter = " AND location = ?"
            params = [check_id, rule["location"], rule["failures"]]

        jobs = db.execute(
            f"SELECT status FROM synthetic_check_jobs "
            f"WHERE check_id = ?{location_filter} AND status IN ('completed','failed','timed_out') "
            f"ORDER BY completed_at DESC LIMIT ?",
            params,
        ).fetchall()

        consecutive_failures = 0
        for job in jobs:
            if job["status"] in ("failed", "timed_out"):
                consecutive_failures += 1
            else:
                break

        is_failing = consecutive_failures >= rule["failures"]
        was_firing = rule["firing"]

        if is_failing and not was_firing:
            db.execute(
                "UPDATE synthetic_alert_rules SET firing=1, last_fired_at=? WHERE id=?",
                (now_str, rule["id"]),
            )
            db.commit()
            self._send_notification(rule, consecutive_failures, channels, now_str)
            logger.info(
                "Synthetic alert fired (failure): %s (check %s, %d failures)",
                rule["name"],
                rule["check_id"],
                consecutive_failures,
            )

        elif not is_failing and was_firing:
            db.execute(
                "UPDATE synthetic_alert_rules SET firing=0 WHERE id=?",
                (rule["id"],),
            )
            db.commit()
            logger.info("Synthetic alert resolved: %s", rule["name"])

    def _evaluate_metric_alert(self, db, rule, channels, now_str: str):
        """Metric-based alert evaluation — check result_json fields against threshold."""
        metric_name = rule["metric_name"] if "metric_name" in rule.keys() else ""
        metric_operator = rule["metric_operator"] if "metric_operator" in rule.keys() else ">"
        metric_threshold = rule["metric_threshold"] if "metric_threshold" in rule.keys() else ""
        consecutive_required = (
            rule["consecutive_occurrences"] if "consecutive_occurrences" in rule.keys() else 3
        )

        if not metric_name or not metric_threshold:
            return

        check_id = rule["check_id"]
        location_filter = ""
        params = [check_id, consecutive_required]
        if "location" in rule.keys() and rule["location"]:
            location_filter = " AND location = ?"
            params = [check_id, rule["location"], consecutive_required]

        jobs = db.execute(
            f"SELECT result_json, status FROM synthetic_check_jobs "
            f"WHERE check_id = ?{location_filter} AND status IN ('completed','failed','timed_out') "
            f"ORDER BY completed_at DESC LIMIT ?",
            params,
        ).fetchall()

        try:
            threshold_f = float(metric_threshold)
        except ValueError:
            threshold_f = None

        consecutive_true = 0
        for job in jobs:
            matched = self._metric_condition_met(
                job, metric_name, metric_operator, metric_threshold, threshold_f
            )
            if matched:
                consecutive_true += 1
            else:
                break

        is_firing = consecutive_true >= consecutive_required
        was_firing = rule["firing"]

        if is_firing and not was_firing:
            db.execute(
                "UPDATE synthetic_alert_rules SET firing=1, last_fired_at=? WHERE id=?",
                (now_str, rule["id"]),
            )
            db.commit()
            message = (
                f"🔴 Synthetic Metric Alert: {rule['name']}\n\n"
                f"Check has exceeded threshold ({metric_name} {metric_operator} {metric_threshold}) "
                f"for {consecutive_true} consecutive check(s) "
                f"(required: {consecutive_required}).\n\n"
                f"View: {self.app.config.get('BASE_URL', '')}/alerts/synthetic-checks/{rule['check_id']}\n"
                f"Time: {now_str}"
            )
            self._send_notification_custom(rule, message, channels)
            logger.info(
                "Synthetic metric alert fired: %s (check %s, %s %s %s, %d consecutive)",
                rule["name"],
                rule["check_id"],
                metric_name,
                metric_operator,
                metric_threshold,
                consecutive_true,
            )

        elif not is_firing and was_firing:
            db.execute(
                "UPDATE synthetic_alert_rules SET firing=0 WHERE id=?",
                (rule["id"],),
            )
            db.commit()
            logger.info("Synthetic metric alert resolved: %s", rule["name"])

    def _evaluate_dns_change_alert(self, db, rule, channels, now_str: str):
        """Alert when DNS answers change from the previously known value."""
        check_id = rule["check_id"]

        check = db.execute(
            "SELECT check_type FROM synthetic_checks WHERE id=?", (check_id,)
        ).fetchone()
        if check is None or check["check_type"] != "dns":
            return

        consecutive_required = (
            rule["consecutive_occurrences"] if "consecutive_occurrences" in rule.keys() else 3
        )
        prev_answers = rule["dns_last_answers"] if "dns_last_answers" in rule.keys() else None

        job = db.execute(
            "SELECT result_json FROM synthetic_check_jobs "
            "WHERE check_id = ? AND status = 'completed' AND result_json IS NOT NULL "
            "ORDER BY completed_at DESC LIMIT 1",
            (check_id,),
        ).fetchone()

        if job is None:
            return

        try:
            result = json.loads(job["result_json"])
        except (json.JSONDecodeError, TypeError):
            return

        current_answers = result.get("answers")
        if current_answers is None:
            return

        current_answers_json = json.dumps(current_answers, sort_keys=True)

        change_count = int(rule["dns_change_count"]) if "dns_change_count" in rule.keys() else 0

        if prev_answers is not None and prev_answers != current_answers_json:
            change_count += 1
        elif prev_answers is not None and prev_answers == current_answers_json:
            change_count = 0
        else:
            change_count = 0

        db.execute(
            "UPDATE synthetic_alert_rules SET dns_last_answers=?, dns_change_count=? WHERE id=?",
            (current_answers_json, change_count, rule["id"]),
        )
        db.commit()

        is_firing = change_count >= consecutive_required
        was_firing = rule["firing"]

        if is_firing and not was_firing:
            db.execute(
                "UPDATE synthetic_alert_rules SET firing=1, last_fired_at=? WHERE id=?",
                (now_str, rule["id"]),
            )
            db.commit()
            message = (
                f"🔴 DNS Answer Change Alert: {rule['name']}\n\n"
                f"DNS answers for check have changed {change_count} consecutive time(s) "
                f"(required: {consecutive_required}).\n\n"
                f"Current answers: {current_answers_json}\n"
                f"Previous answers: {prev_answers}\n\n"
                f"View: {self.app.config.get('BASE_URL', '')}/alerts/synthetic-checks/{rule['check_id']}\n"
                f"Time: {now_str}"
            )
            self._send_notification_custom(rule, message, channels)
            logger.info(
                "Synthetic DNS change alert fired: %s (check %s, %d changes)",
                rule["name"],
                rule["check_id"],
                change_count,
            )

        elif not is_firing and was_firing:
            persist = rule.get("dns_change_persist", 0)
            if persist:
                logger.info(
                    "Synthetic DNS change alert would auto-resolve but persist is on: %s",
                    rule["name"],
                )
                db.execute(
                    "UPDATE synthetic_alert_rules SET dns_change_count=0 WHERE id=?",
                    (rule["id"],),
                )
                db.commit()
            else:
                db.execute(
                    "UPDATE synthetic_alert_rules SET firing=0 WHERE id=?",
                    (rule["id"],),
                )
                db.commit()
                logger.info("Synthetic DNS change alert resolved: %s", rule["name"])

    def _metric_condition_met(self, job, metric_name, operator, threshold_str, threshold_f):
        """Check if a single job result meets the metric condition."""
        try:
            result = json.loads(job["result_json"]) if job["result_json"] else {}
        except (json.JSONDecodeError, TypeError):
            return False

        value = result
        for part in metric_name.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = None
                break

        if value is None:
            return False

        if threshold_f is not None and isinstance(value, (int, float)):
            v = float(value)
            t = threshold_f
            if operator == ">":
                return v > t
            elif operator == ">=":
                return v >= t
            elif operator == "<":
                return v < t
            elif operator == "<=":
                return v <= t
            elif operator == "==":
                return v == t
            elif operator == "!=":
                return v != t
            return False
        else:
            v_str = str(value).strip()
            t_str = threshold_str.strip()
            if operator == "==":
                return v_str == t_str
            elif operator == "!=":
                return v_str != t_str
            return False

    def _send_notification(self, rule, consecutive_failures, channel_ids, now_str: str):
        """Send alert notification through configured channels."""
        try:
            from app.models import get_db

            db = get_db(self.app.config["DATABASE_PATH"])
            try:
                for ch_id in channel_ids:
                    channel = db.execute(
                        "SELECT * FROM notification_channels WHERE id=? AND enabled=1",
                        (ch_id,),
                    ).fetchone()
                    if channel is None:
                        continue

                    message = (
                        f"🔴 Synthetic Check Alert: {rule['name']}\n\n"
                        f"Check has failed {consecutive_failures} time(s) "
                        f"(threshold: {rule['failures']}).\n\n"
                        f"View: {self.app.config.get('BASE_URL', '')}/alerts/synthetic-checks/{rule['check_id']}\n"
                        f"Time: {now_str}"
                    )

                    ch_type = channel["type"]
                    if ch_type == "slack":
                        self._notify_slack(channel, message)
                    elif ch_type == "discord":
                        self._notify_discord(channel, message)

            finally:
                db.close()
        except Exception:
            logger.exception("Failed to send synthetic alert notification")

    def _send_notification_custom(self, rule, message: str, channel_ids):
        """Send a custom alert message through configured channels."""
        try:
            from app.models import get_db

            db = get_db(self.app.config["DATABASE_PATH"])
            try:
                for ch_id in channel_ids:
                    channel = db.execute(
                        "SELECT * FROM notification_channels WHERE id=? AND enabled=1",
                        (ch_id,),
                    ).fetchone()
                    if channel is None:
                        continue

                    ch_type = channel["type"]
                    if ch_type == "slack":
                        self._notify_slack(channel, message)
                    elif ch_type == "discord":
                        self._notify_discord(channel, message)

            finally:
                db.close()
        except Exception:
            logger.exception("Failed to send synthetic alert notification")

    def _notify_slack(self, channel, message: str):
        """Send Slack webhook notification."""
        try:
            config = json.loads(channel["config"])
            webhook_url = config.get("webhook_url", "")
            if not webhook_url:
                return
            from urllib import request as urllib_request

            payload = json.dumps({"text": message}).encode()
            req = urllib_request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib_request.urlopen(req, timeout=10)
        except Exception:
            logger.exception("Slack notification failed for channel %s", channel["id"])

    def _notify_discord(self, channel, message: str):
        """Send Discord webhook notification."""
        try:
            config = json.loads(channel["config"])
            webhook_url = config.get("webhook_url", "")
            if not webhook_url:
                return
            from urllib import request as urllib_request

            payload = json.dumps({"content": message}).encode()
            req = urllib_request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib_request.urlopen(req, timeout=10)
        except Exception:
            logger.exception("Discord notification failed for channel %s", channel["id"])
