# Fleet Block TTL Escalation Bug (2026-05-23)

## Summary

A first-time offender IP (`213.171.9.168`) was blocked for **3 days** instead of the expected **1 day** because the daemon was publishing BLOCKED events for already-blocked IPs, triggering spurious fleet block TTL renewals that escalated via the recidive system.

## The Bug Chain

### Event Flow Per Block

When a detection fires on the agent:

1. `log_processor.py:988` `_on_line()` — detector fires → publishes `DETECTED` event → calls `_on_block(det)`
2. `daemon.py:472` `_on_detection()` — publishes `BLOCKED` event (with `detection_rule_name`, `threat_tag`, etc.) → calls `self.nft.block_local()`
3. `nftables_manager.py:906` `block_local()` — applies nftables rule → publishes `NFT_ACTION + BLOCKED`
4. Databus ships all events to server
5. Server API: BLOCKED event → Propagation Engine → creates fleet block. NFT_ACTION → Intel DB (increments `total_times_blocked`).

### What Went Wrong for 213.171.9.168

Three detections fired for the same IP from the same node in close succession (SSH_MEDIUM_BRUTE, SSH_SLOW_BRUTE, SSH_BANNER_GRAB). Each detection generated a BLOCKED event.

**Batch 1 (04:58:51):**
- Event 3198: SSH_MEDIUM_BRUTE BLOCKED → Propagation Engine creates fleet block with **1d TTL** (correct — Intel DB is empty, `_get_fleet_strike` returns 0).  
- Event 3199: NFT_ACTION → Intel DB gets `total_times_blocked=1`.  
- Event 3201: SSH_SLOW_BRUTE BLOCKED → finds active block → renewal at **1d** (correct — Intel DB not updated yet, same loop 1).  

**Batch 2 (05:01:53):**
- Event 3202: SSH_BANNER_GRAB BLOCKED → arrives AFTER Intel DB was updated.  
- Renewal calls `_get_fleet_strike` → `total_times_blocked=1` → returns 1 → `_ttl_for_fleet_strike(1)` = **259200 (3 days)**.  

**Root Cause**: The daemon published a BLOCKED event **before** checking if the IP was already blocked locally (`daemon.py:501`). Every detection for the same IP generated another BLOCKED event, even though the IP hadn't been unblocked.

## Fixes Applied

### 1. Agent: `vespid/nftables_manager.py`
Added `is_blocked(ip)` method (line ~1277):
```python
def is_blocked(self, ip: str) -> bool:
    now = time.time()
    with self._lock:
        meta = self._local.get(ip)
        if meta is None:
            return False
        expires = meta.get("expires_at")
        if expires is not None and expires <= now:
            return False
        return True
```

### 2. Agent: `vespid/daemon.py`
Added early-return guard in `_on_detection()` (line ~487):
```python
if self.nft.is_blocked(det.source_ip):
    return
```
This prevents ANY BLOCKED event from being published for IPs already in `shield_local`. The detection is still logged via the DETECTED event.

### 3. Server: `vespid-server/app/propagation_engine.py`
Modified the renewal path (line ~490): when the reporting node matches the fleet block's `originating_node_id`, preserve the existing TTL rather than escalating via recidive. Only cross-node renewals (different nodes corroborating) trigger escalation.

```python
originating = existing["originating_node_id"]
existing_ttl = existing["ttl_seconds"]
if originating and node_id and node_id != originating:
    fleet_strike = self._get_fleet_strike(source_ip)
    ttl = self._ttl_for_fleet_strike(fleet_strike)
    ttl = max(ttl, existing_ttl)
else:
    ttl = existing_ttl
```

### 4. Test: `vespid-server/tests/test_fleet_propagation.py`
Added `test_same_node_renewal_does_not_escalate` — verifies same-node renewal preserves existing TTL.

## Key Design Decisions

- **Agent-side fix is the primary fix** — prevents the spurious BLOCKED events from ever reaching the server.
- **Server-side fix is defense-in-depth** — even if an old agent sends the events, the server won't escalate for same-node renewals.
- **Cross-node escalation still works** — the existing `test_renewal_escalates_ttl` test passes because it uses a different node for the renewal.
- **Admin TTL extensions still work** — SSE renew/unblock messages from the server are handled by `FleetBlockSubscriber`, not by the detection path.

## Deployment Notes

The server is running an older version that already has `_get_fleet_strike` and `_ttl_for_fleet_strike` deployed. The fixes need to be deployed:

1. Copy updated `vespid/nftables_manager.py` and `vespid/daemon.py` to the agent node
2. Copy updated `vespid-server/app/propagation_engine.py` to the server
3. Restart both services
4. Fix the existing 3-day TTL for 213.171.9.168: either remove/re-add the fleet block, or manually update `fleet_blocks.ttl_seconds` and `fleet_blocks.expires_at` in MySQL
