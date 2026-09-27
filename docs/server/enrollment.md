# Auto-Enrollment

Auto-enrollment allows agents to provision their own API credentials
without manual key creation.  When an agent starts with no credentials
(or with an empty `API_KEY`), it
contacts the server's enrollment API to request access.

## Enrollment modes

| Mode | Behavior | Use case |
|------|----------|----------|
| `open` | Credentials issued immediately | Lab, development, trusted networks |
| `manual_approval` | Queued until admin approves (default) | Production — admin reviews each node |
| `restricted` | Requires a pre-shared enrollment token | High-security — only nodes with the token can enroll |

Configure the mode in the server dashboard under **Admin → Enrollment**
or in the server config file.

## Agent setup

Set the agent config to trigger enrollment:

```yaml
# /etc/vespid/vespid.yaml
SERVER_URL: "https://your-server"
API_KEY: ""
```

On startup, the agent's `EnrollmentClient` detects the placeholder key
and initiates enrollment:

1. **POST** `/api/v1/enroll` with node hostname, OS, network interfaces
2. Server creates a pending enrollment request
3. Agent polls `GET /api/v1/enroll/status/<node_id>` with exponential
   backoff (30s initial, 5min max)
4. Once approved, the server returns an API key
5. Agent stores credentials at `/var/lib/vespid/credentials.json` (mode 0600)
6. Normal operation begins — heartbeats, event reporting, fleet subscription

## Approval workflow

For `manual_approval` mode:

1. Agent submits enrollment request
2. Admin sees pending requests in **Admin → Enrollment** or via CLI
3. Admin approves or rejects:

```bash
vespid-cli admin enrollment list
vespid-cli admin enrollment approve 12
vespid-cli admin enrollment reject 13
```

Approved agents immediately receive credentials on their next poll.
Rejected agents stop polling and log the rejection.

## Restricted mode

In `restricted` mode, agents must include a pre-shared token in their
enrollment request.  Set the token in the server config:

```yaml
ENROLLMENT_TOKEN: "your-secret-enrollment-token"
```

Then configure agents with the token as their API key:

```yaml
# /etc/vespid/vespid.yaml
API_KEY: "your-secret-enrollment-token"
```

## Credential rotation

Agents support automatic credential rotation:

- If an agent re-enrolls while holding a still-active API key, the server
  validates the existing key via the `X-Existing-Credentials` header
- On successful validation, the server issues a new key and revokes the old one
- This enables zero-downtime key rotation without admin intervention

## Credential storage

Credentials are stored at `/var/lib/vespid/credentials.json` with
mode 0600 (root-only readable).  The file contains:

```json
{
    "api_key": "hg_...",
    "server_url": "https://your-server",
    "node_id": "web01-abc123"
}
```

The agent loads credentials in this order (first match wins):

1. Credentials file (`/var/lib/vespid/credentials.json`)
2. Config file (`/etc/vespid/vespid.yaml` — `API_KEY` field)
3. Environment variable (`VESPID_API_KEY`)

## Revoking enrollment

Admins can revoke an agent's enrollment, which invalidates its API key:

```bash
vespid-cli admin enrollment revoke 12
```

The agent receives a 401 on its next heartbeat and re-enters enrollment
mode automatically.

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/enroll` | None (rate-limited) | Submit enrollment request |
| GET | `/api/v1/enroll/status/<node_id>` | None (rate-limited) | Poll status / retrieve credentials |

Both endpoints are rate-limited to 10 requests per minute per source IP.

## Troubleshooting

**Agent stuck in "enrolling" state:**

- Check server logs for the enrollment request
- Verify the enrollment mode is not `restricted` without a token
- Check network connectivity to the server on the configured port

**Agent enrolled but not reporting:**

- Verify credentials file exists: `ls -la /var/lib/vespid/credentials.json`
- Check the agent log: `sudo vespid-cli tail-log -f`
- Confirm the API key is valid: `vespid-cli server status`

**Re-enrollment after revocation:**

- The agent automatically re-enrolls on 401 errors
- Delete `/var/lib/vespid/credentials.json` to force immediate re-enrollment
