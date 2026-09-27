# Quickstart

Get a Vespid agent protecting a single node in under 10 minutes, then
optionally add the centralized server for fleet management.

## 1. Install the agent

=== "Debian / Ubuntu"

    ```bash
    sudo dpkg -i vespid_1.0.0_all.deb
    sudo apt-get install -f   # resolve dependencies
    ```

=== "RHEL / AlmaLinux / Rocky"

    ```bash
    sudo rpm -ivh vespid-1.0.0-1.noarch.rpm
    ```

=== "pip (development)"

    ```bash
    sudo python3 -m pip install .
    sudo install -d -m 0750 /etc/vespid /var/lib/vespid /var/log/vespid
    ```

## 2. Verify prerequisites

```bash
sudo nft list ruleset   # nftables must be available
sudo vespid --check-config
```

## 3. Start the daemon

```bash
sudo systemctl start vespid
sudo systemctl enable vespid
```

## 4. Verify it's working

```bash
sudo vespid-cli status
sudo vespid-cli list-local
sudo vespid-cli counters
```

The agent immediately begins tailing local logs, detecting brute-force
attacks, and managing `nftables` blocklists.

## 5. (Optional) Add the server

Install the server on a dedicated host for centralized event management,
fleet-wide blocklist sharing, and a web dashboard.

=== "Debian / Ubuntu"

    ```bash
    sudo dpkg -i vespid-server_1.0.0_all.deb
    sudo apt-get install -f
    ```

=== "RHEL / AlmaLinux / Rocky"

    ```bash
    sudo rpm -ivh vespid-server-1.0.0-1.noarch.rpm
    ```

=== "Manual"

    ```bash
    cd vespid-server/
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python vespid_server.py init-db
    python vespid_server.py create-admin --non-interactive
    python vespid_server.py
    ```

The server listens on `http://127.0.0.1:8000` by default.
Packaged installs (RPM/DEB) auto-create the admin user and print the
password during installation. Start the service:

```bash
sudo systemctl start vespid-server
sudo systemctl enable vespid-server
```

## 6. Connect agent to server

Create an API key in the server dashboard (**Admin → API Keys**), then
add it to the agent config:

```yaml
# /etc/vespid/vespid.yaml
SERVER_URL: "https://your-server"
API_KEY: "hg_your_api_key_here"
```

Restart the agent:

```bash
sudo systemctl restart vespid
```

The agent auto-registers on first heartbeat.  Verify in the dashboard
under **Security → Nodes**.

## 7. (Optional) Enable auto-enrollment

Instead of manually creating API keys, enable auto-enrollment on the
server so agents provision their own credentials:

```yaml
# /etc/vespid/vespid.yaml
SERVER_URL: "https://your-server"
API_KEY: ""
```

See the [Auto-Enrollment Guide](server/enrollment.md) for details on
enrollment modes and approval workflows.

## What's next?

- **[Agent Guide](agent/guide.md)** — full configuration reference, detection rules, feed subscriptions
- **[CLI Reference](agent/cli.md)** — all `vespid-cli` commands
- **[Server Guide](server/guide.md)** — dashboard pages, user roles, command channel
- **[Fleet Blocklist](server/fleet.md)** — fleet-wide block propagation
- **[Detection Rule Packs](server/rule-packs.md)** — enable built-in attack detection rules
- **[Architecture](architecture.md)** — how everything fits together
