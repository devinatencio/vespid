%define name        vespid
%define version     1.0.0
%define release     1%{?dist}
%define install_dir /opt/vespid
%define config_dir  /etc/vespid
%define state_dir   /var/lib/vespid
%define log_dir     /var/log/vespid

%global __python bytecompile_errors_terminate_build 0
%global __python_compileall_opt ""

Name:           %{name}
Version:        %{version}
Release:        %{release}
Summary:        Vespid — lightweight security daemon for AlmaLinux / RHEL

License:        GPL-3.0-or-later
URL:            https://github.com/vespid/vespid
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       python3 >= 3.10
Requires:       python3-pip
Requires:       nftables
Requires:       audit
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Vespid is a lightweight, high-performance security daemon that tails
local log files, detects brute-force and reconnaissance activity using
sliding-window analysis, and blocks offending IPs via nftables sets.

Features include built-in detection rules for SSH, HTTP, and banner-grab
attacks, user-defined custom regex rules via YAML config, external IP
blocklist subscriptions, structured JSON telemetry, and a local CLI for
inspection and management.

%prep
%setup -q

%build
# No build step — pure Python application

%install
rm -rf %{buildroot}

# Application files
install -d -m 0755 %{buildroot}%{install_dir}
cp -a vespid/ %{buildroot}%{install_dir}/
cp -a pyproject.toml %{buildroot}%{install_dir}/

# Data directory — shared country-code JSON (canonical source: data/country_codes.json)
install -d -m 0755 %{buildroot}%{install_dir}/data
cp -a data/country_codes.json %{buildroot}%{install_dir}/data/

# Configuration directory with default config and server-managed example
install -d -m 0750 %{buildroot}%{config_dir}

# Normal (standalone) mode config
cp -a config/vespid-normal-mode.yml %{buildroot}%{config_dir}/vespid.yaml
chmod 0640 %{buildroot}%{config_dir}/vespid.yaml

# Fully managed mode config example
cp -a config/vespid-fully-managed.yml %{buildroot}%{config_dir}/vespid-fully-managed.yml.example
chmod 0640 %{buildroot}%{config_dir}/vespid-fully-managed.yml.example

# Systemd unit file
install -d -m 0755 %{buildroot}/usr/lib/systemd/system
install -m 0644 vespid.service %{buildroot}/usr/lib/systemd/system/

# State and log directories (created but empty)
install -d -m 0750 %{buildroot}%{state_dir}
install -d -m 0750 %{buildroot}%{log_dir}

# CLI wrapper scripts — provides 'vespid' and 'vespid-cli' on PATH
install -d -m 0755 %{buildroot}/usr/bin

cat > %{buildroot}/usr/bin/vespid <<'WRAPPER'
#!/bin/bash
# Vespid daemon wrapper
export PYTHONPATH=/opt/vespid
exec /opt/vespid/.venv/bin/python -m vespid.daemon "$@"
WRAPPER
chmod 0755 %{buildroot}/usr/bin/vespid

cat > %{buildroot}/usr/bin/vespid-cli <<'WRAPPER'
#!/bin/bash
# Vespid local management CLI wrapper
export PYTHONPATH=/opt/vespid
exec /opt/vespid/.venv/bin/python -m vespid.cli "$@"
WRAPPER
chmod 0755 %{buildroot}/usr/bin/vespid-cli

# Auditd execve rules (commented out by default — admin enables when ready)
install -d -m 0755 %{buildroot}/etc/audit/rules.d
cat > %{buildroot}/etc/audit/rules.d/vespid-execve.rules <<'AUDITEOF'
# Vespid — Auditd Execve Rules
# =============================
# These rules configure auditd to record all process executions (execve
# syscalls).  Required for Vespid's host-based threat detection pipeline
# (auditd monitoring).
#
# The rules are commented out by default.  To enable:
#   1. Uncomment the two lines below
#   2. Reload the rules:  sudo augenrules --load
#   3. Verify:            auditctl -l | grep execve
#   4. Enable auditd monitoring in your Vespid server profile
#
# Alternatively, apply immediately (non-persistent):
#   sudo auditctl -a always,exit -F arch=b64 -S execve
#   sudo auditctl -a always,exit -F arch=b32 -S execve

# -a always,exit -F arch=b64 -S execve
# -a always,exit -F arch=b32 -S execve
AUDITEOF

# rsyslog drop-in — stops rsyslog from mirroring vespid's own log lines into
# /var/log/messages via journald (self-tailing feedback loop). Requires
# SyslogIdentifier=vespid in the unit.
install -d -m 0755 %{buildroot}/etc/rsyslog.d
cat > %{buildroot}/etc/rsyslog.d/20-vespid.conf <<'RSYSLOGEOF'
# Vespid rsyslog drop-in
# ----------------------
# The vespid daemon and agents log to stdout, which systemd journald captures
# and rsyslog mirrors into /var/log/messages (RHEL/SUSE) and /var/log/syslog
# (Debian). Vespid tails those files for security events, so this filter
# discards its own mirrored lines to avoid a self-tailing feedback loop and
# parse noise.
#
# Matches every vespid program (vespid, vespid-agent, vespid-sync-agent,
# vespid-worker, vespid-server). Set SyslogIdentifier=<unit> in the systemd
# units so the program tag is stable regardless of the wrapper executable name.
#
# NOTE: On RHEL-family systems the standard rules in /etc/rsyslog.conf (e.g.
# "*.info ... /var/log/messages") are evaluated BEFORE the $IncludeConfig of
# /etc/rsyslog.d/*.conf, so this rule cannot undo writes to those files. It
# does stop forwarding to any rules processed after the include (custom log
# files, remote syslog, etc.). The daemon additionally skips its own log lines
# at parse time, which covers the /var/log/messages mirror itself.
:programname, startswith, "vespid" stop
RSYSLOGEOF
chmod 0644 %{buildroot}/etc/rsyslog.d/20-vespid.conf

find %{buildroot} -type d -name "__pycache__" -exec rm -rf {} +
find %{buildroot} -type f -name "*.pyc" -delete

rpm --eval '%__os_install_post'


%post
# Set up Python virtual environment and install dependencies
if [ ! -d %{install_dir}/.venv ]; then
    python3 -m venv %{install_dir}/.venv
fi
%{install_dir}/.venv/bin/pip install --quiet --upgrade pip
%{install_dir}/.venv/bin/pip install --quiet \
    typer'>='0.25.1 rich'>='14.3.0 pyyaml'>='6.0 httpx'>='0.28.0 \
    inotify-simple'>='1.3 2>/dev/null || true

# Optional: install geoip2 if MaxMind DB is present
if [ -f /var/lib/GeoIP/GeoLite2-Country.mmdb ]; then
    %{install_dir}/.venv/bin/pip install --quiet geoip2 2>/dev/null || true
fi

# Create runtime directories (in case they were removed)
install -d -m 0750 %{state_dir}
install -d -m 0750 %{log_dir}

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable %{name}.service

# Apply the rsyslog drop-in that excludes vespid's own lines from the syslog
# mirrors (only relevant when rsyslog is installed and running).
systemctl try-restart rsyslog 2>/dev/null || true

echo ""
echo "=== Vespid installed ==="
echo ""
echo "Configuration:"
echo "  Active config:  %{config_dir}/vespid.yaml (standalone, full reference)"
echo "  Fully managed:  %{config_dir}/vespid-fully-managed.yml.example"
echo ""
echo "To switch to fully managed mode:"
echo "  sudo cp %{config_dir}/vespid-fully-managed.yml.example %{config_dir}/vespid.yaml"
echo "  sudo vi %{config_dir}/vespid.yaml   # set SERVER_URL and API_KEY"
echo ""
echo "Auditd host-threat detection (optional):"
echo "  1. Uncomment the rules in /etc/audit/rules.d/vespid-execve.rules"
echo "  2. Reload:  sudo augenrules --load"
echo "  3. Enable auditd monitoring in your server config profile"
echo ""
echo "Commands:"
echo "  Edit config:    sudo vi %{config_dir}/vespid.yaml"
echo "  Validate:       sudo vespid --check-config"
echo "  Start service:  sudo systemctl start %{name}"
echo "  View logs:      journalctl -u %{name} -f"
echo ""

%preun
if [ "$1" = "0" ]; then
    # Full uninstall — stop and disable the service
    systemctl stop %{name}.service 2>/dev/null || true
    systemctl disable %{name}.service 2>/dev/null || true
fi

%postun
systemctl daemon-reload
if [ "$1" = "0" ]; then
    # Full uninstall — remove the virtual environment
    rm -rf %{install_dir}/.venv
fi

%files
%defattr(-,root,root,-)

# Application
%dir %{install_dir}
%{install_dir}/vespid/
%{install_dir}/pyproject.toml
%{install_dir}/data/country_codes.json

# Configuration
%dir %attr(0750,root,root) %{config_dir}
%config(noreplace) %attr(0640,root,root) %{config_dir}/vespid.yaml
%attr(0640,root,root) %{config_dir}/vespid-fully-managed.yml.example

# Systemd
%attr(0644,root,root) /usr/lib/systemd/system/%{name}.service

# CLI wrappers
%attr(0755,root,root) /usr/bin/vespid
%attr(0755,root,root) /usr/bin/vespid-cli

# Auditd rules (commented out by default)
%config(noreplace) %attr(0644,root,root) /etc/audit/rules.d/vespid-execve.rules

# rsyslog drop-in (excludes vespid's own lines from syslog mirrors)
%config(noreplace) %attr(0644,root,root) /etc/rsyslog.d/20-vespid.conf

# State and log directories
%dir %attr(0750,root,root) %{state_dir}
%dir %attr(0750,root,root) %{log_dir}

# License
%license LICENSE

%changelog
* %(date "+%%a %%b %%d %%Y") Vespid Team <team@vespid.dev> - 1.0.0-1
- Version 1.0.0 release
- Server-to-node command channel (allowlist, block, feed management)
- Heartbeat reports block list, allowlist, and feed state to server
- Feed enable/disable/add/remove via remote commands
- Subscription manager respects per-feed enabled flag
- 5-second startup delay on heartbeat for control socket readiness
- Async log processor with rotation-aware tailing and catchup replay
- Sliding-window brute-force detection (fast, medium, slow)
- SSH reconnaissance detection (banner grab, pre-auth disconnect, auth timeout)
- User-defined custom regex detection rules via YAML config
- Dual nftables set management (shield_local + shield_subscribed)
- External IP blocklist subscription manager
- Producer/consumer telemetry bus with disk spooling
- Local CLI (vespid-cli) over UNIX socket
- GeoIP enrichment (optional)
- YAML and JSON config support
