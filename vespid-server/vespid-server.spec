%define name        vespid-server
%{!?version:%define version 1.0.0}
%define release     1%{?dist}
%define install_dir /opt/vespid-server
%define config_dir  /etc/vespid-server
%define data_dir    /var/lib/vespid-server
%define log_dir     /var/log/vespid-server
%define service_user vespid

Name:           %{name}
Version:        %{version}
Release:        %{release}
Summary:        Vespid Server — centralized security event dashboard

License:        GPL-3.0-or-later
URL:            https://github.com/vespid/vespid
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       python3 >= 3.11
Requires:       python3-pip
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Vespid Server Dashboard is a Flask-based centralized management server
for the Vespid ecosystem. It receives SecurityEvent batches from
distributed Vespid daemon instances, persists them in SQLite (or MySQL),
and presents them through an HTMX-powered web dashboard with real-time
streaming, IP rule management, threat intelligence feed orchestration,
geographic visualization, and trend analytics.

Features:
  - Real-time SSE event streaming with toast notifications
  - Whitelist/blocklist management with command push to nodes
  - Centralized threat intelligence feed catalog (12 pre-seeded feeds)
  - Per-node detail pages with block list, allowlist, and feed toggles
  - Role-based access control (admin, analyst, viewer)
  - YAML and JSON configuration support
  - SQLite (default) or MySQL backend

%prep
%setup -q

%build
# No build step — pure Python application

%install
rm -rf %{buildroot}

# Application files
install -d -m 0755 %{buildroot}%{install_dir}
cp -a app/ %{buildroot}%{install_dir}/
cp -a packs/ %{buildroot}%{install_dir}/
cp -a vespid_server.py %{buildroot}%{install_dir}/
cp -a gunicorn.conf.py %{buildroot}%{install_dir}/
cp -a requirements.txt %{buildroot}%{install_dir}/
cp -a schema_mysql.sql %{buildroot}%{install_dir}/
cp -a CHANGELOG.md %{buildroot}%{install_dir}/
cp -a pyproject.toml README.md VERSION %{buildroot}%{install_dir}/

# Data directory — shared country-code JSON (canonical source: data/country_codes.json)
install -d -m 0755 %{buildroot}%{install_dir}/data
cp -a data/country_codes.json %{buildroot}%{install_dir}/data/

# Configuration directory — install YAML as default, keep JSON as reference
install -d -m 0750 %{buildroot}%{config_dir}
install -m 0640 config.example.yaml %{buildroot}%{config_dir}/config.yaml


# Systemd unit file
install -d -m 0755 %{buildroot}/usr/lib/systemd/system
install -m 0644 vespid-server.service %{buildroot}/usr/lib/systemd/system/

# Data and log directories (created but empty)
install -d -m 0750 %{buildroot}%{data_dir}
install -d -m 0750 %{buildroot}%{log_dir}

# GeoIP database directory
install -d -m 0755 %{buildroot}%{config_dir}/geoip

# DB-IP Lite GeoIP databases (CC BY 4.0 — freely redistributable).
# Prefer the copy bundled in the source tarball (so SRPM rebuilds work),
# fall back to a locally pre-staged directory, and otherwise build
# without GeoIP data rather than failing.
if ls geoip/dbip-*.mmdb >/dev/null 2>&1; then
    cp -a geoip/dbip-*.mmdb %{buildroot}%{config_dir}/geoip/
elif ls /tmp/vespid-server-geoip/dbip-*.mmdb >/dev/null 2>&1; then
    cp -a /tmp/vespid-server-geoip/dbip-*.mmdb %{buildroot}%{config_dir}/geoip/
else
    echo "WARNING: no DB-IP GeoIP databases found (bundled or pre-staged) —" \
         "building RPM without GeoIP data; run ./download_geoip.sh /tmp/vespid-server-geoip"
fi

# Manifest for the optional GeoIP mmdb files. %files -f needs the file list at
# install-processing time; generating it here means SRPM rebuilds (which lack
# the pre-staged /tmp dir) succeed even when no GeoIP data was bundled.
: > %{_builddir}/%{name}-%{version}/vespid-geoip.files
if ls %{buildroot}%{config_dir}/geoip/dbip-*.mmdb >/dev/null 2>&1; then
    echo "%{config_dir}/geoip/dbip-*.mmdb" > %{_builddir}/%{name}-%{version}/vespid-geoip.files
fi

# Environment file for systemd overrides
cat > %{buildroot}%{config_dir}/environment <<'EOF'
# Environment overrides for vespid-server.service
# See gunicorn.conf.py for full documentation on each setting.
#
# Uncomment ONE section below based on your database backend.

# --- SQLite backend (gevent) ---
# SQLite serializes writes, so keep workers minimal. Gevent still helps
# because SSE and reads don't block each other.
# GUNICORN_WORKERS=1
# GUNICORN_WORKER_CONNECTIONS=1000

# --- MySQL / MariaDB backend (gevent) ---
# One worker per CPU core. Gevent handles concurrency within each worker.
# For a 2-core box use 2, for 4-core use 4.
# GUNICORN_WORKERS=2
# GUNICORN_WORKER_CONNECTIONS=1000

# --- Common settings (apply regardless of backend) ---
# GUNICORN_BIND=127.0.0.1:8000
# GUNICORN_WORKER_CLASS=gevent
# GUNICORN_TIMEOUT=120
# GUNICORN_KEEPALIVE=65
# GUNICORN_MAX_REQUESTS=8000
# GUNICORN_MAX_REQUESTS_JITTER=800
EOF
chmod 0640 %{buildroot}%{config_dir}/environment

# CLI wrapper script — provides 'vespid-server-admin' on PATH
install -d -m 0755 %{buildroot}/usr/bin
cat > %{buildroot}/usr/bin/vespid-server-admin <<'WRAPPER'
#!/bin/bash
# Wrapper for vespid_server.py CLI commands.
# Auto-discovers config: config.yaml > config.yml > config.json
CONFIG_DIR="/etc/vespid-server"
CONFIG=""
for candidate in "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/config.yml" "$CONFIG_DIR/config.json"; do
    if [ -f "$candidate" ]; then
        CONFIG="$candidate"
        break
    fi
done
if [ -z "$CONFIG" ]; then
    echo "Warning: no config file found in $CONFIG_DIR, using defaults" >&2
fi
exec /opt/vespid-server/.venv/bin/python \
    /opt/vespid-server/vespid_server.py \
    ${CONFIG:+--config "$CONFIG"} "$@"
WRAPPER
chmod 0755 %{buildroot}/usr/bin/vespid-server-admin

%pre
# Create the vespid system user if it does not exist
getent group %{service_user} >/dev/null || groupadd -r %{service_user}
getent passwd %{service_user} >/dev/null || \
    useradd -r -g %{service_user} -d %{install_dir} -s /sbin/nologin \
    -c "Vespid Server" %{service_user}
exit 0

%post
# Set up Python virtual environment and install dependencies
if [ ! -d %{install_dir}/.venv ]; then
    python3 -m venv %{install_dir}/.venv
fi
%{install_dir}/.venv/bin/pip install --quiet --upgrade pip
(cd %{install_dir} && .venv/bin/pip install --quiet -r requirements.txt)

# Fix ownership
chown -R %{service_user}:%{service_user} %{install_dir}
chown -R %{service_user}:%{service_user} %{data_dir}
chown -R %{service_user}:%{service_user} %{log_dir}
chown -R %{service_user}:%{service_user} %{config_dir}

# Generate a random SECRET_KEY on first install (must be before init-db)
if [ "$1" = "1" ]; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    if [ -f %{config_dir}/config.yaml ]; then
        sed -i "s/change-me-to-a-random-string/${SECRET}/" %{config_dir}/config.yaml
    fi

fi

# Initialize the database (auto-discovers config.yaml)
su -s /bin/bash %{service_user} -c \
    "cd %{install_dir} && .venv/bin/python vespid_server.py --config %{config_dir}/config.yaml init-db"

# Auto-create admin user on first install
if [ "$1" = "1" ]; then
    su -s /bin/bash %{service_user} -c \
        "cd %{install_dir} && .venv/bin/python vespid_server.py --config %{config_dir}/config.yaml create-admin --non-interactive" 2>&1
    ADMIN_PASSWORD=""
    if [ -f "%{config_dir}/.admin-password" ]; then
        ADMIN_PASSWORD=$(cat "%{config_dir}/.admin-password")
        rm -f "%{config_dir}/.admin-password"
    fi
fi

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable %{name}.service

echo ""
echo "=== Vespid Server installed ==="
echo ""
echo "Configuration:  %{config_dir}/config.yaml"
echo "Database:       %{data_dir}/vespid.db"
echo ""
if [ "$1" = "1" ] && [ -n "$ADMIN_PASSWORD" ]; then
    echo "Admin password: $ADMIN_PASSWORD"
    echo ""
fi
echo "Next steps:"
echo "  1. Edit %{config_dir}/config.yaml (SECRET_KEY is auto-generated)"
echo "  2. Start service: sudo systemctl start %{name}"
echo "  3. Login at http://localhost:8000/ (place nginx/Caddy in front for TLS)"
echo "  4. View logs:    journalctl -u %{name} -f"
echo ""
echo "For MySQL backend, see: %{install_dir}/schema_mysql.sql"
echo ""
echo "GeoIP: DB-IP Lite databases are pre-installed in %{config_dir}/geoip/"
echo "  (country, city, ASN — updated monthly). To use MaxMind instead,"
echo "  replace with GeoLite2-Country.mmdb, GeoLite2-City.mmdb, GeoLite2-ASN.mmdb."
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

%files -f %{_builddir}/%{name}-%{version}/vespid-geoip.files
%defattr(-,%{service_user},%{service_user},-)

# Application
%dir %{install_dir}
%{install_dir}/app/
%{install_dir}/packs/
%{install_dir}/vespid_server.py
%{install_dir}/gunicorn.conf.py
%{install_dir}/requirements.txt
%{install_dir}/pyproject.toml
%{install_dir}/README.md
%{install_dir}/VERSION
%{install_dir}/CHANGELOG.md
%{install_dir}/data/country_codes.json
%{install_dir}/schema_mysql.sql

# Configuration
%dir %{config_dir}
%config(noreplace) %{config_dir}/config.yaml

%config(noreplace) %{config_dir}/environment

# Systemd
%attr(0644,root,root) /usr/lib/systemd/system/%{name}.service

# CLI wrapper
%attr(0755,root,root) /usr/bin/vespid-server-admin

# Data and log directories
%dir %{data_dir}
%dir %{log_dir}

# GeoIP database directory (DB-IP Lite databases provided under CC BY 4.0).
# The mmdb contents are optional — they come from the vespid-geoip.files
# manifest generated in the install scriptlet, so SRPM rebuilds without GeoIP data succeed.
%dir %{config_dir}/geoip

# License
%license LICENSE

%changelog
* %(date "+%%a %%b %%d %%Y") Vespid Team <team@vespid.dev> - 1.0.0-1
- Detection rule packs loaded from YAML files (packs/ directory)
- Included packs: Apache attacks, NGINX attacks, OpenSSH attacks, Postfix attacks
- YAML configuration support (preferred over JSON)
- Centralized threat intelligence feed catalog (12 pre-seeded feeds)
- Whitelist/blocklist IP rule management with command push
- Per-node detail pages with block list, feed toggles, and unblock actions
- Server-to-node command channel (allowlist, block, feed management)
- Node heartbeat with block list, allowlist, and feed state reporting
- MySQL schema file for high-volume deployments
- Flask-based dashboard with HTMX UI
- Event ingestion API with bearer token auth
- Real-time SSE event streaming
- Role-based access control (admin, analyst, viewer)
- Geographic visualization and trend charts
- Audit logging and API key management
