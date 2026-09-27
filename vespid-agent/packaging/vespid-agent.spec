%global agent_name vespid-agent
%global agent_user vespid-agent
%global agent_group vespid-agent
%global config_dir %{_sysconfdir}/vespid-agent
%global state_dir %{_sharedstatedir}/vespid-agent
%global log_dir %{_localstatedir}/log/vespid-agent

%global debug_package %{nil}

Name:           vespid-agent
Version:        1.0.0
Release:        1%{?dist}
Summary:        Vespid Agent system metrics collection agent

License:        GPL-3.0-or-later
URL:            https://github.com/vespid/hivemonitor
Source0:        %{agent_name}-%{version}.tar.gz

BuildRequires:  rustc
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros
BuildRequires:  protobuf-compiler

%description
Vespid Agent Agent collects system metrics (CPU, memory, disk, network,
systemd) from Linux hosts and ships them to a Vespid server for
storage in VictoriaMetrics. Designed to be lightweight, secure and
easy to deploy.

%prep
%setup -q

%build
export PROTOC=/usr/bin/protoc
cargo build --release --bin %{agent_name}

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{config_dir}
mkdir -p %{buildroot}%{state_dir}
mkdir -p %{buildroot}%{log_dir}
mkdir -p %{buildroot}%{_unitdir}

install -D -m 755 target/release/%{agent_name} %{buildroot}%{_bindir}/%{agent_name}
install -D -m 644 systemd/vespid-agent.service %{buildroot}%{_unitdir}/%{agent_name}.service
install -D -m 644 systemd/vespid-worker.service %{buildroot}%{_unitdir}/vespid-worker.service

cat > %{buildroot}%{config_dir}/agent.yaml <<'CONFIGEOF'
log_level: "info"
log_retention_days: 30

server:
  url: "https://localhost:8443"
  api_key: ""

agent:
  labels: {}

collectors:
  cpu:
    enabled: true
    interval_secs: 60
  memory:
    enabled: true
    interval_secs: 60
  disk:
    enabled: true
    interval_secs: 60
  network:
    enabled: true
    interval_secs: 60
    exclude_interfaces:
      - "lo"
  systemd:
    enabled: true
    interval_secs: 60
  process:
    enabled: true
    interval_secs: 120
    top_n: 20
  psi:
    enabled: true
    interval_secs: 60
  loadavg:
    enabled: true
    interval_secs: 60
  procfs:
    enabled: false
    interval_secs: 60
    metrics: []
  exec:
    enabled: false
    interval_secs: 300
    timeout_secs: 30
    scripts: []
    # Nagios-compatible health checks (exit code 0=OK, 1=WARN, 2=CRIT):
    # scripts:
    #   - name: "disk_usage"
    #     command: ["/usr/local/bin/check-disk.sh"]
    #   - name: "ssl_cert"
    #     command: ["/usr/local/bin/check-ssl-cert", "example.com"]

buffer:
  path: "/var/lib/vespid-agent/buffer"
  max_total_size: 67108864
  max_file_size: 8388608

transport:
  batch_size: 500
  flush_interval_secs: 30
  request_timeout_secs: 30
CONFIGEOF

cat > %{buildroot}%{config_dir}/worker.yaml <<'WORKEREOF'
server:
  url: "https://localhost:8443"
  api_key: ""

agent:
  labels: {}

worker:
  capabilities: ["http", "icmp", "tcp", "dns"]
  labels:
    location: "default"
  max_concurrent: 10
  poll_interval_secs: 5
WORKEREOF

%pre
getent group %{agent_group} >/dev/null || groupadd -r %{agent_group}
getent passwd %{agent_user} >/dev/null || useradd -r -g %{agent_group} -d %{state_dir} -s /sbin/nologin %{agent_user}

%post
%systemd_post %{agent_name}.service

# Ensure the runtime directories exist and are owned by the service account.
# This also repairs directories/files left root-owned by an earlier install or
# a manual run, which would otherwise cause a "Permission denied" panic when
# the agent opens its log file.
mkdir -p %{state_dir} %{log_dir}
chown -R %{agent_user}:%{agent_group} %{state_dir} %{log_dir}
chmod 0750 %{state_dir} %{log_dir}

if [ $1 -eq 1 ]; then
    echo ""
    echo "=== Vespid Agent Agent installed ==="
    echo ""
    echo "1. Edit /etc/vespid-agent/agent.yaml and set:"
    echo "   - server.url (your Vespid server)"
    echo "   - server.api_key (enrollment token)"
    echo ""
    echo "2. Start the agent:"
    echo "   systemctl enable --now vespid-agent"
    echo ""
    echo "3. For synthetic monitoring checks, start the worker:"
    echo "   Edit /etc/vespid-agent/worker.yaml and set:"
    echo "   - server.url, server.api_key, worker.labels.location"
    echo "   systemctl enable --now vespid-worker"
    echo ""
fi

%preun
%systemd_preun %{agent_name}.service
%systemd_preun vespid-worker.service

%postun
%systemd_postun_with_restart %{agent_name}.service
%systemd_postun_with_restart vespid-worker.service

%files
%defattr(-,root,root,-)
%{_bindir}/%{agent_name}
%config(noreplace) %{config_dir}/agent.yaml
%config(noreplace) %{config_dir}/worker.yaml
%dir %attr(0750,%{agent_user},%{agent_group}) %{state_dir}
%dir %attr(0750,%{agent_user},%{agent_group}) %{log_dir}
%{_unitdir}/%{agent_name}.service
%{_unitdir}/vespid-worker.service

%changelog
* Sat Jun  6 2026 Vespid Team <dev@vespid.io> - 1.0.0-1
- Initial release
- 5 collectors: CPU, memory, disk, network, systemd
- HTTP batch transport with Prometheus remote write format
- Local file buffer for offline resilience
- systemd service with security hardening
