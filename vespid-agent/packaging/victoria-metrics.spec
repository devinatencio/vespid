%global vm_version 1.144.0
%global vm_user victoriametrics
%global vm_group victoriametrics
%global vm_home %{_sharedstatedir}/victoria-metrics
%global debug_package %{nil}

%ifarch x86_64
%global vm_arch amd64
%endif
%ifarch aarch64
%global vm_arch arm64
%endif
%ifarch %{ix86}
%global vm_arch 386
%endif
%ifarch armv7hl
%global vm_arch arm
%endif

Name:           victoria-metrics
Version:        %{vm_version}
Release:        1%{?dist}
Summary:        Fast, cost-effective time-series database

License:        Apache-2.0
URL:            https://github.com/VictoriaMetrics/VictoriaMetrics

Source0: https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v%{vm_version}/victoria-metrics-linux-%{vm_arch}-v%{vm_version}.tar.gz
Source1: victoria-metrics.service

BuildArch:      %{_arch}

%description
VictoriaMetrics is a fast, cost-effective, and scalable monitoring
solution and time-series database. It can be used as a long-term
remote storage for Prometheus.

This package provides the single-node VictoriaMetrics binary with
a hardened systemd service, running as a dedicated unprivileged user.

Features:
  - PromQL and MetricsQL query language support
  - Prometheus remote write API compatible
  - Single binary, zero external dependencies
  - 90-day default retention, configurable via override

%prep
%setup -q -c

%build
# Binary-only package — nothing to compile

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{vm_home}
mkdir -p %{buildroot}%{_unitdir}

install -D -m 755 victoria-metrics-prod %{buildroot}%{_bindir}/victoria-metrics-prod
install -D -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/victoria-metrics.service

%pre
getent group %{vm_group} >/dev/null || groupadd -r %{vm_group}
getent passwd %{vm_user} >/dev/null || useradd -r -g %{vm_group} -d %{vm_home} -s /sbin/nologin %{vm_user}

%post
%systemd_post victoria-metrics.service
if [ $1 -eq 1 ]; then
    echo ""
    echo "=== VictoriaMetrics installed ==="
    echo ""
    echo "  Metrics API:  http://localhost:8428"
    echo "  Data dir:     %{vm_home}"
    echo "  Config:       Systemd override via drop-in or edit the unit"
    echo ""
    echo "  Start:  systemctl enable --now victoria-metrics"
    echo "  Status: systemctl status victoria-metrics"
    echo "  Logs:   journalctl -u victoria-metrics -f"
    echo ""
    echo "  To change retention or listen address, create an override:"
    echo "    systemctl edit victoria-metrics"
    echo ""
fi

%preun
%systemd_preun victoria-metrics.service

%postun
%systemd_postun_with_restart victoria-metrics.service

%files
%defattr(-,root,root,-)
%{_bindir}/victoria-metrics-prod
%dir %attr(0750,%{vm_user},%{vm_group}) %{vm_home}
%{_unitdir}/victoria-metrics.service

%changelog
* Thu May 28 2026 Vespid Team <dev@vespid.io> - 1.144.0-1
- Initial packaging of VictoriaMetrics 1.144.0
