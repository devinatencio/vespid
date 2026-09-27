%global sync_name vespid-sync
%global install_dir /opt/%{sync_name}
%global config_dir %{_sysconfdir}/%{sync_name}
%global log_dir %{_localstatedir}/log/%{sync_name}

%global debug_package %{nil}

Name:           vespid-sync
Version:        1.0.0
Release:        1%{?dist}
Summary:        Vespid Sync Agent — infrastructure asset discovery

License:        GPL-3.0-or-later
URL:            https://github.com/vespid/hivemonitor
Source0:        %{sync_name}-%{version}.tar.gz

BuildRequires:  python3
BuildRequires:  python3-devel
BuildRequires:  systemd-rpm-macros

Requires:       python3
Requires:       python3-pip

%description
Vespid Sync Agent discovers infrastructure assets from hypervisors
(Proxmox, VMware, etc.) and pushes them to the Vespid inventory
service. Runs every 5 minutes via systemd timer.

Supports:
  - Proxmox PVE (QEMU VMs + LXC containers)
  - Hypervisor node discovery
  - Guest agent data (hostname, IPs, MAC addresses)
  - Resource pool mapping
  - Entity resolution against existing assets

%prep
%setup -q -n %{sync_name}-%{version}

%build
# Python package — no compilation needed

%install
# Create directory structure
mkdir -p %{buildroot}%{install_dir}
mkdir -p %{buildroot}%{install_dir}/providers
mkdir -p %{buildroot}%{config_dir}
mkdir -p %{buildroot}%{log_dir}
mkdir -p %{buildroot}%{_unitdir}

# Copy Python source
cp -a sync.py %{buildroot}%{install_dir}/sync.py
cp -a providers/ %{buildroot}%{install_dir}/providers/
cp -a setup.py %{buildroot}%{install_dir}/setup.py

# Install the default config (will be customized by the admin)
install -D -m 600 config.yaml.example %{buildroot}%{config_dir}/config.yaml

# Install systemd units
install -D -m 644 systemd/vespid-sync-agent.service %{buildroot}%{_unitdir}/vespid-sync-agent.service
install -D -m 644 systemd/vespid-sync-agent.timer %{buildroot}%{_unitdir}/vespid-sync-agent.timer

%post
# Create virtual environment and install dependencies on first install
if [ $1 -eq 1 ]; then
    %{_bindir}/python3 -m venv --system-site-packages %{install_dir}/.venv
    %{install_dir}/.venv/bin/pip install --no-cache-dir \
        requests pyyaml proxmoxer 2>&1 || :
    echo ""
    echo "=== Vespid Sync Agent installed ==="
    echo ""
    echo "1. Create an API key in the Vespid dashboard"
    echo "   (Admin → API Keys → Create Key → role: agent)"
    echo ""
    echo "2. Edit /etc/vespid-sync/config.yaml and set:"
    echo "   - sync.server_url (your Vespid server)"
    echo "   - sync.api_key (the key you created)"
    echo "   - providers[].token_id and token_secret (Proxmox credentials)"
    echo ""
    echo "3. Enable and start the timer:"
    echo "   systemctl enable --now vespid-sync-agent.timer"
    echo ""
    echo "   To test discovery without waiting for the timer:"
    echo "   systemctl start vespid-sync-agent"
    echo ""
fi

%preun
%systemd_preun vespid-sync-agent.timer
%systemd_preun vespid-sync-agent.service

%postun
%systemd_postun_with_restart vespid-sync-agent.timer
%systemd_postun_with_restart vespid-sync-agent.service
# The virtualenv is created in %post, not at build time, so rpm does not own
# it — remove it (and the now-empty install dir) on final uninstall.
if [ $1 -eq 0 ]; then
    rm -rf %{install_dir}/.venv
    rmdir %{install_dir} 2>/dev/null || true
fi

%files
%defattr(-,root,root,-)
%{install_dir}/sync.py
%{install_dir}/providers/
%{install_dir}/setup.py
%config(noreplace) %attr(600,root,root) %{config_dir}/config.yaml
%dir %attr(750,root,root) %{log_dir}
%{_unitdir}/vespid-sync-agent.service
%{_unitdir}/vespid-sync-agent.timer

%changelog
* Sat Jun  6 2026 Vespid Team <dev@vespid.io> - 1.0.0-1
- Initial release
- Proxmox PVE provider (QEMU + LXC)
- Hypervisor node + cluster discovery
- Guest agent data integration
- Systemd timer (every 5 minutes)
