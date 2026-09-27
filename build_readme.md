Two .deb packages built via 
build_deb.sh
:

Package	What it installs
vespid_1.0.0_all.deb	Daemon + CLI (the node agent)
vespid-server_1.0.0_all.deb	Flask dashboard server
File layout:

build_deb.sh                          # Main build script
debian/
├── vespid/DEBIAN/
│   ├── control                       # Package metadata + dependencies
│   ├── conffiles                     # Marks /etc/vespid/vespid.yaml as a conffile
│   ├── postinst                      # Creates venv, installs pip deps, enables systemd
│   ├── prerm                         # Stops + disables service on removal
│   └── postrm                        # Cleans up venv/state on purge
└── vespid-server/DEBIAN/
    ├── control                       # Package metadata + dependencies
    ├── conffiles                     # Marks config.yaml + environment as conffiles
    ├── preinst                       # Creates vespid system user
    ├── postinst                      # Creates venv, installs deps, init-db, generates SECRET_KEY
    ├── prerm                         # Stops + disables service on removal
    └── postrm                        # Cleans up venv/state/user on purge
Usage:

# Build both packages (run on a Debian/Ubuntu machine with dpkg-deb)
./build_deb.sh

# Build only one
./build_deb.sh client
./build_deb.sh server

# Install
sudo dpkg -i dist/deb/vespid_1.0.0_all.deb
sudo dpkg -i dist/deb/vespid-server_1.0.0_all.deb
sudo apt-get install -f   # resolve any missing deps
The packages mirror the same layout and lifecycle as your existing RPM specs — virtualenv created in postinst, config files protected from overwrites on upgrade, systemd services enabled automatically, and clean removal/purge behavior.
