from setuptools import find_packages, setup

setup(
    name="vespid-sync",
    version="1.0.1",
    description="Vespid Sync Agent — discover infrastructure assets from Proxmox and other providers",
    author="Vespid Team",
    author_email="dev@vespid.io",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.28",
        "pyyaml>=6.0",
    ],
    extras_require={
        "proxmox": ["proxmoxer>=2.0"],
        "vmware": ["pyvmomi>=8.0"],
    },
    entry_points={
        "console_scripts": [
            "vespid-sync=sync:main",
        ],
    },
)
