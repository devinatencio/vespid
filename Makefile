.PHONY: test dev rpm deb clean lint help install-deps test-deps syntax-check docs docs-serve \
        sign-rpms package package-rpm package-deb package-deps package-docker package-clean

PYTHON   ?= python3
PYTEST   ?= python3 -m pytest
PIP      ?= pip3
NAME     := vespid
VERSION  := 1.0.0
# RPM signing — set SIGN_KEY to the GPG signing key ID/name
#   gpg --gen-key           # one-time: create a signing key
#   echo '%_gpg_name Vespid Security' >> ~/.rpmmacros
#   make rpm SIGN_KEY="Vespid Security"
SIGN_KEY ?=

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install-deps: ## Install runtime dependencies (requires pip)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-agent.txt

test-deps: ## Install test and dev dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-test.txt

test: ## Run pytest test suite (also runs syntax checks)
	PYTHONPATH=. $(PYTEST) tests/ -v

syntax-check: ## Run basic import and syntax checks
	$(PYTHON) -c "import ast; ast.parse(open('vespid/config.py').read())"
	$(PYTHON) -c "import ast; ast.parse(open('vespid/log_processor.py').read())"
	$(PYTHON) -c "import ast; ast.parse(open('vespid/detectors.py').read())"
	$(PYTHON) -c "import ast; ast.parse(open('vespid/daemon.py').read())"
	$(PYTHON) -c "import ast; ast.parse(open('vespid/cli.py').read())"
	$(PYTHON) -c "import ast; ast.parse(open('vespid/databus.py').read())"
	$(PYTHON) -c "import ast; ast.parse(open('vespid/server_client.py').read())"
	$(PYTHON) -c "import ast; [ast.parse(open(f'vespid/cli/{m}.py').read()) for m in ('__init__','app','fleet','intel','nodes','config','admin','server','events')]"
	@echo "All syntax checks passed."

lint: ## Run ruff linter + formatter check on all agent source files
	ruff check vespid/ tests/
	ruff format --check vespid/ tests/

rpm: ## Build RPM package from source (set SIGN_KEY to sign)
	mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	rm -rf /tmp/$(NAME)-$(VERSION)
	mkdir -p /tmp/$(NAME)-$(VERSION)/$(NAME)-$(VERSION)
	cp -r vespid config data pyproject.toml vespid.service LICENSE /tmp/$(NAME)-$(VERSION)/$(NAME)-$(VERSION)/
	find /tmp/$(NAME)-$(VERSION) -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find /tmp/$(NAME)-$(VERSION) -name '*.pyc' -delete 2>/dev/null || true
	cd /tmp/$(NAME)-$(VERSION) && tar czf $(CURDIR)/rpmbuild/SOURCES/$(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	rm -rf /tmp/$(NAME)-$(VERSION)
	cp $(NAME).spec rpmbuild/SPECS/
	rpmbuild --define "_topdir $(CURDIR)/rpmbuild" -bb rpmbuild/SPECS/$(NAME).spec
	@echo "RPM built in rpmbuild/RPMS/"
ifneq ($(SIGN_KEY),)
	rpm --addsign --define "_gpg_name $(SIGN_KEY)" rpmbuild/RPMS/*/*.rpm rpmbuild/SRPMS/*.rpm
	@echo "RPMs signed with key: $(SIGN_KEY)"
endif

sign-rpms: ## Sign all RPMs in rpmbuild/ (usage: make sign-rpms SIGN_KEY="Vespid Security")
	test -n "$(SIGN_KEY)" || { echo "Set SIGN_KEY (e.g. SIGN_KEY=\"Vespid Security\")"; exit 1; }
	rpm --addsign --define "_gpg_name $(SIGN_KEY)" rpmbuild/RPMS/*/*.rpm rpmbuild/SRPMS/*.rpm
	@echo "RPMs signed with key: $(SIGN_KEY)"

deb: ## Build .deb packages for Debian/Ubuntu
	./build_deb.sh

# --- Unified packaging -----------------------------------------------------
# Builds packages for every component (Python agent, server, Rust agent,
# vespid-sync). `make package` picks the host's native format; use
# `make package-docker` to build both formats in containers.
DIST_DIR   := $(CURDIR)/dist
PKG_FORMAT := $(shell sh packaging/detect-pkg-format.sh)

package: ## Build this host's native packages (all components)
	@case "$(PKG_FORMAT)" in \
		rpm) $(MAKE) package-rpm ;; \
		deb) $(MAKE) package-deb ;; \
		*) echo "No native RPM/DEB toolchain detected on this host."; \
		   echo "  install one:             make package-deps"; \
		   echo "  or build both in Docker: make package-docker"; \
		   exit 1 ;; \
	esac

package-rpm: ## Build all RPM packages into dist/rpm
	@mkdir -p "$(DIST_DIR)/rpm"
	$(MAKE) rpm
	$(MAKE) -C vespid-server rpm
	vespid-agent/packaging/build-rpm.sh -o "$(DIST_DIR)/rpm"
	vespid-agent/packaging/build-vespid-sync-rpm.sh -o "$(DIST_DIR)/rpm"
	@cp rpmbuild/RPMS/*/*.rpm "$(DIST_DIR)/rpm/" 2>/dev/null || true
	@cp vespid-server/rpmbuild/RPMS/*/*.rpm "$(DIST_DIR)/rpm/" 2>/dev/null || true
	@echo "RPMs written to $(DIST_DIR)/rpm"

package-deb: ## Build all DEB packages into dist/deb
	@mkdir -p "$(DIST_DIR)/deb"
	./build_deb.sh
	vespid-agent/packaging/build-vespid-agent-deb.sh -o "$(DIST_DIR)/deb"
	vespid-agent/packaging/build-vespid-sync-deb.sh -o "$(DIST_DIR)/deb"
	@echo "DEBs written to $(DIST_DIR)/deb"

package-deps: ## Install this host's packaging toolchain
	sh packaging/install-pkg-deps.sh

package-docker: ## Build both RPM and DEB in containers (works on any host)
	sh packaging/package-docker.sh

package-clean: ## Remove dist/ and generated rpmbuild trees
	rm -rf "$(DIST_DIR)" rpmbuild vespid-server/rpmbuild

clean: ## Remove build artifacts
	rm -rf rpmbuild/ build/ dist/ *.egg-info
	find . -maxdepth 2 -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -maxdepth 2 -name '*.pyc' -delete 2>/dev/null || true
	rm -rf .pytest_cache
	rm -rf site/ website/docs/

docs: ## Build MkDocs documentation site
	pip install mkdocs-material
	mkdocs build
	@echo "Docs built in website/docs/"
	@echo "Preview with: make docs-serve"

docs-serve: ## Serve MkDocs site locally on port 8000
	python3 -m http.server -d website/docs/ 8000
