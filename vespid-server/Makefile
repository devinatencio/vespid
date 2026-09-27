.PHONY: test dev rpm clean lint help

PYTHON   ?= .venv/bin/python
PYTEST   ?= .venv/bin/pytest
PIP      ?= .venv/bin/pip
FLASK    ?= .venv/bin/flask
NAME     := vespid-server
VERSION  := $(shell cat VERSION 2>/dev/null || echo 1.0.0)

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

venv: ## Create virtual environment and install dependencies
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

test: ## Run pytest test suite
	$(PYTEST) server_tests/ -v

test-props: ## Run only property-based tests
	$(PYTEST) server_tests/test_properties.py -v

dev: ## Run Flask development server
	$(PYTHON) vespid_server.py

rpm: ## Build RPM package from source
	mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	rm -rf /tmp/$(NAME)-$(VERSION)
	mkdir -p /tmp/$(NAME)-$(VERSION)/$(NAME)-$(VERSION)
	cp -r app packs vespid_server.py gunicorn.conf.py requirements.txt \
		pyproject.toml README.md VERSION \
		config.example.yaml schema_mysql.sql CHANGELOG.md \
		vespid-server.service ../data ../LICENSE /tmp/$(NAME)-$(VERSION)/$(NAME)-$(VERSION)/
	# Strip __pycache__ and .pyc before packaging
	find /tmp/$(NAME)-$(VERSION) -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find /tmp/$(NAME)-$(VERSION) -name '*.pyc' -delete 2>/dev/null || true
	# Strip macOS metadata junk (AppleDouble companions, .DS_Store, __MACOSX)
	find /tmp/$(NAME)-$(VERSION) -name '._*' -delete 2>/dev/null || true
	find /tmp/$(NAME)-$(VERSION) -name '.DS_Store' -delete 2>/dev/null || true
	find /tmp/$(NAME)-$(VERSION) -type d -name '__MACOSX' -exec rm -rf {} + 2>/dev/null || true
	# Download DB-IP Lite GeoIP databases for packaging and bundle them into
	# the source tarball so SRPM rebuilds include GeoIP data
	rm -rf /tmp/vespid-server-geoip
	./download_geoip.sh /tmp/vespid-server-geoip
	mkdir -p /tmp/$(NAME)-$(VERSION)/$(NAME)-$(VERSION)/geoip
	cp -a /tmp/vespid-server-geoip/dbip-*.mmdb /tmp/$(NAME)-$(VERSION)/$(NAME)-$(VERSION)/geoip/
	# COPYFILE_DISABLE prevents macOS tar from embedding AppleDouble metadata
	cd /tmp/$(NAME)-$(VERSION) && COPYFILE_DISABLE=1 tar czf $(CURDIR)/rpmbuild/SOURCES/$(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	rm -rf /tmp/$(NAME)-$(VERSION)
	cp $(NAME).spec rpmbuild/SPECS/
	rpmbuild --define "_topdir $(CURDIR)/rpmbuild" --define "version $(VERSION)" -bb rpmbuild/SPECS/$(NAME).spec
	@echo "RPM built in rpmbuild/RPMS/"

clean: ## Remove build artifacts
	rm -rf rpmbuild/ __pycache__ .pytest_cache .hypothesis
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
	find . -name '._*' -delete 2>/dev/null || true
	find . -name '.DS_Store' -delete 2>/dev/null || true

lint: ## Run ruff linter + formatter check on all server source files
	ruff check app/ vespid_server.py gunicorn.conf.py
	ruff format --check app/ vespid_server.py gunicorn.conf.py
