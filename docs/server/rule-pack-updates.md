# Rule Pack Updates

Vespid ships detection rules as **rule packs** — YAML files in the server's
`packs/` directory. This page explains how to publish updated packs from a
build host and how installations check for and apply them, without redeploying
the whole server.

!!! note "Who this is for"
    Operators who maintain a fleet of Vespid servers and want to roll out new
    or updated detection rules (typically the Sigma packs) independently of
    server releases.

---

## Concepts

A **bundle** is a directory or archive containing one or more pack `*.yaml`
files plus an optional `manifest.json`:

```
sigma-web-attacks.yaml
sigma-ssh-attacks.yaml
sigma-host-threats.yaml
manifest.json
```

The `manifest.json` records provenance and integrity data:

```json
{
  "sigma_commit": "8a4813404ea3074890e0cda9272d4d1a8b2941d6",
  "generated_at": "2026-10-08T16:59:07Z",
  "rules_imported": 155,
  "packs": {
    "sigma-web-attacks.yaml": { "sha256": "f34b2b82…", "rules": 38 }
  }
}
```

Bundles can be a plain directory, a `.tar.gz`/`.tgz` archive, or a `.zip`
archive. `rules update` also accepts an `http(s)://` URL to an archive.

---

## 1. Produce a bundle

### From a build host (recommended)

Sync the latest SigmaHQ rules, convert them, and package a distributable
bundle in one step:

```bash
cd /path/to/vespid
python -m vespid.scripts.sigma_import --sync --bundle dist/sigma-packs.tar.gz

# or, via the Makefile:
make sigma-bundle
```

`--bundle` accepts a directory, a `.tar.gz`/`.tgz`, or a `.zip`. Without
`--bundle`, the packs and `manifest.json` are written into
`vespid-server/packs/`; `--output-dir DIR` redirects them elsewhere. The
manifest records the exact upstream Sigma commit the packs were generated from,
plus a SHA-256 and rule count for each file. If upstream has no new commits,
`--sync --bundle` still rebuilds the bundle so you always get a fresh artifact.

### From an installed server

You can also export the packs currently installed on a server:

```bash
# all installed packs -> a gzipped archive
vespid-server-admin rules export --to /tmp/vespid-packs.tar.gz

# only the Sigma packs
vespid-server-admin rules export --to /tmp/sigma-packs.tar.gz \
  --packs sigma-web-attacks,sigma-ssh-attacks,sigma-host-threats
```

Existing manifest provenance (e.g. `sigma_commit`) is carried into the
exported bundle.

!!! tip "Sign the bundle"
    Bundle signing/verification is not built in yet. For untrusted transport,
    distribute the archive over TLS and/or sign it (e.g. `minisign`/`gpg`) and
    verify the signature before running `rules update`. See
    [Roadmap](#roadmap).

---

## 2. Publish

Host the archive anywhere reachable by your servers — an internal web server,
artifact repository, or object store. A stable URL such as
`https://packs.example.com/sigma-packs.tar.gz` works well.

---

## 3. Check and apply on an installation

```bash
# Show what is installed and its provenance
vespid-server-admin rules status

# Check whether the bundle has anything new (exit 1 if updates are available)
vespid-server-admin rules update --from https://packs.example.com/sigma-packs.tar.gz --check

# Preview the diff without changing anything
vespid-server-admin rules update --from https://packs.example.com/sigma-packs.tar.gz --dry-run

# Apply (prompts for confirmation)
vespid-server-admin rules update --from https://packs.example.com/sigma-packs.tar.gz

# Apply non-interactively
vespid-server-admin rules update --from https://packs.example.com/sigma-packs.tar.gz --yes

# Then load the new packs in the running process
sudo systemctl restart vespid-server
```

`--from` accepts a **directory**, a local **archive**, or an **`http(s)` URL**.

### What `rules update` does

1. **Resolve & fetch** the bundle (downloading/extracting into a temp dir; archive
   paths are checked to prevent traversal).
2. **Validate** every rule — regexes must compile *on the target Python*,
   log-based rules must contain a `(?P<ip>…)` capture group (auditd rules are
   exempt), names must be unique, and thresholds must be sane. If validation
   fails, nothing is changed.
3. **Diff** the bundle against the installed packs — added / removed / changed
   rules are reported. The diff is scoped to the packs inside the bundle, so
   shipping only the Sigma packs does not report your other packs as removed.
4. **Back up** the current packs to `packs/.backups/<timestamp>/`.
5. **Install** the bundle's pack files.
6. **Reconcile** the database against the new packs (see below).
7. **Bump the detection-rules revision** so connected agents fetch the new rules.

Restart the server to expose the new packs to the running web process (the
database is already reconciled; the restart refreshes the in-memory pack list).

### Reconcile semantics

The reconcile is non-destructive to user changes:

| Situation | Behaviour |
|---|---|
| New rule in a pack | Inserted **disabled**, so an admin reviews before enabling |
| Pack ships a changed definition, rule is pristine | Definition refreshed; the user's `enabled` state is preserved |
| Pack ships a changed definition, rule was **edited** by the user | Left untouched (`user_modified` is protected) |
| Rule **renamed** upstream (same Sigma UUID, new name) | Renamed in place — no duplicate rule is created, `enabled` preserved |
| Rule **removed** from a pack, rule is pristine | Retired (deleted) so it doesn't linger as a stale duplicate |
| Rule removed from a pack but was **edited** by the user | Left untouched |

---

## Rollback

Each apply leaves the previous packs in `packs/.backups/<timestamp>/`. To roll
back, restore the previous pack files and restart — the reconciler reapplies
them on startup (user `enabled`/edited state is preserved):

```bash
sudo cp /opt/vespid-server/packs/.backups/20261008-095727/sigma-*.yaml /opt/vespid-server/packs/
sudo systemctl restart vespid-server
```

---

## Automation example

Check daily and apply automatically, then reload the service:

```cron
# /etc/cron.d/vespid-rule-updates
0 5 * * * root vespid-server-admin rules update \
  --from https://packs.example.com/sigma-packs.tar.gz --check && \
  (vespid-server-admin rules update \
     --from https://packs.example.com/sigma-packs.tar.gz --yes && \
   systemctl reload vespid-server)
```

`--check` exits `1` when updates are available, so it composes cleanly in
shell conditionals. Use `systemctl reload` for a graceful reload.

!!! warning "Air-gapped hosts"
    Download the bundle on a connected host, copy it across, and point
    `--from` at the local archive path.

---

## Bundle format (reference)

| Member | Required | Purpose |
|---|---|---|
| `*.yaml` | yes | One or more [pack files](rule-packs.md#pack-file-format) |
| `manifest.json` | no | Provenance (`sigma_commit`, `generated_at`) + per-file `sha256` and rule counts |

---

## Roadmap

Planned improvements to the update workflow:

- Cryptographic signing + verification of bundles (`rules update --verify`).
- `--prune` to remove installed packs that a bundle intentionally supersedes.
- An HTTP endpoint so the dashboard can show "update available" and apply it.

The legacy `POST /api/v1/rules/sigma/sync` admin endpoint requires the
source-tree importer and is **not available in packaged installs**; use
`rules update` instead (see [Sigma Rule Integration](../SIGMA_INTEGRATION.md)).
