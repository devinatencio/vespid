# 07 — Module Switcher & Unified UX

## Overview

As Vespid grows to support three modules (Security, Monitoring, Inventory),
the sidebar nav needs to adapt. Each module brings its own pages, and showing all
of them in a single nav list becomes overwhelming.

The solution: a **module switcher** dropdown that changes the sidebar content
based on which module is selected.

## Current State

Today, the sidebar shows all pages in a flat list with section groupings:

```
📊 Dashboard
  📈 Analytics
    Events, Counters, Geo, Trends
  🧠 Intelligence
    Search, Threat Metrics
  🔒 Security
    Blocked, Feeds, Fleet, IP Rules, Nodes, Detection Rules
  ⚙️ Admin
    API Keys, Audit Log, ...
```

With Metrics enabled, a fourth section appears. With Inventory (future), it becomes
five. The sidebar scrolls on smaller screens. Users hunting for a specific page
scan past unrelated sections.

## Target UX

The top bar gains a module selector. The sidebar renders only the selected module's
pages:

```
┌──────────────────────────────────────────────────────────────┐
│ ☰    Vespid       [ 🔒 Security ▾ ]    🔔    👤    🌙     │ ← top bar
│                         │                                     │
│                    ┌────┴────┐                               │
│                    │ Security │  ← selected                   │
│                    │ Metrics  │                               │
│                    │Inventory │                               │
│                    └─────────┘                               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  📊 Dashboard                       ← Security module pages  │
│  📈 Analytics                                                │
│    Events, Counters, Geo, Trends                             │
│  🧠 Intelligence                                             │
│    Search, Threat Metrics                                    │
│  🔒 Security                                                 │
│    Blocked, Feeds, Fleet, IP Rules, Nodes, Detections       │
│  ⚙️ Admin (security-specific)                                │
│    Config, Enrollment, Test Rules                            │
│                                                               │
│  ─── Shared ───                                              │
│  ⚙️ Admin                                                     │
│    API Keys, Audit Log, DB Backups, Server Logs, Users      │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

Switch to Metrics:

```
┌──────────────────────────────────────────────────────────────┐
│ ☰    Vespid       [ 📊 Metrics ▾ ]     🔔    👤    🌙     │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  📊 System Metrics                    ← Metrics module pages  │
│    Overview, Health Checks                                   │
│  📈 Host Detail (when selected)                              │
│                                                               │
│  ─── Shared ───                                              │
│  ⚙️ Admin                                                     │
│    API Keys, Audit Log, DB Backups, Server Logs, Users      │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

## Implementation Strategy

### Phase 1: Config-driven modules (done)

The foundation is already built. Each module is enabled/disabled via config:

```yaml
SUBSYSTEMS:
  SECURITY_ENABLED: true
  METRICS_ENABLED: true
  INVENTORY_ENABLED: false   # future
```

When a module is disabled, its blueprints aren't registered and its nav section
is hidden. A monitoring-only user sees only Metrics in the sidebar.

### Phase 2: Module selector dropdown (V2)

Add a select element or custom dropdown to the top bar. Changing the selection
hides all non-selected module sections in the sidebar via CSS.

**Pure CSS approach (simplest):**

```html
<select class="module-switcher" onchange="switchModule(this.value)">
    <option value="security" selected>🔒 Security</option>
    <option value="metrics">📊 Metrics</option>
    <option value="inventory">📋 Inventory</option>
</select>
```

```javascript
function switchModule(module) {
    document.querySelectorAll('.spn-section[data-module]').forEach(el => {
        el.style.display = el.dataset.module === module ? '' : 'none';
    });
    localStorage.setItem('vespid_module', module);
}
```

Each sidebar section gets a `data-module` attribute:

```html
<div class="spn-section" data-module="security">
    <div class="spn-section-title">📈 Analytics</div>
    ...
</div>
<div class="spn-section" data-module="metrics">
    <div class="spn-section-title">📊 Metrics</div>
    ...
</div>
```

The shared Admin section has no `data-module` attribute (always visible).

### Phase 3: Module-aware URL routing (V3)

Each module gets its own URL namespace and default page:

| Module | Namespace | Default page | Nav label |
|--------|-----------|-------------|-----------|
| Security | `/dashboard` | Dashboard overview | 🔒 Security |
| Metrics | `/metrics` | Fleet overview | 📊 Metrics |
| Inventory | `/inventory` | Asset list | 📋 Inventory |

The login redirect goes to the first enabled module's default page. Breadcrumbs
reflect the module context:

```
Vespid > Security > Events > Event detail
Vespid > Metrics > web-01 > CPU
Vespid > Inventory > Proxmox > vms > db-01
```

### Phase 4: Cross-module linking (V3)

Pages in different modules can link to each other meaningfully:

- Inventory asset detail → "View Metrics" link if the host is monitored
- Metrics host detail → "View in Inventory" link if the host has asset data
- Security event → "View host metrics" link

## What the switcher changes

| Concern | Before | After |
|---------|--------|-------|
| Sidebar length | All sections, scrolls | One module's sections |
| Role visibility | All modules' pages mixed | Only your enabled module |
| Default page | Always security dashboard | Per-module default |
| Bookmarks | Work unchanged | Work unchanged (URLs don't depend on switcher state) |
| Keyboard nav | All shortcuts available | Module-specific shortcuts |

## Why this over separate UIs

- **One deployment** — same server, same auth, same DB, same process
- **Shared infrastructure** — API keys, users, audit log, backups work across modules
- **Progressive disclosure** — start with Security, add Metrics, add Inventory without rebuilding
- **Cross-module context** — a security event on host X is more useful when you can click through to its CPU graph
- **HTMX-friendly** — server-rendered pages, no SPA framework needed

## Risk: feeling like three separate apps

Mitigated by:
- Consistent visual design (same theme, same nav structure, same CSS)
- Shared header with module switcher always visible
- Cross-links between modules
- Unified search (future): search across events, metrics, and assets in one bar

## Rollout

| Phase | What |
|-------|------|
| V1 (done) | Config-driven subsystem toggles (`SECURITY_ENABLED`, `METRICS_ENABLED`) |
| V2 | Module switcher dropdown (CSS + JS, ~50 lines) |
| V3 | Module-aware URLs, cross-module links, unified search |
