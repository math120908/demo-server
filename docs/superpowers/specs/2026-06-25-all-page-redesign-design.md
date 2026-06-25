# /all/ Page Redesign — Design

**Date:** 2026-06-25
**Component:** `src/demo_server/server.py` — `listing()` handler + `WELCOME_PAGE` template

## Problem

The `/all/` listing page is visually plain (generic white box, blue links) and
ordered alphabetically with no sense of recency. Users can't tell which modules
were updated recently versus long ago.

## Goals

1. Sort modules by update time (newest first).
2. Show each module's update time inline.
3. Split the list into time sections: recently updated vs older.
4. Refresh the visual design (Direction A — "refined rows").

## Design

### Timestamp source

- A module's update time = **mtime of the newest file inside its directory**
  (recursive walk). Falls back to the directory's own mtime if the directory has
  no files.
- Filesystem mtime chosen over git-commit time for simplicity / zero git
  dependency. Known caveat: a fresh `git clone` rewrites file mtimes to checkout
  time, collapsing real history — accepted, because the production server serves
  locally-built pages whose mtimes are accurate.

### Sorting

- Primary: **mtime descending** (newest first).
- Tiebreaker: **name ascending** (alphabetical) when mtimes collide. This gives
  a stable, sensible order for buckets where many dirs share one clone-stamped
  second (e.g. the entire "Earlier" group).

### Sections (render order)

1. **Pinned** — from `.config` `pinned-modules`, in config order. Excluded from
   the time sections below. No count badge.
2. **Recent · past month** — non-pinned modules updated within **30 days**.
   Count badge shown.
3. **Earlier** — everything else. Count badge shown.

Within each section, the sort rule above applies. A section is omitted entirely
if it has no modules.

### Timestamp display

- Recent section: **relative** — `today`, `1 day ago`, `N days ago`.
- Earlier section: **absolute** — `Mon D` (e.g. `May 21`); include year only if
  not the current year (`Mon D, YYYY`).

### Visual (Direction A — refined rows)

- Centered white panel, max-width ~560px, soft shadow, rounded corners.
- Header: `demo-server` title + `N modules` tagline.
- Section labels: small uppercase muted text + rounded count pill.
- Each module is a full-width row: name left, time right (tabular numerals,
  muted). Hairline divider between rows; subtle hover background.
- Pinned rows prefixed with a gold star (★).
- `today` rendered in green to highlight the freshest module.
- All copy in **English**.

## Out of scope

- No git-based timestamps.
- No card-grid layout (considered, rejected for 40+ items).
- No change to auth / encryption / routing — only the listing render path.

## Verification

- Load `/all/` against the real `pages/` dir; confirm: pinned on top, Recent
  ordered today→older, Earlier alphabetical, counts correct (Recent 12 /
  Earlier 26 at time of writing), times match `stat` on the dirs.
