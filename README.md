# snapdragon-tube-bff-api

Tube BFF — the access governance plane for the **LocalTube** video OPTIONAL SERVICE
(self-hosted personal YouTube archival: a user connects Google, their subscribed
channels sync to a DB, and yt-dlp downloads new videos on a schedule for owner-private
in-platform viewing). Twin of `snapdragon-owncast-bff-api` / `snapdragon-wiki-bff-api`
(Java 21 WebFlux + R2DBC Postgres + Liquibase + Casdoor JWT resource server, package
`systems.snapdragon.tubebff`).

## What this BFF owns

This service is the **may-use governance plane** for the tube service, NOT the media
plane. The downloaded content lives on a per-domain content PVC served range/HLS through
a SEPARATE be-gateway route + a tube-media serving sidecar (PR5), and the
Google-connect/subs-sync (PR3) + the yt-dlp downloader CronJob + work queue (PR4) are
separate components. This BFF owns the `tube_access` governance table — the
per-principal **may-use** grant/timeout/ban overlay an ADMIN curates so that, on top of
the `ROLE_TUBE` base role, an admin decides which of their domain's users may actually
use the tube service.

The browser→governance path is:

```
browser -> fe-gateway /bff/tube/** -> THIS BFF -> tube_access Postgres overlay
browser -> be-gateway /tube/media/** (range/HLS) -> tube-media sidecar (per-domain content PVC, PR5)
```

## PR2 (this PR) — the `tube_access` overlay + `TubeAccessGuard`

PR2 is the BFF **skeleton + the use grant/timeout/ban overlay**, cloned EXACTLY from the
owncast-bff `owncast_grant` (004) overlay (which itself cloned the wiki-bff `wiki_access`),
swapping `broadcast` → `use`:

- **`tube_access`** (Liquibase `004-tube-access.xml`) — the desired-state table:
  `access_type ∈ {use, banned}`, `state ∈ {active, revoked}` (never deleted = audit),
  `expires_at` NULL=permanent / future=timeout-auto-restore, partial-unique on active
  `(domain, user_subject, access_type)`, domain-scoped.
- **`TubeAccessGuard.assertCanUse`** — the LOAD-BEARING, **DEFAULT-DENY** enforcement:
  SUPERADMIN short-circuits ALLOW (exempt from ban); otherwise load the principal's
  active non-expired `tube_access` rows for their brand; an active BAN denies even a
  grantee (precedence **ban > grant**); else ALLOW iff an active `use` grant exists;
  else **403**. The base `ROLE_TUBE` is the gateway route-access floor + the
  connect/view-own surface — it does NOT by itself confer use; an admin's `use` grant
  is the only thing that lifts a user above the default-deny floor.
- **`TubeAccessController`** —
  `/bff/tube/admin/access` grant/timeout/ban/restore (ADMIN | SUPERADMIN) +
  `/bff/tube/superadmin/access` list/history (SUPERADMIN).
- **`ROLE_TUBE`** — the base service role (sibling of `ROLE_OWNCAST` / `ROLE_WIKI` /
  `ROLE_FORUM`).

## Role model

- **SUPERADMIN** — `TUBE_MANAGE`; service enable per-domain (+GPU-node check);
  cross-domain; exempt from ban.
- **ADMIN (own brand)** — `TUBE_GOVERN`: grant/timeout/ban/restore may-use (quota /
  retention / allow-deny-users / cadence are the wider PR4/PR8 admin surface).
- **MOD** — moderation lives in mod-bff (`tube.*` ModActionType, later PR) via the
  derived `ROLE_TUBE_MOD` (MOD ∩ TUBE).
- **USER** — `ROLE_TUBE` + a `use` grant (default-deny): connect Google + view-own
  (owner-scoped). Google-connect / subs-sync / yt-dlp download / owner-private viewing
  are PR3–PR5.

DEFAULT-OFF (ships dark), GPU-pinned (x86 + GPU). The `tube_google_link` +
`tube_subscription` + `tube_download_job` + `tube_storage_usage` tables, the downloader
CronJob, the media-serving sidecar, the `snapdragon-tube-ui` remote, and the generator
devops land in later PRs (PR3–PR9).

Build + test: `./mvnw -DskipITs test`. CI = GitLab (`.gitlab-ci.yml`).
