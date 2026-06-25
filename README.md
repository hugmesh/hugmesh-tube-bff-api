# snapdragon-tube-bff-api

Tube BFF — the access-governance + control plane for the **LocalTube** video OPTIONAL
SERVICE (self-hosted personal YouTube archival: a user connects Google, their subscribed
channels sync to a DB, and yt-dlp downloads new videos on a schedule for owner-private
in-platform viewing). Twin of `snapdragon-owncast-bff-api` / `snapdragon-wiki-bff-api`
(Java 25 WebFlux + R2DBC Postgres + Liquibase + Casdoor JWT resource server, package
`systems.snapdragon.tubebff`, artifact `tube-bff` 0.1.0, Spring Boot 4.0.7).

> **State convention:** ✅ shipped (on `main`) · 🚧 in-flight (open branch/PR) ·
> 🔭 planned (design only, no code in this repo). See the
> [Roadmap / not yet in this repo](#roadmap--not-yet-in-this-repo) section.

## Current State

As of 2026-06-24 this BFF sits on the unified Snapdragon ecosystem baseline:

- **Spring Boot 4.0.7 / Spring Cloud 2025.1.2, Java 25 LTS, WebFlux reactive.** The build is
  a child of the org metapom **`snapdragon-parent` 2.7.0** (which itself rides Boot 4), so
  the reactive-BFF dependency + plugin baseline is inherited, not duplicated here.
- **Shared security/tenancy via `snapdragon-commons` 2.0.0** (`systems.snapdragon.commons.*`).
  This BFF's former local copies of `security.{Roles,CasdoorAuthorities,DomainRegistry,DomainScope}`,
  `config.TenancyResourceServerConfig` and `web.ApiException` were deleted and now come
  from commons (version managed by the parent). This BFF does **not** depend on
  `snapdragon-auth-core` — that artifact carries account/session/MFA/Casdoor-admin infra
  and is consumed only by `user-bff` + `admin-bff`; tube-bff owns no login/session/account
  surface (it only connects Google for `youtube.readonly` on behalf of an
  already-authenticated principal).
- **Place in the auth model.** tube-bff is a pure **downstream Casdoor-JWT OAuth2 resource
  server** reached only through the gateway. The browser holds an OPAQUE `bff_`-prefixed
  session and never its Casdoor JWT; the gateway's pre-security exchange filter swaps
  `bff_` → the internal custody JWT before proxying, so this BFF always receives a normal
  validated Casdoor JWT and its authorities/issuer→domain logic runs unchanged. The
  platform's login/session relocation (admin-bff → user-bff) and the auth-core extraction
  do **not** touch this repo. Authorization upstream is data-driven by the gateway's
  `gateway_route_access` table; the base `ROLE_TUBE` row is the route-access floor before
  any handler here runs.
- **Data access** is Spring Data R2DBC reactive repositories (Liquibase migrates over a
  JDBC datasource; runtime is R2DBC) — no raw SQL strings / inline `@Query`.
- **CI is GitLab** (`.gitlab-ci.yml`); there are **no** GitHub Actions. The GitHub repo is
  pull-mirrored into in-cluster GitLab.

Functionally, everything in [Capabilities](#capabilities-what-is-on-main) (the access
overlay, Google OAuth connect, download queue, signed media URLs + the GitLab pentest stage)
is ✅ shipped on `main`; the byte plane (tube-media sidecar), the yt-dlp runner, the
tube-ui remote and the wider admin quota/retention surface remain 🔭 external / planned
(see below).

## What this BFF owns

This service is the **control plane** for the tube service — it owns the may-use
governance overlay PLUS the user-facing connect/list/queue/sign surfaces. It does NOT
serve media bytes and does NOT run yt-dlp. Concretely, on `main` today this BFF owns:

- ✅ the `tube_access` **governance overlay** — the per-principal may-use grant/timeout/ban
  table an ADMIN curates on top of the base `ROLE_TUBE` role;
- ✅ the **Google OAuth link** (`youtube.readonly`) + the **subscription mirror** — the
  refresh token is stored only as an AES-256-GCM ciphertext (no plaintext column);
- ✅ the **download work-queue** + **per-user storage budgets** — the
  queued→claimed→downloading→done/failed/skipped state machine, dedup, and
  claim/report endpoints;
- ✅ the **media-URL signing** surface — short-TTL HMAC-signed URLs that authorise a
  byte fetch (owner two-wall enforced here).

The media **bytes** are still served by a separate per-domain tube-media Nginx sidecar
(🔭 not in this repo) over a `be-gateway /tube/content/**` route, and the yt-dlp runner
image + polling CronJob that drain the work-queue are still external (🔭 not in this
repo) — see [Roadmap](#roadmap--not-yet-in-this-repo). What lives HERE are the queue +
claim/report + signed-URL **control** surfaces, not the byte plane or the downloader.

### Request flows

The browser→governance/control path (everything `/bff/tube/**` is THIS BFF, behind the
`fe-gateway`):

```mermaid
flowchart LR
    browser["browser"]
    fe["fe-gateway<br/>/bff/tube/**"]
    bff["tube-bff (this repo)"]
    pg[("tube_access / tube_google_link /<br/>tube_subscription / tube_download_job /<br/>tube_storage_usage")]

    browser --> fe --> bff --> pg
```

The media **byte** path is a two-step signed flow — the signing hop is a call to THIS
BFF first, then the byte fetch goes to the separate sidecar:

```mermaid
flowchart LR
    browser["browser"]
    fe["fe-gateway<br/>/bff/tube/media/sign"]
    bff["tube-bff (this repo)<br/>owner two-wall + HMAC sign"]
    be["be-gateway<br/>/tube/content/**"]
    sidecar["tube-media Nginx sidecar<br/>(per-domain content PVC)<br/>verifies HMAC / exp / sub / domain"]

    browser -->|"1: GET /bff/tube/media/sign?path=..."| fe --> bff
    bff -.->|"returns signed<br/>/tube/content/&lt;domain&gt;/&lt;subject&gt;/...<br/>?sig=&amp;exp=&amp;sub=&amp;domain="| browser
    browser -->|"2: GET /tube/content/... (range/HLS)"| be --> sidecar

    classDef planned stroke-dasharray:4 3
    class be,sidecar planned
```

> Nodes drawn with a dashed border (`be-gateway /tube/content` route + the tube-media
> sidecar) are 🔭 **planned** — not in this repo. The signing hop (`/bff/tube/media/sign`)
> is ✅ shipped here.

## Capabilities (what is on `main`)

| Area | Status | Package | Notes |
|------|--------|---------|-------|
| `tube_access` overlay + `TubeAccessGuard` (default-deny) | ✅ shipped | `access` | grant/timeout/ban/restore; ban > grant; SUPERADMIN ban-exempt |
| Google OAuth connect + subscriptions sync | ✅ shipped | `google` | `youtube.readonly`; refresh token AES-256-GCM at rest via `TokenCipher` |
| Signed short-TTL HMAC media URLs + owner two-wall | ✅ shipped | `media` | signs `/tube/content/...` URLs; the public `/bff/tube/media/verify` `auth_request` endpoint for the sidecar is ✅ shipped |
| Download work-queue + storage budgets | ✅ shipped | `download` | claim/report state machine; per-user budget cap |
| GitLab CI: test → build:image → pentest | ✅ shipped | — | SCA + ZAP DAST baseline (incl. nuclei) via the shared harness; `make pentest` mirrors it |

## API surface (route groups)

All routes are mounted under `/bff/tube` (reached only through the `fe-gateway`; the base
`ROLE_TUBE` gateway route-access is the floor before any of these handlers run).

**Access governance** — `access/TubeAccessController`
- `POST /bff/tube/admin/access/grant` · `.../timeout` · `.../ban` (ADMIN | SUPERADMIN, own-brand)
- `DELETE /bff/tube/admin/access/{accessType}/{userSubject}` — restore (ADMIN | SUPERADMIN)
- `GET /bff/tube/superadmin/access` — list (SUPERADMIN)
- `GET /bff/tube/superadmin/access/{userSubject}/history` (SUPERADMIN)

**Google connect + subscriptions** — `google/GoogleConnectController`, `google/TubeSubscriptionsController`
- `GET /bff/tube/google-connect/{status,authorize,callback}` · `POST /bff/tube/google-connect/disconnect`
- `GET /bff/tube/subscriptions` · `POST /bff/tube/subscriptions/sync`
  (authenticated + a live `use` grant; SUPERADMIN exempt)

**Media signing** — `media/TubeMediaController`
- `GET /bff/tube/media/sign` — authenticated; owner two-wall (path `sub` must equal the
  caller's JWT subject and brand) → returns a signed `/tube/content/<domain>/<subject>/...`
  URL + `expiresAt`
- `GET /bff/tube/media/verify` — **PUBLIC** (`permitAll`), the tube-media nginx sidecar's
  `auth_request` target; carries NO JWT (the HMAC signature minted by `/sign` is the sole
  credential). Fail-closed + non-leaking: `200` only for a valid, unexpired signature over
  the exact `(sub, domain, path, exp)` tuple, `403` (empty body) for every other case

**Downloads + budgets** — `download/TubeDownloadController`, `download/TubeDownloadWorkerController`, `download/TubeStorageBudgetController`
- `GET /bff/tube/downloads` · `POST /bff/tube/downloads` — authenticated (owner-scoped enqueue/list)
- `POST /bff/tube/internal/download-jobs/{claim,report}` — **`ROLE_TUBE_WORKER` only**
  (a service/mTLS principal for the future yt-dlp CronJob; deliberately OUTSIDE the
  human role hierarchy — no USER/MOD/ADMIN/SUPERADMIN reaches it)
- `POST /bff/tube/admin/storage-budget` — set a user's storage budget cap (ADMIN | SUPERADMIN, own-brand)

## The `tube_access` overlay + `TubeAccessGuard`

The use grant/timeout/ban overlay was cloned EXACTLY from the owncast-bff `owncast_grant`
(004) overlay (which itself cloned the wiki-bff `wiki_access`), swapping `broadcast` → `use`:

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
- **`ROLE_TUBE`** — the base service role (sibling of `ROLE_OWNCAST` / `ROLE_WIKI` /
  `ROLE_FORUM`).

## Role model

- **SUPERADMIN** — `TUBE_MANAGE`; service enable per-domain (+GPU-node check);
  cross-domain; exempt from ban.
- **ADMIN (own brand)** — `TUBE_GOVERN`: grant/timeout/ban/restore may-use + set storage
  budgets (✅). The wider quota / retention / allow-deny-users / cadence admin surface is
  🔭 planned (see [Roadmap](#roadmap--not-yet-in-this-repo)) — only the storage-budget `POST` is shipped today.
- **MOD** — 🔭 moderation lives in mod-bff (`tube.*` ModActionType, later PR) via the
  derived `ROLE_TUBE_MOD` (MOD ∩ TUBE); not in this repo.
- **USER** — `ROLE_TUBE` + a `use` grant (default-deny): connect Google + sync
  subscriptions + enqueue/list owner-scoped downloads + obtain owner-scoped signed media
  URLs (✅).
- **`ROLE_TUBE_WORKER`** — a non-human service/mTLS principal (the future yt-dlp CronJob)
  that may claim/report download jobs ONLY; deliberately outside the human role hierarchy.

## Schema (Liquibase changelogs on `main`)

Liquibase runs over a JDBC datasource (Liquibase has no R2DBC runner); all runtime data
access goes through R2DBC. Numbering starts at 004 to match the `owncast_grant` /
`wiki_access` (004) overlay this is cloned from (001–003 in wiki-bff are the wiki content
store, which tube has no analogue of — use is grant-only). Mirrors the comment block in
`db.changelog-master.xml`:

- **004 `tube-access`** — the use grant/timeout/ban overlay.
- **005a `tube-google-link`** — `tube_google_link`: per-(brand,user) Google OAuth
  `youtube.readonly` connection; refresh token stored only as AES-256-GCM ciphertext
  (`refresh_token_ciphertext = base64(iv||ct||tag)`), partial-UNIQUE on the live row,
  soft-revoke=audit.
- **005b `tube-download-queue`** — `tube_download_job` (the queued→claimed→downloading→
  done/failed/skipped work-queue + dedup + claim/report) + `tube_storage_usage`
  (per-user budget accounting).
- **006 `tube-subscription`** — `tube_subscription`: per-(brand,user) mirror of subscribed
  YouTube channels, `UNIQUE(domain, user_subject, channel_id)`.
- **007 `tube-subscription-download-fields`** — adds `latest_video_id`,
  `latest_video_title`, `created_at`, `updated_at` so the work-queue can use
  `tube_subscription` as its enqueue source.
- **008 `db-generated-uuid-pks`** — moves the `varchar(64)` UUID primary keys of
  `tube_access` / `tube_download_job` / `tube_google_link` / `tube_subscription` from
  app-minted (`UUID.randomUUID().toString()`) to DB-generated column DEFAULTs
  (`(gen_random_uuid())::text`, with `pgcrypto` installed defensively); inserts omit `id`
  and read it back via `RETURNING id` (adopts the mod-bff #36 / admin-bff #133 pattern, PR #23).

## CI

CI = GitLab (`.gitlab-ci.yml`). The GitHub repo is pull-mirrored into in-cluster GitLab
(`mirror_trigger_builds=true`), so the pipeline runs on push / mirror-sync. Stages:

- **`test:unit`** — `./mvnw -B -DskipITs test` (unit/slice tests; keeps a broken
  overlay/guard from shipping an image).
- **`build:image`** — builds + pushes the container image on the privileged x86 runner
  (immutable SHA/tag + a moving branch tag). Images carry NO keys.
- **`pentest`** — ✅ the continuous-OWASP stage per the platform pen-test standard:
  `pentest:sca` (OWASP Dependency-Check SCA) + `pentest:dast` (authenticated ZAP DAST
  baseline incl. nuclei probes), both `extends:` the centralized `.pentest-*` hidden jobs
  in `snapdragon-generator`'s `tests/pentest/ci/pentest-stage.gitlab-ci.yml`. Currently
  `allow_failure: true` (report-and-fix posture). `make pentest` runs the same
  SCA + DAST self-scan locally.

> k6 load testing is part of the platform pen-test standard but is not wired into THIS
> repo's pipeline yet (SCA + DAST baseline are).

Build + test locally: `./mvnw -DskipITs test`.

## Roadmap

This repo tracks the platform's tube-service slice of the wider Snapdragon roadmap. The
immediate, repo-local follow-ups are enumerated under
[Roadmap / not yet in this repo](#roadmap--not-yet-in-this-repo) below. Platform-wide
initiatives this BFF will plug into as they land: SSO-end-to-end-live (the gateway
`bff_`-session exchange this BFF already sits behind), MFA / step-up for privileged tube
governance ops, encrypted versioned backups of the tube data + content PVC, per-node
attached storage for the GPU host that runs the byte plane, and the multi-tenancy
superadmin (per-domain enable of the tube optional service). A/V-adjacent media remains
LAN-only until the platform TURN/SFU work lands; tube serves owner-private archived bytes,
not live A/V.

## Roadmap / not yet in this repo

DEFAULT-OFF (ships dark), GPU-pinned (x86 + GPU). The following are 🔭 planned /
🚧 in-flight and are NOT shipped in this repo — this BFF owns the control surfaces they
plug into, but the components themselves live elsewhere:

- 🔭 **yt-dlp downloader runner image + generator-gated polling CronJob** that drains the
  `tube_download_job` work-queue via the `ROLE_TUBE_WORKER` claim/report endpoints. The
  queue + claim/report + storage budgets are ✅ shipped here; the runner/CronJob are a
  deferred follow-up.
- 🔭 **tube-media Nginx serving sidecar + `be-gateway /tube/content/**` route** that
  verifies the HMAC-signed URLs this BFF issues (via a `auth_request` to
  `/bff/tube/media/verify`). The signing AND the public `/verify` `auth_request` endpoint
  are ✅ shipped here; the byte-serving sidecar that calls `/verify` is an external component.
- 🔭 **`snapdragon-tube-ui` native-federation remote** (DB-hosted federated Angular
  module) consuming these BFF endpoints.
- 🔭 **Generator devops for the tube optional service** — the deployment story:
  DEFAULT-OFF / ships-dark, GPU-pinned (x86 + GPU) per-domain enable gated on a
  superadmin `TUBE_MANAGE` + a GPU-node check.
- 🔭 **mod-bff tube moderation surface** — `tube.*` ModActionType + the derived
  `ROLE_TUBE_MOD` (MOD ∩ TUBE); lands in mod-bff, not here.
- 🔭 **Wider admin surface** — quota / retention / allow-deny-users / cadence
  governance. Only the storage-budget `POST` is shipped today.
- 🚧 **Notifications EXTERNAL channels** (platform-wide, in-flight) — Matrix DM / Akkoma
  feed / phpBB / email adapters on top of the in-app notifications MVP; the tube service
  would emit account/infra events through that subsystem.
