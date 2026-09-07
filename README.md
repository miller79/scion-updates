# scion-updates

Notes from running [**Scion**](https://github.com/GoogleCloudPlatform/scion) inside a big
enterprise, written up for the maintainers.

We got it working — but hit a fair number of snags along the way, mostly in places that only
show up when you're not deploying to a fresh public-internet VM. Rather than let that
knowledge evaporate, it's all here with file references so it's easy to act on.

Everything is **re-verified against current `main` after every upgrade**, not written from
memory. Most recently at `8f66d97d` (2026-09-07), across eight rounds of pulls — and this time
against a **live hub upgraded to that commit**, not just its source. Twelve of the original 44
are now fixed; four of those by patches we contributed. Each item is marked per-issue:
`RESOLVED`, `OBSOLETE`, `PARTIALLY RESOLVED`, `CONFIRMED still present`, or
`NOT REPRODUCIBLE` where our own configuration no longer triggers it.

## The short version

Scion's `scripts/starter-hub/` assumes it's provisioning its own demo VM with a public IP,
Cloud DNS, and Let's Encrypt. Our reality: a pre-existing internal host, no public IP,
IAP-only SSH, corporate package mirrors, DNS managed by a network team, narrow
service-account scopes, and TLS handled by an F5.

Four of the six deploy steps didn't apply. It all worked in the end, but a number of these are
genuine bugs rather than just "enterprise is different" — including several security ones.

**Take these and run with them.** Copy anything into issues, commits, or PRs — no
attribution needed, no need to ask.

## How this repo is laid out

| | |
|---|---|
| [**FINDINGS.md**](FINDINGS.md) | The canonical numbered list. This is the one to act on — findings cross-reference each other, so they live in one place and get corrected in place. |
| [**updates/**](updates/) | A dated entry per working day: what we did, what we found, what we got wrong. |
| [**role-model-proposal/**](role-model-proposal/) | A target-state proposal for roles and permissions — not a description of current behaviour. |
| [**docker-support-proposal/**](docker-support-proposal/) | How agents could run containers (Testcontainers, buildpacks) without granting host root — including a working reference implementation we run today. |

Latest: [**2026-09-07**](updates/2026-09-07.md) — upgrading the hub to `8f66d97d` and retesting
everything against it; four of our own fixes are now upstream and six more issues retired.

## Fixed since we started reporting

Credit where it's due — these moved:

| # | Issue | Fixed in |
|---|---|---|
| 11 | Local secrets backend stored plaintext while a comment claimed writes were rejected | `af102183` (#1253) — AES-256-GCM at rest, and the misleading comment corrected |
| 5 | OIDC guide overstated HTTPS as a prerequisite | The published guide omits the claim |
| 16 | Every authenticated user could read every project — the open-by-default wildcard | `fd818e08` — hub-member/hub-viewer rebuilt as curated lists excluding `project.read`/`list` at system scope, guarded by `TestGolden_CrossProjectVisibilityRegression` |
| 17 | `viewer` role selectable but identical to `member` | `fd818e08` — `hub-viewer` is now a distinct curated read-only role |
| 18 | Project membership conferred no project visibility | `fd818e08` — `projectMemberPermissionIDs()` now grants project `read`/`list` |
| 9 | The image build could not use an internal package registry | `8f66d97d` - our PR merged (miller79/scion#13). **pip still uncovered**, so `hermes` remains unbuildable behind a PyPI-blocking proxy |
| 15 | Provision script granted `logging.viewer` but not `monitoring.viewer` | `8f66d97d` - our PR merged (miller79/scion#17) |
| 33 | Clone credentials injected via `strings.Replace`, corrupting URLs with userinfo | `8f66d97d` - our PR merged (miller79/scion#2), with an added `Scheme == "https"` guard after review caught our patch injecting tokens into `ssh://` remotes |
| 36 | Terminal link in the chat members sidebar forced a new browser tab | `8f66d97d` - our PR merged (miller79/scion#22) |
| 34 | A project-scoped `GITHUB_TOKEN` could never authenticate the initial clone | `8f66d97d` - the token is now written as a project secret before `cloneSharedWorkspaceProject` |
| 6 | Dev-auth cleanup targeted the wrong username | **Obsolete** - `scion@localhost` is gone from the sources; the dev user is keyed by `DevUserID` UUID |
| 3 | `default_runtime` dead config key | Gone from `pkg/config` as of `2b8be982` (confirmed by search, not exercised) |

`feb3e188` (#1250) also tightened `isProjectOwnerOrAdmin` to check only the canonical project
members group, closing an escalation where owning *any* explicit group in a project conferred
project-owner rights.

## Where these now live

At Preston's suggestion these are being filed as issues on
**[miller79/scion](https://github.com/miller79/scion/issues)**, a fork he can merge from
directly. **26 are filed and open** (see the *Filed* column below), plus four filed and since
closed by merged fixes. This repo stays as the narrative record — the daily entries, the
reasoning, and the wrong turns — while the fork carries the actionable items.

The remaining **6** are marked **_held_**: 24, 25, 28, 29, 30 and 31. Each needs a test we
cannot run non-invasively on a hub other people are using — creating and deleting projects,
spawning progeny agents, turning the message broker off, or driving the UI as a non-admin.
Two of them (29 and 30) we specifically **could not reproduce** at `8f66d97d` because our own
configuration no longer triggers them, which is not the same as them being fixed. They stay
unfiled rather than asserted on evidence we do not have.

## What's still open

Full write-up: [**FINDINGS.md**](FINDINGS.md)
(deployed and re-verified at `8f66d97d`, Ubuntu 24.04, Keycloak SSO, TLS via BIG-IP)

| # | Issue | Severity | Effort | Filed |
|---|---|---|---|---|
| 31 | Progeny agents still get no credentials after the #1292 fix — **three** further blockers, incl. `resolveSecrets` returning `count=0` with ancestry present | 🔴 **Security** | Low | _held_ |
| 35 | Delete a git project and recreate it with the same name, and every agent creation fails — the on-disk marker still points at the deleted project | 🔴 Blocking | Trivial | [#28](https://github.com/miller79/scion/issues/28) |
| 45 | No protected or break-glass admin — `AdminEmails` is authoritative and all-or-nothing, so an edit naming one user silently demotes another on the next restart | 🟠 High | Low [#35](https://github.com/miller79/scion/issues/35) |
| 44 | Every agent in a **non-git** project shares one workspace directory — no per-agent mode exists, `workspaceMode` is silently dropped, and agents overwrite each other's files. Also: no way to run an agent without a project at all | 🟠 High | Low | [#9](https://github.com/miller79/scion/issues/9) |
| 43 | A project's git branch is write-once at creation — no UI to change it, and the `PATCH` that could silently wipes the project's clone URL along with it | 🟠 High | Low | [#8](https://github.com/miller79/scion/issues/8) |
| 42 | A chat message containing `<template>` renders truncated — everything after it silently disappears, though copy-paste still yields the full text | 🟠 High | Trivial | [#10](https://github.com/miller79/scion/issues/10) |
| 38 | `profiles.<name>.env` was deliberately removed from both resolvers, but the field is still in `ProfileConfig` — the key parses and is silently ignored rather than rejected | 🟠 High | Trivial | [#11](https://github.com/miller79/scion/issues/11) |
| 39 | Agents are sibling containers to the Docker daemon — host-path bind mounts silently mount an **empty directory** instead of failing | 🟠 High | Low | [#30](https://github.com/miller79/scion/issues/30) |
| 37 | `git-sandbox` skill never injected into clone-per-agent workspaces — its condition reuses a boolean that means "don't make worktrees here" — and its content claims an air-gap that does not exist | 🟠 High | Medium | [#29](https://github.com/miller79/scion/issues/29) |
| 40 | File secrets are also injected as an env var holding the same bytes — any subprocess of the agent (build script, npm postinstall, test) can read every secret | 🔴 **Security** | Low | [#7](https://github.com/miller79/scion/issues/7) |
| 41 | Anything an agent prints persists in the message store **and** the host journal, credentials included, with no redaction and no way to retract | 🔴 **Security** | Low | [#31](https://github.com/miller79/scion/issues/31) |
| 13 | `--session-secret` in the systemd template leaks the signing secret into `ps` — and now also undermines 11's encryption-at-rest fix, which derives its key from it | 🔴 **Security** | Trivial | [#1](https://github.com/miller79/scion/issues/1) |
| 21 | Secret Manager values are rewritten to SQLite in cleartext on every boot; the signing keys bypass 11's encryption entirely | 🔴 **Security** | Low | [#5](https://github.com/miller79/scion/issues/5) |
| 20 | `hub_id` derives from the hostname; a hostname change silently re-namespaces every secret | 🔴 **Security** | Low | [#4](https://github.com/miller79/scion/issues/4) |
| 22 | Signing keys derive from `SESSION_SECRET`; rotation is undocumented and leaves superseded versions enabled | 🟠 **Security** | Low | [#6](https://github.com/miller79/scion/issues/6) |
| 24 | Harness-config files unreachable in both broker resolution paths break every agent start, while `/healthz` reports healthy | 🔴 Blocking | Low | _held_ |
| 2 | `gce-start-hub.sh` does `git push origin main`, which nobody outside the repo can do | 🔴 Blocking | Low | [#3](https://github.com/miller79/scion/issues/3) |
| 4 | The OIDC guide gives a redirect URI route that doesn't exist | 🔴 Blocking | Trivial | [#20](https://github.com/miller79/scion/issues/20) |
| 25 | Create Project shows a permission error to every non-admin on page load, before they touch anything | 🟠 High | Trivial | _held_ |
| 28 | Metrics dashboard is reachable by non-admins but its endpoint is admin-only — repeating 403s and permission toasts on a timer | 🟠 High | Trivial | _held_ |
| 30 | Chat is on by default but its store is only created when the message broker is enabled — UI renders, every send 503s, and the fix key is absent from the settings schema | 🟠 High | Low | _held_ |
| 29 | Agent telemetry is on by default, can never authenticate without a registered service account, and retries forever at `INFO` | 🟠 High | Low | _held_ |
| 26 | No way to hide an unused harness, and `harness-config delete` silently reverts on restart | 🟠 High | Low | [#32](https://github.com/miller79/scion/issues/32) |
| 14 | Settings template misses `telemetry.cloud.gcp_project_id`, so the metrics dashboard is dead | 🟠 High | Trivial | [#16](https://github.com/miller79/scion/issues/16) |
| 12 | `SCION_HUB_ENDPOINT` in `hub.env.sample` isn't wired to anything | 🟠 High | Trivial | [#15](https://github.com/miller79/scion/issues/15) |
| 1 | Go pinned to 1.23.0 vs `go.mod` 1.26.1 — usually masked by `GOTOOLCHAIN=auto`, breaks air-gapped builds | 🟠 High | Low | [#12](https://github.com/miller79/scion/issues/12) |
| 8 | Unknown `settings.yaml` keys vanish with no warning | 🟠 High | Low | [#19](https://github.com/miller79/scion/issues/19) |
| 7 | No real path for internal-only / bring-your-own-cert / IAP setups | 🟠 High | Medium | [#34](https://github.com/miller79/scion/issues/34) |
| 23 | The same config field is spelled `gcp_project_id` or `gcpProjectId` depending on where you set it; the wrong one is silently dropped | 🟡 Medium | Low | [#18](https://github.com/miller79/scion/issues/18) |
| 27 | Image build can only target groups, so one unbuildable image blocks unrelated ones | 🟡 Medium | Low | [#14](https://github.com/miller79/scion/issues/14) |
| 19 | No way to import a template except from a URL or server-side files — no zip upload *(feature request)* | 🟡 Low | Low | [#33](https://github.com/miller79/scion/issues/33) |
| 32 | Agents cannot create a chat thread — every chat endpoint is user-identity-only, so an orchestrator can't give its team a home *(feature request)* | 🟡 Low | Medium | [#21](https://github.com/miller79/scion/issues/21) |
| 10 | Small stuff: no `--version` alias, NATS still installed, a placeholder registry that looks real | 🟡 Low | Low | [#23](https://github.com/miller79/scion/issues/23) |

**If you only look at three:**

**31** first, because it is live work — the `hasAnyKey` fix in #1292 is correct and deployed
here, and progeny agents still get no credentials. Three conditions sit behind it, one of them
a one-line prefix mismatch. Worth seeing before #1252 is closed.

**13** is a one-line fix that now also protects the new encryption at rest.

**30** is the cheapest win: chat ships enabled with a nil store whenever the message broker is
off, so it renders fully and 503s on every send — and the key that fixes it is absent from the
settings schema.

A pattern worth naming across several of these: **the hub reports healthy while a feature is
completely non-functional**. Agent creation (24), chat (30), telemetry (29) and progeny
credentials (31) all fail silently with `/healthz` at 200. In each case a single startup-time
WARN naming the missing prerequisite would have saved hours.

There's a **"What worked well"** section in there too — the list above is all complaints,
which isn't a fair picture. `/healthz`, the fail-fast OIDC validation, and the secrets
authorization model were all genuinely nice to work with.

## On the verification

Worth saying, since "we found 44 items" is easy to write and harder to trust:

- Everything cites the specific file, usually the function
- Behaviour was checked against the source rather than guessed from symptoms
- We re-check every open item after each upgrade, and record what got fixed as readily as what
  didn't — see "Fixed since we started reporting" above
- Claims we got wrong are **corrected in place**, with the evidence that disproved them. The
  Go-version mismatch was overstated in an early draft; the three-day outage in issue 24 was
  attributed to two different wrong causes before the right one, and the daily entry records
  that sequence rather than presenting the final answer as if it had been obvious. On
  2026-08-25 we spent half an hour convinced a set of 404s was a deliberate policy blocking AI
  CLI packages; a cold-cache control test disproved it, and the write-up leads with the wrong
  turn rather than burying it
- Where a test turned out to be **inconclusive**, we said that instead of claiming a result
- For issue 16 we went further and **tested a candidate fix on a live hub**, with before/after
  numbers and an explicit note on what we did and did not exercise
- Issue 18 was re-confirmed on a brand-new project created by a non-admin on the current build

## The environment

Generalised — no internal hostnames or addresses in here.

| | |
|---|---|
| Platform | GCE, Ubuntu 24.04 LTS |
| Network | Shared VPC, no external IP, IAP-only SSH |
| TLS | Terminated upstream by an F5 BIG-IP |
| Identity | Keycloak OIDC, public client, Kerberos/SPNEGO realm |
| Secrets | GCP Secret Manager backend, dedicated least-privilege service account |
| Storage | GCS bucket, hub-namespaced |
| Packages | Corporate Artifactory mirrors, public registries blocked |
| Scion | `main` @ `90bf246e`, re-verified at `1b3c9418`, `1933d359`, `89ed0fe8`, `2b8be982`, `aedf89ed`, `fd818e08`, and `8f66d97d` |

## Questions

Open an issue here and I'll answer. Happy to pull logs, share more config, or test a fix
against our setup — we've got a working internal deployment to try things on.

— Anthony Lofton
