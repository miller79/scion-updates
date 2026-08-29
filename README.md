# scion-updates

Notes from running [**Scion**](https://github.com/GoogleCloudPlatform/scion) inside a big
enterprise, written up for the maintainers.

We got it working — but hit a fair number of snags along the way, mostly in places that only
show up when you're not deploying to a fresh public-internet VM. Rather than let that
knowledge evaporate, it's all here with file references so it's easy to act on.

Everything is **re-verified against current `main` after every upgrade**, not written from
memory. Most recently at `aedf89ed`, across six rounds of pulls.

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

Latest: [**2026-08-25**](updates/2026-08-25.md) — rebuilding every container image behind a
corporate proxy, and half an hour spent believing a 404 was a policy decision.

## Fixed since we started reporting

Credit where it's due — these moved:

| # | Issue | Fixed in |
|---|---|---|
| 11 | Local secrets backend stored plaintext while a comment claimed writes were rejected | `af102183` (#1253) — AES-256-GCM at rest, and the misleading comment corrected |
| 16 | Deleting a seeded policy silently reverted on restart | `65482def` (#1254) — `Origin` field plus deletion tombstones. **The open-by-default wildcard itself is unchanged** |
| 3 | `default_runtime` dead config key | Gone from `pkg/config` as of `2b8be982` (confirmed by search, not exercised) |

`feb3e188` (#1250) also tightened `isProjectOwnerOrAdmin` to check only the canonical project
members group, closing an escalation where owning *any* explicit group in a project conferred
project-owner rights.

## What's still open

Full write-up: [**FINDINGS.md**](FINDINGS.md)
(deployed `main` @ `aedf89ed`, Ubuntu 24.04, Keycloak SSO, TLS via BIG-IP)

| # | Issue | Severity | Effort |
|---|---|---|---|
| 31 | Progeny agents still get no credentials after the #1292 fix — **three** further blockers, incl. `resolveSecrets` returning `count=0` with ancestry present | 🔴 **Security** | Low |
| 35 | Delete a git project and recreate it with the same name, and every agent creation fails — the on-disk marker still points at the deleted project | 🔴 Blocking | Trivial |
| 33 | Clone credentials injected via `strings.Replace` — any remote whose URL carries a username (e.g. every Azure DevOps clone URL) gets a corrupted token and a misleading "repo not found" | 🔴 Blocking | Trivial |
| 34 | A project-scoped `GITHUB_TOKEN` can never authenticate the initial clone — the clone runs during project creation, and there is no retry | 🟠 High | Low |
| 13 | `--session-secret` in the systemd template leaks the signing secret into `ps` — and now also undermines 11's encryption-at-rest fix, which derives its key from it | 🔴 **Security** | Trivial |
| 21 | Secret Manager values are rewritten to SQLite in cleartext on every boot; the signing keys bypass 11's encryption entirely | 🔴 **Security** | Low |
| 20 | `hub_id` derives from the hostname; a hostname change silently re-namespaces every secret | 🔴 **Security** | Low |
| 16 | Every authenticated user can read every project by default — `visibility: private` is inert | 🔴 **Security** | Low |
| 17 | The `viewer` role is selectable but never enforced — identical to `member` | 🔴 **Security** | Low |
| 18 | Project membership grants agent create/stop but **not** read — so fixing 16 hides projects from their own members | 🔴 **Security** | Low |
| 22 | Signing keys derive from `SESSION_SECRET`; rotation is undocumented and leaves superseded versions enabled | 🟠 **Security** | Low |
| 24 | Harness-config files unreachable in both broker resolution paths break every agent start, while `/healthz` reports healthy | 🔴 Blocking | Low |
| 2 | `gce-start-hub.sh` does `git push origin main`, which nobody outside the repo can do | 🔴 Blocking | Low |
| 4 | The OIDC guide gives a redirect URI route that doesn't exist | 🔴 Blocking | Trivial |
| 25 | Create Project shows a permission error to every non-admin on page load, before they touch anything | 🟠 High | Trivial |
| 28 | Metrics dashboard is reachable by non-admins but its endpoint is admin-only — repeating 403s and permission toasts on a timer | 🟠 High | Trivial |
| 30 | Chat is on by default but its store is only created when the message broker is enabled — UI renders, every send 503s, and the fix key is absent from the settings schema | 🟠 High | Low |
| 29 | Agent telemetry is on by default, can never authenticate without a registered service account, and retries forever at `INFO` | 🟠 High | Low |
| 26 | No way to hide an unused harness, and `harness-config delete` silently reverts on restart | 🟠 High | Low |
| 14 | Settings template misses `telemetry.cloud.gcp_project_id`, so the metrics dashboard is dead | 🟠 High | Trivial |
| 15 | Provision script grants `logging.viewer` but not `monitoring.viewer` | 🟠 High | Trivial |
| 12 | `SCION_HUB_ENDPOINT` in `hub.env.sample` isn't wired to anything | 🟠 High | Trivial |
| 1 | Go pinned to 1.23.0 vs `go.mod` 1.26.1 — usually masked by `GOTOOLCHAIN=auto`, breaks air-gapped builds | 🟠 High | Low |
| 5 | The OIDC guide says HTTPS is required — it isn't | 🟠 High | Trivial |
| 8 | Unknown `settings.yaml` keys vanish with no warning | 🟠 High | Low |
| 7 | No real path for internal-only / bring-your-own-cert / IAP setups | 🟠 High | Medium |
| 23 | The same config field is spelled `gcp_project_id` or `gcpProjectId` depending on where you set it; the wrong one is silently dropped | 🟡 Medium | Low |
| 6 | Dev-auth cleanup command deletes the wrong username (so, nothing) | 🟡 Medium | Trivial |
| 9 | The image build cannot be pointed at an internal package registry — behind one, **no image builds at all**. Patch available | 🟠 High | Low |
| 27 | Image build can only target groups, so one unbuildable image blocks unrelated ones | 🟡 Medium | Low |
| 19 | No way to import a template except from a URL or server-side files — no zip upload *(feature request)* | 🟡 Low | Low |
| 32 | Agents cannot create a chat thread — every chat endpoint is user-identity-only, so an orchestrator can't give its team a home *(feature request)* | 🟡 Low | Medium |
| 36 | Terminal link in the chat members sidebar forces a new browser tab, while the adjacent pop-out link looks different but behaves the same | 🟡 Low | Trivial |
| 10 | Small stuff: no `--version` alias, NATS still installed, a placeholder registry that looks real | 🟡 Low | Low |

**If you only look at four:**

**31** first, because it is live work — the `hasAnyKey` fix in #1292 is correct and deployed
here, and progeny agents still get no credentials. Three conditions sit behind it, one of them
a one-line prefix mismatch. Worth seeing before #1252 is closed.

**16 and 18** together are what most enterprises will care about — all users can read all
projects out of the box, and the obvious fix hides projects from their own members.

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

Worth saying, since "we found 36 items" is easy to write and harder to trust:

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
| Scion | `main` @ `90bf246e`, re-verified at `1b3c9418`, `1933d359`, `89ed0fe8`, `2b8be982`, and `aedf89ed` |

## Questions

Open an issue here and I'll answer. Happy to pull logs, share more config, or test a fix
against our setup — we've got a working internal deployment to try things on.

— Anthony Lofton
