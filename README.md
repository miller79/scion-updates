# scion-updates

Notes from running [**Scion**](https://github.com/GoogleCloudPlatform/scion) inside a big
enterprise, written up for the maintainers.

We got it working — but hit a fair number of snags along the way, mostly in places that only
show up when you're not deploying to a fresh public-internet VM. Rather than let that
knowledge evaporate, it's all here with file references so it's easy to act on.

Everything was **re-verified against current `main` twice**, not written from memory — most recently across 40 commits, with all 17 issues still present.

## The short version

Scion's `scripts/starter-hub/` assumes it's provisioning its own demo VM with a public IP,
Cloud DNS, and Let's Encrypt. Our reality: a pre-existing internal host, no public IP,
IAP-only SSH, corporate package mirrors, DNS managed by a network team, narrow
service-account scopes, and TLS handled by an F5.

Four of the six deploy steps didn't apply. It all worked in the end, but a few of these are
genuine bugs rather than just "enterprise is different" — including two security ones.

**Take these and run with them.** Copy anything into issues, commits, or PRs — no
attribution needed, no need to ask.

## How this repo is laid out

| | |
|---|---|
| [**FINDINGS.md**](FINDINGS.md) | The canonical numbered list. This is the one to act on — findings cross-reference each other, so they live in one place and get corrected in place. |
| [**updates/**](updates/) | A dated entry per working day: what we did, what we found, what we got wrong. Append-only — nothing here is rewritten later. |

Latest: [**2026-08-18**](updates/2026-08-18.md) — authorization findings, and a correction to
finding 1.

## What we found

Full write-up: [**FINDINGS.md**](FINDINGS.md)
(deployed `main` @ `1933d359`, Ubuntu 24.04, Keycloak SSO, TLS via BIG-IP)

| # | Issue | Severity | Effort |
|---|---|---|---|
| 13 | `--session-secret` in the systemd template leaks the cookie signing secret into `ps` | 🔴 **Security** | Trivial |
| 11 | Local secrets backend stores plaintext, while a comment says writes are rejected | 🔴 **Security** | Low–Med |
| 16 | Every authenticated user can read every project by default — `visibility: private` is inert *(includes a tested fix)* | 🔴 **Security** | Low |
| 17 | The `viewer` role is selectable but never enforced — identical to `member` | 🔴 **Security** | Low |
| 2 | `gce-start-hub.sh` does `git push origin main`, which nobody outside the repo can do | 🔴 Blocking | Low |
| 4 | The OIDC guide gives a redirect URI route that doesn't exist | 🔴 Blocking | Trivial |
| 14 | Settings template misses `telemetry.cloud.gcp_project_id`, so the metrics dashboard is dead | 🟠 High | Trivial |
| 15 | Provision script grants `logging.viewer` but not `monitoring.viewer` | 🟠 High | Trivial |
| 12 | `SCION_HUB_ENDPOINT` in `hub.env.sample` isn't wired to anything | 🟠 High | Trivial |
| 1 | Go pinned to 1.23.0 vs `go.mod` 1.26.1 — usually masked by `GOTOOLCHAIN=auto`, breaks air-gapped builds | 🟠 High | Low |
| 3 | `default_runtime` looks like config but is silently thrown away | 🟠 High | Low |
| 5 | The OIDC guide says HTTPS is required — it isn't | 🟠 High | Trivial |
| 8 | Unknown `settings.yaml` keys vanish with no warning | 🟠 High | Low |
| 7 | No real path for internal-only / bring-your-own-cert / IAP setups | 🟠 High | Medium |
| 6 | Dev-auth cleanup command deletes the wrong username (so, nothing) | 🟡 Medium | Trivial |
| 9 | Nothing documented for pointing the build at a corporate package registry | 🟡 Medium | Low |
| 10 | Small stuff: no `--version` alias, NATS still installed, a placeholder registry that looks real | 🟡 Low | Low |

**If you only look at three:** 16 is the one most enterprises will care about — all users
can read all projects out of the box. 13 is a one-line security fix. 2 stops a stock
deployment dead at step 1.

There's a **"What worked well"** section in there too — the list above is all complaints,
which isn't a fair picture. `/healthz`, the fail-fast OIDC validation, and the secrets
authorization model were all genuinely nice to work with.

## On the verification

Worth saying, since "we found 17 bugs" is easy to write and harder to trust:

- Everything cites the specific file, usually the function
- Behaviour was checked against the source rather than guessed from symptoms
- We pulled 24 commits, then a further 16, re-checking every item both times — none were
  fixed, and the report says so plainly
- One claim we got wrong in an early draft (calling the Go mismatch a hard build failure) is
  **corrected in place**, with the test output that disproved it
- Where we fixed something locally, it's noted as verified working
- Where a test turned out to be **inconclusive**, we said that instead of claiming a result
- For issue 16 we went further and **tested a candidate fix on a live hub**, with before/after
  numbers and an explicit note on what we did and did not exercise

## The environment

Generalised — no internal hostnames or addresses in here.

| | |
|---|---|
| Platform | GCE, Ubuntu 24.04 LTS |
| Network | Shared VPC, no external IP, IAP-only SSH |
| TLS | Terminated upstream by an F5 BIG-IP |
| Identity | Keycloak OIDC, public client, Kerberos/SPNEGO realm |
| Packages | Corporate Artifactory mirrors, public registries blocked |
| Scion | `main` @ `90bf246e`, re-verified at `1b3c9418` and again at `1933d359` |

## Questions

Open an issue here and I'll answer. Happy to pull logs, share more config, or test a fix
against our setup — we've got a working internal deployment to try things on.

— Anthony Lofton
