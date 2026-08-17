# scion-updates

Notes from running [**Scion**](https://github.com/GoogleCloudPlatform/scion) inside a big
enterprise, written up for the maintainers.

We got it working — but hit a fair number of snags along the way, mostly in places that only
show up when you're not deploying to a fresh public-internet VM. Rather than let that
knowledge evaporate, it's all here with file references so it's easy to act on.

Everything was **re-verified against current `main`**, not written from memory.

## The short version

Scion's `scripts/starter-hub/` assumes it's provisioning its own demo VM with a public IP,
Cloud DNS, and Let's Encrypt. Our reality: a pre-existing internal host, no public IP,
IAP-only SSH, corporate package mirrors, DNS managed by a network team, narrow
service-account scopes, and TLS handled by an F5.

Four of the six deploy steps didn't apply. It all worked in the end, but a few of these are
genuine bugs rather than just "enterprise is different" — including two security ones.

**Take these and run with them.** Copy anything into issues, commits, or PRs — no
attribution needed, no need to ask.

## What we found

Full write-up: [**2026-08 — Starter-Hub enterprise deployment**](findings/2026-08-starter-hub-enterprise-deployment.md)
(deployed `main` @ `1b3c9418`, Ubuntu 24.04, Keycloak SSO, TLS via BIG-IP)

| # | Issue | Severity | Effort |
|---|---|---|---|
| 13 | `--session-secret` in the systemd template leaks the cookie signing secret into `ps` | 🔴 **Security** | Trivial |
| 11 | Local secrets backend stores plaintext, while a comment says writes are rejected | 🔴 **Security** | Low–Med |
| 1 | Go pinned to 1.23.0 but `go.mod` needs 1.26.1 — build just fails | 🔴 Blocking | Low |
| 2 | `gce-start-hub.sh` does `git push origin main`, which nobody outside the repo can do | 🔴 Blocking | Low |
| 4 | The OIDC guide gives a redirect URI route that doesn't exist | 🔴 Blocking | Trivial |
| 14 | Settings template misses `telemetry.cloud.gcp_project_id`, so the metrics dashboard is dead | 🟠 High | Trivial |
| 15 | Provision script grants `logging.viewer` but not `monitoring.viewer` | 🟠 High | Trivial |
| 12 | `SCION_HUB_ENDPOINT` in `hub.env.sample` isn't wired to anything | 🟠 High | Trivial |
| 3 | `default_runtime` looks like config but is silently thrown away | 🟠 High | Low |
| 5 | The OIDC guide says HTTPS is required — it isn't | 🟠 High | Trivial |
| 8 | Unknown `settings.yaml` keys vanish with no warning | 🟠 High | Low |
| 7 | No real path for internal-only / bring-your-own-cert / IAP setups | 🟠 High | Medium |
| 6 | Dev-auth cleanup command deletes the wrong username (so, nothing) | 🟡 Medium | Trivial |
| 9 | Nothing documented for pointing the build at a corporate package registry | 🟡 Medium | Low |
| 10 | Small stuff: no `--version` alias, NATS still installed, a placeholder registry that looks real | 🟡 Low | Low |

**If you only look at three:** 13 and 11 are the security ones, and **13 is a one-line
fix**. 14 and 15 together mean the Metrics dashboard can't work on a stock install.

There's a **"What worked well"** section in there too — the list above is all complaints,
which isn't a fair picture. `/healthz`, the fail-fast OIDC validation, and the secrets
authorization model were all genuinely nice to work with.

## On the verification

Worth saying, since "we found 15 bugs" is easy to write and harder to trust:

- Everything cites the specific file, usually the function
- Behaviour was checked against the source rather than guessed from symptoms
- After the first draft we pulled 24 commits and re-checked all of them — none were fixed,
  and the report says so plainly
- Where we fixed something locally, it's noted as verified working
- Where a test turned out to be **inconclusive**, we said that instead of claiming a result

## The environment

Generalised — no internal hostnames or addresses in here.

| | |
|---|---|
| Platform | GCE, Ubuntu 24.04 LTS |
| Network | Shared VPC, no external IP, IAP-only SSH |
| TLS | Terminated upstream by an F5 BIG-IP |
| Identity | Keycloak OIDC, public client, Kerberos/SPNEGO realm |
| Packages | Corporate Artifactory mirrors, public registries blocked |
| Scion | `main` @ `90bf246e`, re-verified at `1b3c9418` |

## Questions

Open an issue here and I'll answer. Happy to pull logs, share more config, or test a fix
against our setup — we've got a working internal deployment to try things on.

— Anthony Lofton
