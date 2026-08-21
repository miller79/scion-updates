# Notes from a Scion starter-hub deployment inside an enterprise

*Anthony Lofton — August 2026*

We stood up a Scion Hub on an internal-only GCE VM (Ubuntu 24.04) with Keycloak SSO and TLS
handled by an F5 BIG-IP. Running `main` @ `1933d359`.

**It works.** But we hit enough snags getting there that it seemed worth writing down —
partly so the next person in a similar environment has an easier time, and partly because a
few of these look like real bugs rather than just "our setup is unusual".

> **A note on freshness:** we deployed at `90bf246e`, then pulled 24 commits (through PR
> #1201), then a further 16 (through PR #1217) — rebuilding and re-checking every item each
> time. **All 19 issues below are still present in `1933d359`.**
>
> One thing worth flagging from the latest round: **PR #1205 ("add shellcheck gate and fix
> existing findings") edited eight files under `scripts/starter-hub/`**, including the two
> scripts most of this report concerns. Those edits were pure lint hygiene — `# shellcheck`
> directives, `read -r`, quoting `--labels` and `--create-disk`. The `git push origin main`,
> the stale Go pin, and the `--session-secret` on the systemd `ExecStart` line all came
> through untouched, which is entirely expected since shellcheck has no opinion on any of
> them. Noted just to make clear these aren't things a linter will surface.
>
> `pkg/secret/` has been untouched across all 40 commits, so issue 11 is exactly as
> described.

---

## The setup

The VM already existed and sat in a shared VPC with no external IP, IAP-only SSH, a service
account with fairly narrow scopes, corporate package mirrors instead of public registries,
and DNS run by a network team outside GCP. Probably a familiar shape to anyone who's tried
to get something running inside a large company.

`gce-demo-deploy.sh` expects to provision its own public-internet VM, so **four of its six
steps didn't apply**. We ended up doing the relevant parts by hand, which is how most of
this came to light.

Issues are numbered in the order we found them — the table at the end is sorted by priority
instead. Numbers 11–19 came later, while we were hardening things for a wider test group and
trying to get telemetry working.

**If you only look at three:** **13** and **11** are the security ones, and **13 is a
one-line fix**. **2** is the one that stops a stock deployment dead at step 1.

---

## Security issues

### 11. The local secrets backend silently stores plaintext, contradicting its own comment 🔴

`pkg/secret/secret.go` declares:

```go
// ErrNoSecretBackend is returned when a secret operation requires a production
// secrets backend (e.g., GCP Secret Manager) but only the local backend is configured.
// The local backend does not encrypt secret values, so write operations are rejected.
var ErrNoSecretBackend = errors.New("secret storage requires a configured secrets backend; ...")
```

**Write operations are not rejected.** `ErrNoSecretBackend` is *checked* in three places in
`pkg/hub/handlers_env_secrets.go` but is **never returned anywhere in non-test code**. We
grepped the whole tree to confirm.

What actually happens with `SCION_SERVER_SECRETS_BACKEND=local`:

```go
// pkg/secret/localbackend.go — toStoreSecret()
return &store.Secret{
    Key:            input.Name,
    EncryptedValue: input.Value,   // ← raw plaintext into a field named "encrypted_value"
    ...
}
```

The value is written verbatim into a column called `encrypted_value`, in the SQLite
database on disk. The ent schema marks the field `Sensitive()`, which correctly keeps it
out of logs and API responses — but does nothing at rest.

So an operator reading either the comment *or* the column name reasonably concludes their
secrets are protected, when they are stored in the clear. In practice that means anyone with
a shell on the host — or a snapshot of its disk — can read every stored secret, with no
audit trail of having done so.

**Suggested fix — any one of these would resolve it:**
1. Actually return `ErrNoSecretBackend` from `LocalBackend.Set()` (matching the stated
   intent, and the handlers are already written to translate it to HTTP 501); **or**
2. Encrypt at rest in the local backend with a key derived from the session/signing secret; **or**
3. At minimum, rename the field away from `encrypted_value`, fix the comment, and log a
   prominent WARN at startup when the local backend is active.

Option 1 seems closest to the original design intent. Whichever route, the current state —
where the code comment asserts a safety property the code does not implement — is the
part worth removing.

### 13. The systemd template puts the session signing secret in the process table 🔴

`gce-start-hub.sh` generates this `ExecStart`:

```
ExecStart=%s --global server start --foreground --production --debug --enable-hub%s \
  --enable-web --web-port 8080 --storage-bucket \${SCION_HUB_STORAGE_BUCKET} \
  --session-secret \${SESSION_SECRET} --auto-provide
```

systemd expands `${SESSION_SECRET}` from the `EnvironmentFile`, so the literal value lands
on the **process command line**. Any local user can then read it:

```bash
$ ps -eo args | grep scion
... --session-secret <the-actual-secret> ...
```

No sudo, no file access, no privilege required — and `hidepid` is not set on a default
Ubuntu image, so `/proc/<pid>/cmdline` is world-readable. `hub.env` being mode 600 is
irrelevant; the value is in the process table.

Because that secret signs session cookies, anyone who reads it can **forge a valid session
for any user, including an admin**, without authenticating. That turns "has a shell on the
box" into "can impersonate the hub administrator" — a meaningful privilege escalation on any
host with more than one user.

**The fix is a one-line deletion**, because the fallback already exists.
`resolveSessionSecret()` reads `--session-secret`, then `SCION_SERVER_SESSION_SECRET`, then
`SESSION_SECRET` — and the unit already supplies `SESSION_SECRET` via `EnvironmentFile`.
Dropping the flag keeps the identical value working, invalidates no sessions, and removes
the exposure. We verified this in place: no `--session-secret` in `ps`, and no
`no session secret set` warning in the log.

The same argument applies to `--storage-bucket`, though a bucket name is not sensitive.

### 16. Every authenticated user can read every project by default 🔴

On first startup `pkg/hub/seed.go` creates this policy:

```go
Name:         "hub-member-read-all",
Description:  "Allow hub members to read all resources",
ScopeType:    "hub",
ResourceType: "*",                          // every resource type
Actions:      []string{"read", "list"},
Effect:       "allow",
```

It is bound to the `hub-members` group, and **every user is auto-joined to that group on
login** (`pkg/hub/handlers_auth.go`). The net effect is that any authenticated user can read
every project, agent, and resource on the hub.

We hit this during a security test: two users each created a project, and each could
immediately see the other's.

What makes it worth flagging is that the rest of the design clearly anticipates isolation:

- The policy engine is **default-deny** — `Decision{Allowed: false, Reason: "default deny"}`
  (`pkg/hub/authz.go`)
- Projects carry a `visibility` field with `private` / `team` / `public`
  (`pkg/api/types.go`)

Both are overridden by the one seeded wildcard. A project created with
`visibility: "private"` displays as private and is readable by everyone — the field is
currently inert.

**To be precise about severity:** the grant is `read` + `list` only. Writes still fall
through to default deny, and we verified a non-owner could not modify another user's
project. This is visibility exposure, not a write hole.

**Suggested fix — any of these:**
1. Narrow the seed to the shared building blocks it is presumably meant to cover —
   `template`, `skill`, `harness_config`, `broker` — and exclude `project` and `agent`
2. Or make the policy honour `visibility`, so `private` means something
3. Or, if collaborative-by-default is the intended product stance, **document it
   prominently**. "Scion hubs are collaborative by default: every member can see every
   project" is a perfectly reasonable design choice — it just needs stating up front rather
   than being discovered during a security review.

We would suggest 1 or 3. Silently defaulting open is the part worth changing.

#### Why we would call this a gap rather than a design stance

"Scion hubs are collaborative; everyone sees everything" would be a perfectly defensible
product decision. But the codebase argues against that reading:

- the policy engine is **default-deny** (`pkg/hub/authz.go`)
- projects carry a `visibility` field supporting `private` / `team` / `public`
- there is a per-project members group with `owner` / `admin` / `member` roles
- there is an `isProjectOwnerOrAdmin` baseline specifically for project-level access

Someone clearly designed for isolation. A single seeded wildcard overrides all of it, and the
per-project seed is missing the one policy that would make membership meaningful (finding 18).
Taken together that reads like unfinished wiring rather than an intentional stance.

The practical consequence for an operator: there is **no supported way to turn isolation on**.
No configuration flag, no admin UI, no documented pattern. Achieving it requires knowing that
`hub-member-read-all` exists, that deleting it silently re-seeds, that `matchesResource` is
exact-string so one policy per type is needed, and that per-project read is not auto-created.
We only assembled that from reading the source.

To be fair about severity: this is **read visibility**, not a write hole. Non-owners cannot
modify or delete another user's project, agent creation is already restricted to project
members, and secret scoping is genuinely enforced. The confidentiality boundary is missing;
the integrity boundary is not.

#### We tested option 1 — here is a working seed

Rather than leave this as "narrow it somehow", we ran the change on our hub and measured it.

Replaced the single wildcard with four type-specific policies, all `ScopeType: "hub"`,
`Actions: ["read","list"]`, `Effect: "allow"`, bound to the same `hub-members` group:

```
hub-member-read-template          resourceType: template
hub-member-read-harness_config    resourceType: harness_config
hub-member-read-skill             resourceType: skill
hub-member-read-broker            resourceType: broker
```

then deleted `hub-member-read-all`.

Note these must be **four separate policies** — `matchesResource` (`pkg/hub/authz.go`) does a
plain string comparison on `ResourceType`, so `"*"` is the only special value and a
comma-separated list would match nothing.

**Measured A/B**, same user, same token, only the policy set changed. The user was demoted
from `admin` to `member` for the test, since the admin bypass would otherwise mask the result:

| | wildcard present | wildcard removed |
|---|---|---|
| Projects visible | 3 (including one owned by another user) | **1 — own only** |
| Agents visible | 2 | **1 — own only** |
| Templates | 1 | 1 (preserved) |
| Skills | 0 | 0 (preserved) |
| Brokers | 1 | 1 (preserved) |
| Harness configs | 7 | 7 (preserved) |

Every endpoint still returned HTTP 200 — no 403s, nothing degraded. Cross-project visibility
closed; the shared building blocks a member needs in order to build anything stayed readable.

**What we verified:** all read paths above, and that project isolation is genuinely restored
(a member no longer sees another user's project or its agents).

**What we did not verify:** a member creating an agent end to end. Templates and brokers being
*readable* is necessary but may not be sufficient — the create path may consult resource types
we did not enumerate. If it does, the fix is presumably one more policy of the same shape.

We offer this as a candidate default rather than a proven-complete one — but it is at least a
concrete starting point that measurably restores isolation without breaking the read paths we
could exercise.

#### ⚠️ Deleting the policy is NOT a durable fix — it silently reverts

This one caught us, and it is arguably worse than the original default.

Our first attempt was simply to **delete** `hub-member-read-all`. Isolation worked, and a
second non-admin user independently confirmed they could no longer see another user's
project. We considered it done.

It came back at the next hub restart.

`seedPolicy` (`pkg/hub/seed.go`) matches **by name only**:

```go
existing, err := s.ListPolicies(ctx, store.PolicyFilter{Name: policy.Name}, store.ListOptions{Limit: 1})
if existing.TotalCount > 0 {
    return          // exists by name -> leave alone
}
// ... otherwise create it
```

So the seed runs on **every startup** and recreates any policy whose *name* is absent. Delete
the wildcard and it is faithfully restored the next time the hub restarts — with no warning,
and no signal to the operator that their isolation has just been undone.

That is a nasty failure mode: an admin removes the policy, verifies isolation, ships it, and
loses it at the next deploy or reboot while still believing it is closed.

**The durable approach is to keep the name and neuter the contents**, so the seeder finds it
and leaves it alone:

```
PATCH /api/v1/policies/{id}
{
  "name": "hub-member-read-all",          // name retained so seed.go does not recreate it
  "resourceType": "_disabled",            // matches nothing: matchesResource is exact string equality
  "actions": ["read"],
  "effect": "allow",
  "scopeType": "hub"
}
```

**Verified across a restart this time:** after `systemctl restart scion-hub`, the policy list
showed no wildcard, no duplicate `hub-member-read-all`, and no `seeded policy` log lines. A
member still saw only their own project and agent, with templates, brokers, and harness
configs all still readable.

**Suggested fix regardless of which route upstream takes:** whatever the default becomes,
make it *changeable*. Right now a seeded policy can be deleted through the API and silently
restored by the next boot, which means the API and the seeder disagree about who owns that
row. Either skip re-seeding when an operator has explicitly removed a seeded policy (a
tombstone, or an `origin`/`managed` marker like `syncHubSettings` already uses for hub
settings), or document clearly that seeded policies are not deletable and must be edited in
place.

### 17. The `viewer` role implies a restriction it does not provide 🟠

`viewer` is a first-class user role: it is in the ent enum
(`admin` / `member` / `viewer`), it is selectable from the admin UI
(`web/src/components/pages/admin-users.ts`), and it is the default role assigned to
federated identities (`pkg/hub/federation_auth.go`).

**It is never consulted in any authorization decision.** We grepped the tree: the only role
check in the authz path is `user.Role() == "admin"` (`pkg/hub/authz.go`). `member` and
`viewer` are functionally identical — both fall through to policy evaluation and receive
exactly the same answer.

So an operator who demotes a user to `viewer` expecting read-only access reasonably believes
they have restricted that user. They have not. Combined with issue 16, a "viewer" can read
every project on the hub, which is the same as everyone else.

**Suggested fix:** either implement it (a `viewer` deny baseline for mutating actions, sitting
alongside the existing admin bypass), or remove it from the enum and the admin UI so it
cannot imply a guarantee it does not make.

### 18. The per-project member seed is incomplete — membership does not confer visibility 🟠

When a project is created, Scion auto-creates a members group and two policies
(`createProjectMembersGroupAndPolicy`):

```
project:<slug>:member-create-agents           agent                 ["create","stop_all"]
project:<slug>:member-assign-service-accounts gcp_service_account   ["assign"]
```

**Neither grants `read` or `list` on the project itself**, and the
`isProjectOwnerOrAdmin` baseline (`pkg/hub/authz.go`) only fires for group role `owner` or
`admin` — not `member`.

So a user added to a project as a `member` can create and stop agents in a project **they
cannot see**. We hit this directly: added a member to a project, and the project stayed
invisible to them.

This never surfaces on a default install, because `hub-member-read-all` (finding 16) grants
read on everything and quietly covers it. The moment an operator narrows that wildcard for
isolation — the very thing finding 16 recommends — project membership stops meaning anything.
The two findings are coupled: **fixing 16 without fixing 18 leaves members unable to see the
projects they belong to.**

**Verified fix.** Adding one project-scoped policy per project, bound to that project's
members group, restores it:

```
scopeType:    project
scopeId:      <project-id>
resourceType: project
actions:      ["read","list"]
effect:       allow
```

After adding it, the member saw the project they belong to (2 projects: one owned, one joined)
while still not seeing unrelated projects. Confirmed to survive a hub restart.

Note this covers the project, not its contents — `agent: read/list` is a separate gap with the
same shape, so a member can see the project but not the agents running in it. Whether that is
desirable is a product decision, but it should be a decision rather than an accident.

**Suggested fix:** add `project: ["read","list"]` (and probably `agent: ["read","list"]`) to
the per-project policy set created by `createProjectMembersGroupAndPolicy`. Without it, the
per-project seed depends on a hub-wide wildcard that any security-conscious operator will
want to remove.



---

## Things that block a deployment

### 1. Hardcoded Go version no longer satisfies `go.mod` 🟠

`go.mod` requires `go 1.26.1`, but the install scripts pin **Go 1.23.0** in two places:

- `scripts/starter-hub/gce-demo-cloud-init.yaml`
- `scripts/starter-hub/gce-start-hub.sh` (the "install missing dependencies" block)

**Correction to an earlier draft of this report:** we initially described this as a hard
build failure. It usually is not. With the default `GOTOOLCHAIN=auto` and network access,
Go quietly downloads the required toolchain and the build succeeds. We verified this:

```
$ go version                       # with 1.23.0 installed, in a go1.26.1 module
go: downloading go1.26.1 (linux/amd64)
go version go1.26.1 linux/amd64    # ← silently substituted
```

It *does* fail hard where toolchain download is unavailable — `GOTOOLCHAIN=local`,
air-gapped hosts, or a restricted module proxy:

```
go: go.mod requires go >= 1.26.1 (running go 1.23.0; GOTOOLCHAIN=local)
```

So this is less severe than first stated, but still worth fixing: the provisioned toolchain
is not the one that builds the binary, the pin is silently stale, and it breaks exactly the
locked-down environments where the starter-hub is most awkward to debug.

**Suggested fix:** derive the version from `go.mod` rather than hardcoding, e.g.

```bash
GO_VERSION=$(awk '/^go /{print "go"$2}' go.mod)
curl -fsSL "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
```

A drift check in CI comparing the scripts' pin against `go.mod` would stop this
recurring — this looks like it drifted silently when the toolchain moved.

### 2. `gce-start-hub.sh` pushes to the upstream repo 🔴

Step 1 runs `git push origin main`. Anyone who is not a maintainer of
`GoogleCloudPlatform/scion` fails immediately, at the very start of the deployment.

It is also unnecessary — the VM clones from GitHub directly, so a local push has no
bearing on what gets deployed.

**Suggested fix:** drop it, or gate behind `--push` / skip when `origin` isn't
writable. Failing that, at minimum don't make it step 1 of the happy path.

### 3. `default_runtime` is a dead config key 🟠

`gce-start-hub.sh` writes `default_runtime: ${DEFAULT_RUNTIME}` into `settings.yaml`,
but no such key exists in the Go config schema. The hub **silently strips it** when it
rewrites the file on startup.

This is actively misleading: it reads as though it controls agent placement, and an
operator setting `default_runtime: docker` will believe they've configured something.

**Suggested fix:** remove it from the template, or implement it. Related — see
issue 8 on silent key-dropping.

---

## Docs that are wrong

### 4. OIDC redirect URI is wrong in the setup guide 🔴

The circulating `oidc-setup.md` instructs registering:

```
https://<hub-domain>/api/v1/auth/oidc/callback
```

**That route does not exist.** The actual redirect URI is constructed in
`pkg/hub/web.go` as `BaseURL + "/auth/callback/" + provider`, with the provider slug
`oidc` from `pkg/hubclient/auth.go`:

```
https://<hub-domain>/auth/callback/oidc
```

Anyone following the guide registers the wrong URI in their IdP and gets an opaque
`invalid redirect_uri` at the end of the flow — a genuinely painful thing to debug
against an enterprise SSO team.

### 5. The guide overstates HTTPS as a prerequisite 🟠

`oidc-setup.md` lists "A running Scion Hub instance with HTTPS" under Prerequisites.
The hub actually adapts — `pkg/hub/web.go` derives the session cookie's `Secure`
flag from the base URL scheme:

```go
Secure: strings.HasPrefix(cfg.BaseURL, "https://"),
```

**We ran OIDC login successfully over plain HTTP** against Keycloak. This matters
because on an internal host with no public IP, obtaining a certificate can mean a
multi-day PKI ticket. We nearly blocked the deployment on that before testing.

**Suggested wording:** HTTPS is strongly recommended (tokens otherwise traverse the
network in cleartext), and required only if your IdP enforces HTTPS redirect URIs —
but it is not a functional requirement of the Hub.

### 6. Dev-auth cleanup targets the wrong user 🟡

The guide says:

```bash
sudo sqlite3 /home/scion/.scion/hub.db "DELETE FROM users WHERE email = 'dev@localhost';"
```

The actual dev user is **`scion@localhost`**. The command silently deletes nothing,
leaving an admin-role row behind while the operator believes they've cleaned up.

Worth also noting: once `--dev-auth` is removed the row is unauthenticatable anyway,
and it may own the auto-provisioned Global project — so deleting it may be both
unnecessary and mildly risky.

### 12. `SCION_HUB_ENDPOINT` in `hub.env.sample` binds to nothing 🟠

`hub.env.sample` offers:

```bash
# (Optional) Fallback for client/agent communication if different from BASE_URL
# SCION_HUB_ENDPOINT=https://your-hub-domain.example.com
```

That variable name is never read. The koanf env provider is registered with the
`SCION_SERVER_` prefix (`pkg/config/hub_config.go`: `SCION_SERVER_HUB_PORT -> hub.port`),
so populating `cfg.Hub.Endpoint` requires **`SCION_SERVER_HUB_ENDPOINT`**. Setting the
documented name is a silent no-op.

This one cost us real debugging time. We needed exactly the split the sample describes —
browsers on `https://` through the load balancer, colocated Docker agents on `http://` to
avoid a TLS trust problem — set `SCION_HUB_ENDPOINT`, restarted, and the hub logged:

```
"msg":"Hub endpoint resolved from SCION_SERVER_BASE_URL: https://..."
"msg":"Dispatcher hub endpoint configured","endpoint":"https://..."
```

Agents were still being pointed at the HTTPS URL. Nothing errored; the setting was simply
ignored. We only caught it because we were reading the dispatcher log line — a deployment
that trusted the sample would have failed at first agent launch with a TLS error and no
obvious cause.

**Suggested fix:** correct the sample to `SCION_SERVER_HUB_ENDPOINT`. More generally,
`hub.env.sample` mixes variables read directly by the process (`SESSION_SECRET`,
`SCION_SERVER_BASE_URL`) with ones that must go through the koanf prefix — the file would
be much clearer if it noted which convention applies to each, since they look identical.

---

## Telemetry does not work out of the box

Both of these were found together: the in-product **Metrics dashboard** returns a 503 on a
by-the-book starter-hub deployment, and would still not work after fixing the first issue.

### 14. The `settings.yaml` template omits `telemetry.cloud.gcp_project_id` 🟠

`gce-start-hub.sh` writes a `telemetry.cloud` block containing `enabled`, `provider`,
`endpoint`, `protocol`, and `batch` — but **not `gcp_project_id`**.

That key is the only thing `telemetryGCPProjectFromSettings()` reads
(`cmd/server_foreground.go`). Without it `TelemetryProjectID` stays empty, so
`pkg/hub/server.go` never constructs either the metrics dashboard **or** the Cloud Logging
query service. Users then get:

```
503 metrics_unavailable
"Metrics dashboard is not configured (no telemetry project ID)"
```

The confusing part is that `hub.env.sample` **does** ship `SCION_GCP_PROJECT_ID`, so an
operator reasonably believes they have configured a telemetry project. But that variable is
consumed by the *agent-side* exporter (`pkg/sciontool/telemetry/config.go`,
`pkg/config/telemetry_convert.go`) — it does not feed the hub's own dashboard. Two
similarly-named settings, different consumers, and the error message says the project ID is
missing when the operator has plainly set one.

**Fix:** add `gcp_project_id: ${PROJECT_ID}` to the `telemetry.cloud` block in the template.
We confirmed this is sufficient — after adding it, the hub logged all three:

```
Telemetry project ID from settings: <project>
Cloud Logging query service initialized
Metrics dashboard service initialized
```

### 15. `gce-demo-provision.sh` grants `logging.viewer` but not `monitoring.viewer` 🟠

The provision script grants the service account:

```
roles/cloudtrace.agent          roles/logging.logWriter
roles/logging.viewer            roles/monitoring.metricWriter
```

`monitoring.viewer` is missing. Writing metrics and reading them back are separate
permissions, so the metrics dashboard — which queries Cloud Monitoring — cannot read the
data the hub just wrote. The asymmetry looks accidental rather than deliberate:
`logging.viewer` was clearly added so the log viewer could read, and the metrics equivalent
appears to have been overlooked.

**Fix:** add `roles/monitoring.viewer` alongside the existing grants.

> Together, 14 and 15 mean the Metrics dashboard cannot work on a stock starter-hub
> deployment: the service is never constructed, and even once it is, it lacks read
> permission. Worth noting the provision script *does* set
> `--scopes=cloud-platform`, so the access-scope layer is fine on a stock deploy — it only
> bit us because our pre-existing VM had narrower scopes.


### 19. No way to import a template without a remote URL or server-side files 🟡

*(Feature request rather than a defect.)*

Template import accepts exactly one source — a URL:

```go
// pkg/hub/handlers_resource_import.go
if req.SourceURL == "" {
    writeError(w, http.StatusBadRequest, "invalid_request", "sourceUrl is required", nil)
}
```

`NormalizeTemplateSourceURL` resolves that into `http(s)://`, `git+https://`, a GitHub
`owner/repo` shorthand, or an rclone remote. The per-project endpoint additionally accepts a
**workspace path** — files already sitting on the server.

So in practice a template must either live in a git repo / reachable URL, or already be on the
hub host. There is **no upload path**: nothing in the template import flow parses
`multipart/form-data`.

This is awkward in an enterprise setting. Getting a template in means either pushing it to a
git remote the hub can reach (which may cross a network or approval boundary) or having shell
access to the host (which most users deliberately do not have). "Here is a zip of a template,
please add it" has no answer.

**Two things make this a smaller ask than it first appears:**

1. **The extraction code already exists.** `extractZip(zipPath, destPath)` in
   `pkg/config/remote_templates.go` already unpacks zips (and gzip/tar) for archives fetched
   from remote URLs. An upload endpoint would reuse it rather than add anything new.
2. **The upload pattern already exists elsewhere in the hub.** `admin_allow_list.go` and
   `admin_user_invite.go` both accept `multipart/form-data` via `r.FormFile("file")`. So this
   would follow an established convention in the same codebase, not introduce one.

**Suggested fix:** accept `multipart/form-data` on the existing import endpoints alongside
`sourceUrl` — upload a zip, run it through `extractZip`, then feed the result into the same
discovery path the URL flow already uses.


---

## Enterprise friction

### 7. No supported path for an internal-only host 🟠

Several assumptions are baked in with no override:

| Assumption | Enterprise reality |
|---|---|
| VM has an external IP | Internal-only, no public ingress |
| Cloud DNS zone + `dns.admin` | DNS managed by a network team outside GCP |
| Let's Encrypt is reachable | ACME cannot reach a private IP |
| `gcloud compute ssh` works directly | IAP tunnelling required |
| Public package registries | Corporate Artifactory/Nexus mirrors only |
| SA has `cloud-platform` scope | Narrow, policy-constrained scopes |

`gce-certs.sh` in particular has no fallback — it wants to create a managed zone and
run `certbot --dns-google`. For us both were impossible, and there's no documented
"bring your own cert" or "TLS terminated upstream" path, even though **an LB/F5 in
front is how most enterprises actually terminate TLS**.

**Suggested additions:**
- `USE_IAP=true` → append `--tunnel-through-iap` to the `gcloud compute ssh`/`scp` calls
- `SKIP_CERTS=true` → bring-your-own-cert, pointing the Caddyfile at existing files
- An HTTP-only Caddyfile variant for hubs behind an upstream TLS terminator
- `NPM_REGISTRY` / `NPM_TOKEN` passthrough into the build (see 9)
- A short "Deploying to an existing/internal VM" section in the starter-hub README

### 8. Hub silently drops unknown `settings.yaml` keys 🟠

On startup the hub rewrites `settings.yaml` (injecting `server.broker.broker_id`) and
discards any key not in its schema — no warning, no log line.

Combined with issue 3, an operator can write a setting, restart, see the hub come up
healthy, and never learn their configuration was discarded. We only caught it by
diffing the file before and after startup.

**Suggested fix:** log at WARN for each unrecognised key encountered during load.
Cheap to implement, and it turns a silent misconfiguration into an obvious one.

### 9. No way to inject a package registry into the build 🟡

`make web` runs `npm install` against whatever registry is configured. Behind
corporate egress, direct `registry.npmjs.org` tarball fetches were reset, and npm
surfaced this as:

```
npm error Exit handler never called!
```

— which names npm itself as the culprit. The real cause was only visible in
`~/.npm/_logs/*-debug-0.log`: ~15 concurrent `.tgz` fetches all failing `ECONNRESET`.
Package *metadata* succeeded and ~197 packages installed first, which made it look
like a partial/flaky install rather than a network policy problem.

We fixed it with a `.npmrc` in the service user's home. Worth noting the hub's own
"rebuild-web" maintenance task depends on that file existing there — an operator who
sets the registry only in their own shell will find in-app rebuilds broken later.

**Suggested fix:** document the corporate-registry case in the starter-hub README,
and mention that `.npmrc` must live in the *service user's* home for maintenance
tasks to work.

### 10. Minor items 🟡

- **`scion --version` doesn't exist** — it's `scion version`. The `--version` flag
  errors with `unknown flag`, which is a surprising first impression right after a
  successful build. Worth adding as an alias.
- **cloud-init installs NATS**, which the starter-hub README itself marks as archived
  and superseded by in-process events. Dead weight on every provision.
- **`gce-demo-cloud-init.yaml` targets Ubuntu 22.04**; we ran 24.04 with no issues,
  but the pinning is implicit rather than stated.
- **`--storage-bucket ${VAR}` is passed unconditionally** in the systemd template even
  when unset. It works — `cmd/server_foreground.go` falls back to local filesystem
  storage — but it relies on an empty-string flag being treated as absent, and the
  surrounding code does branch on `Flags().Changed("storage-bucket")`. Making the flag
  conditional would be more obviously correct.
- **`hub.env.sample` ships `SCION_IMAGE_REGISTRY=us-docker.pkg.dev/ptone-misc/scion-alt`**.
  Being a real, working-looking registry, it's easy to carry into a deployment
  unnoticed and only discover at first agent launch. A clearly invalid placeholder
  would fail louder and sooner.

---

## What worked well

Worth saying explicitly, since the above is all friction:

- **The hub itself came up clean on the first try** once dependencies were right —
  no crashes, no schema surprises, no migration issues.
- **`/healthz` is genuinely good.** Composite status across web/hub/broker with
  database and Docker sub-checks made verification trivial and made it obvious the
  broker had reconnected after each restart.
- **Startup validation of OIDC config fails fast** with a clear message — exactly the
  right behaviour, and it let us wire automatic rollback around config changes with
  confidence.
- **Admin auto-promotion via `SCION_SERVER_HUB_ADMINEMAILS`** worked first time and
  removed any bootstrap-admin dance.
- **Public OIDC client support (PR #1140)** was present and worked with no client
  secret — important for us, and recent enough that we checked for it specifically.
- **The colocated broker's HMAC auth** is properly independent of dev-auth, so
  disabling dev-auth didn't disturb it. We'd guarded for that and didn't need to.
- **The secrets *API* design is genuinely solid** — worth saying given issue 11 is about
  secrets. `metaToStoreSecret()` has no value field at all, so no user-facing endpoint can
  return a secret value, and `resolveEnvSecretAccess()` enforces scoping properly (user
  scope resolves to the caller's own ID; project scope goes through `authzService`; agent
  identities are read-only and confined to their own project). We audited this specifically
  before letting a wider group onto the hub, and the access-control layer held up. The gap
  in issue 11 is purely at-rest storage, not authorization.
- **Structured JSON logging with subsystem tags** made diagnosis fast throughout.
- Build performance was excellent: web assets ~11 s, binary ~52 s on 16 vCPU.

---

## Suggested fixes, by priority

Ordered by priority, not by issue number.

| # | Change | Severity | Effort |
|---|---|---|---|
| **13** | **Drop `--session-secret` from the systemd template — it exposes the cookie signing secret via `ps`** | **Security** | **Trivial** |
| **11** | **Local backend stores plaintext while its comment claims writes are rejected** | **Security** | Low–Med |
| **16** | **All authenticated users can read all projects by default; `visibility` is inert** | **Security** | Low |
| **17** | **`viewer` role implies a restriction it does not enforce** | **Security** | Low |
| **18** | **Per-project member seed omits `project: read` — membership confers no visibility** | **Security** | Low |
| 1 | Derive Go version from `go.mod`; add CI drift check | High | Low |
| 2 | Remove/gate `git push origin main` | Blocking | Low |
| 4 | Fix OIDC redirect URI in docs → `/auth/callback/oidc` | Blocking | Trivial |
| 14 | Add `telemetry.cloud.gcp_project_id` to the settings template | High | Trivial |
| 15 | Add `roles/monitoring.viewer` in `gce-demo-provision.sh` | High | Trivial |
| 12 | Fix `SCION_HUB_ENDPOINT` → `SCION_SERVER_HUB_ENDPOINT` in `hub.env.sample` | High | Trivial |
| 3 | Remove or implement `default_runtime` | High | Low |
| 5 | Correct the HTTPS-prerequisite claim | High | Trivial |
| 8 | WARN on unknown `settings.yaml` keys | High | Low |
| 7 | Support internal/BYO-cert/IAP deployments | High | Medium |
| 6 | Fix dev-auth cleanup user (`scion@localhost`) | Medium | Trivial |
| 9 | Document corporate npm registry setup | Medium | Low |
| 19 | Accept a zip upload for template import (extractor already exists) | Low (feature) | Low |
| 10 | `--version` alias; drop NATS; placeholder registry | Low | Low |

Happy to supply logs, configs, or test any of these against our environment — we have
a working internal deployment we can iterate on.
