# Notes from a Scion starter-hub deployment inside an enterprise

*Anthony Lofton — August 2026*

We stood up a Scion Hub on an internal-only GCE VM (Ubuntu 24.04) with Keycloak SSO and TLS
handled by an F5 BIG-IP. Running `main` @ `89ed0fe8`.

**It works.** But we hit enough snags getting there that it seemed worth writing down —
partly so the next person in a similar environment has an easier time, and partly because a
few of these look like real bugs rather than just "our setup is unusual".

> **A note on freshness:** we deployed at `90bf246e`, then pulled 24 commits (through PR
> #1201), then a further 16 (through PR #1217) — rebuilding and re-checking every item each
> time. **All 19 issues below are still present in `1933d359`.** We later pulled through
> `89ed0fe8` and added issues 20-25, then through `2b8be982` and added issues 26-27.
> Issues 20-23 surfaced while moving the hub onto GCP Secret Manager and GCS object storage;
> 24 and 25 surfaced when agent creation broke for three days and the hub reported nothing
> wrong throughout; 9 was substantially rewritten and 26-27 added while rebuilding all
> container images from source behind a corporate proxy.
>
> **Re-verified at `aedf89ed` (2026-08-25), 23 commits on from `2b8be982`: every open issue
> above is still open.** That upgrade added the GKE Helm chart work, a `grok-build` harness,
> and a `DefaultHarnessAuth` setting; none of it touches the areas these issues live in. The
> checks were made against the files each issue cites, not from memory — for example issue 1's
> two scripts still pin `go1.23.0`, and issue 21's `backupSigningKeyToStore` still assigns
> `EncryptedValue = encodedValue` directly.
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
trying to get telemetry working. Numbers 20–25 came later still, when we moved secrets
into GCP Secret Manager and storage into a GCS bucket — that migration is where the two
most serious items in this report turned up.

**If you only look at a few:** **13**, **11**, **20** and **21** are the security ones.
**13 is a one-line fix.** **20** can orphan every secret you have stored, without an
error. **21** is the reason **11**'s natural remedy — "switch to Secret Manager" — only
half-works. **2** is the one that stops a stock deployment dead at step 1.

---

## Security issues

### 11. The local secrets backend silently stores plaintext, contradicting its own comment 🔴

> **Resolved in `af102183` (#1253), verified at `2b8be982`.** The local backend now encrypts
> at rest with AES-256-GCM behind an `enc:v1:` prefix, legacy plaintext is detected and read
> back for compatibility, and the misleading comment quoted below has been corrected. Left in
> place for the record, and because two caveats follow from the fix: the encryption key is
> derived from the deployment-wide shared signing secret, so issue **13** — which exposes that
> secret via `ps` — now undermines encryption at rest rather than being an independent nit;
> and the signing-key write-back in issue **21** bypasses this path entirely, leaving those
> two values as the remaining plaintext in an otherwise-encrypted table.

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

> **Partially addressed in `65482def` (#1254), verified at `2b8be982`.** Deleting a seeded
> policy now sticks: policies carry an `Origin`, and a deletion records a
> `seed.policy.deleted.<name>` tombstone the seeder honours. That closes the trap described
> below, where the wildcard silently returned on restart — the commit message cites it as "a
> real customer issue where project-isolation gaps could not be fixed by policy deletion".
> **The default is unchanged:** `hub-member-read-all` with `ResourceType: "*"` is still seeded
> on every fresh hub, so a new deployment is still open-by-default. The workaround is now
> supported; the posture is not yet safe out of the box.

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

### 20. `hub_id` defaults to a value derived from the hostname, silently re-namespacing every secret 🔴

When `server.hub.hub_id` is not set, the hub derives it from the machine's hostname. That id
is not cosmetic — it is the namespace for both secret storage and object storage.

Secret names are built in `pkg/secret/gcpbackend.go`:

```go
// Format: scion-{scope}-{sha256(hubID:scopeID)[:12]}-{name}
```

and GCS objects are written under `hubs/<hub_id>/...`.

A GCE instance reports a short hostname early in boot and its fully-qualified name once the
metadata-driven hostname is applied. A routine stop/start flipped ours, and the hub id
changed with it. Because the id feeds a hash, a one-character hostname difference produces a
completely unrelated namespace:

```
hub_id  <id A>  ->  secrets under  scion-hub-<hash A>-*
hub_id  <id B>  ->  secrets under  scion-hub-<hash B>-*
```

The consequence is that **every secret the hub previously wrote becomes unreachable**, and
the signing keys are re-derived — invalidating every session and agent token. Nothing fails
loudly. The hub starts, reports healthy, and quietly operates on an empty namespace.

There is a warning, but it fires only when a storage bucket is configured
(`cmd/server_foreground.go`), it is one `WARN` among several hundred startup lines, and it
frames the risk as being about "multi-hub deployments" rather than "your secrets are about to
be orphaned":

```
storage: hub_id was auto-generated from hostname; set an explicit hub_id in settings for
multi-hub deployments
```

We caught it only because we were reading the startup log for an unrelated reason. Pinning
`hub_id` fixed it, and the warning disappeared.


**Suggested fix:** persist the generated `hub_id` to `settings.yaml` on first boot and reuse
it thereafter, so stability is structural rather than something the operator has to know to
ask for. Failing that, refuse to start when a secrets or storage backend is configured and
`hub_id` is unset — a soft warning is not proportionate to losing access to every stored
secret. At minimum, reword it to say what is actually at stake.

### 21. Enabling Secret Manager does not remove plaintext from SQLite — it is rewritten on every boot 🔴

This is issue 11's sibling, and it undercuts the usual remedy for it.

`GCPBackend.Set()` deliberately clears the local copy:

```go
secret.EncryptedValue = "" // Don't store value in DB
secret.SecretRef = "gcpsm:" + fullName
```

The hub then puts it straight back. In `pkg/hub/server.go`, immediately after a successful
sync:

```go
// Re-persist the actual value to SQLite as backup. The backend's Set() stores
// EncryptedValue="" (using a SecretRef), so without this the key material
// would be lost if the secret backend becomes unavailable.
if persistErr := s.backupSigningKeyToStore(ctx, keyName, encodedValue, hubID); persistErr != nil {
```

So with `backend: gcpsm` fully working, `agent_signing_key` and `user_signing_key` are still
present in cleartext in `hub.db`, refreshed on every start. We verified this on a live hub:
the rows carry both a valid `secret_ref` *and* the raw value.

We tried purging the values. They came back on the next restart — which is correct behaviour
given the code. The point is that an operator has no reachable state in which the hub's
internal keys live only in Secret Manager.

The comment is honest about the trade-off and the reasoning is defensible: it protects
against a wiped database. But the effect is that adopting a managed secret store does not
deliver the property most people adopt it for. If issue 11 is read as "use gcpsm in
production", this is the footnote saying it only half-helps.

**Suggested fix:** skip the write-back when the GCP backend is active — Secret Manager is
already the durable copy, which is the entire premise of using it. If the fallback is worth
keeping, encrypt the backup with a key not stored beside it, and document that plaintext
persists locally so operators can make an informed choice.

### 22. Signing keys derive from `SESSION_SECRET`, and there is no documented rotation path 🟠

> **Clarification after re-checking at `2b8be982`.** `docs-site/.../single-node/auth.md`
> states that "the Hub rotates signing keys every 24 hours automatically, maintaining a key
> overlap period". That is accurate, but describes a **different key set** — the RS256 OIDC
> federation keys in `pkg/hub/oidckeys.go`, published via JWKS and used for tokens minted to
> external audiences. The `agent_signing_key` and `user_signing_key` below are not those keys
> and have no rotation of any kind. An operator reading that line could reasonably conclude
> their session signing keys rotate automatically. They do not.

The hub logs its key provenance plainly:

```
ensureSigningKey: derived from shared signing secret   source=shared_secret
```

`agent_signing_key` and `user_signing_key` are derived deterministically from
`SESSION_SECRET`. We confirmed the determinism by accident: across three restarts the derived
values were byte-identical, and changed only once we rotated `SESSION_SECRET`.

Two consequences worth documenting:

1. **Rotating the signing keys means rotating `SESSION_SECRET`** — they are not independent.
   That is a larger action than it sounds, because it invalidates every session and agent
   token at once. There is no staged or partial rotation.
2. **`SESSION_SECRET` lives in cleartext in `hub.env`** (and, per issue 13, in `ps` output
   under the stock systemd template). The material every token ultimately derives from is
   therefore the least protected value in the deployment.

Rotation also leaves the old material behind. Afterwards, Secret Manager held three enabled
versions, the first two being pre-rotation keys. Nothing disables or destroys them, so
superseded keys stay readable to anything holding `secretmanager.versions.access` until an
operator prunes them by hand.

**Suggested fix:** document the rotation procedure, including the logout blast radius and the
need to prune superseded versions. Longer term, letting the signing keys rotate independently
of `SESSION_SECRET` would make routine rotation a non-event rather than a scheduled outage.

### 24. The broker's harness-config resolution has two paths, and both can be empty on a hub-only install 🔴

An agent start failed for three days with:

```
Failed to dispatch to runtime broker: runtime broker returned error 500:
Failed to start agent: failed to find harness-config "copilot": harness-config "copilot" not found
```

The harness-config was present the whole time — global scope, `status: active`, twelve files
listed in the database. What was missing were its *files*, in the places the broker looks.

The broker resolves a harness-config two ways:

1. **Hydrate from the Hub's storage backend** into a content-hash cache, when the dispatch
   request carries `HarnessConfigID` / `HarnessConfigHash`
   (`pkg/runtimebroker/handlers.go`, `hydrateHarnessConfig`)
2. **Fall back to local disk** — `FindHarnessConfigDir` checks the template dir, the project
   dir, then `~/.scion/harness-configs/<name>` (`pkg/config/harness_config.go`)

The fallback is explicit about being a fallback:

```go
// Graceful degradation: if hydration fails, fall back to on-disk only.
```

On a hub-only install both can be empty at once. Nothing populates `~/.scion/harness-configs/`
— that directory is a CLI-workstation convention, and a host that only ever ran the server
never gets one. And hydration fails whenever the files are not in the storage backend the hub
is *currently* configured for, which is exactly what happens after a backend switch, because
the bundled-resource bootstrap skips harness-configs entirely when rows already exist:

```
template bootstrap: repairing storage            name=default issues=1
bundled resource bootstrap: active harness configs exist, skipping harness-config seeding
```

Templates are verified against storage on every boot and repaired. Harness-configs are not:
the check is "do rows exist", not "are the files reachable". A repair path does exist
(`pkg/hub/harness_config_repair.go`) but triggers on content-hash mismatch, and absent files
never produce a mismatch to detect.

The hydration failure is logged at DEBUG and is the only place the real cause appears:

```
Env-gather: harness-config hydration failed, falling back to on-disk
error: failed to download file Dockerfile: download failed with status 404
```

Four things make this very hard to diagnose:

1. **`/healthz` stays `healthy`** while every agent launch is broken.
2. **The error names the harness, not the path.** "harness-config not found" reads as a missing
   or misnamed config — but the row is present and `active`, so the natural first check
   confirms it exists and points away from storage.
3. **The failure surfaces at the runtime broker** as a 502 wrapping a 500, so it reads as a
   broker fault rather than resource resolution.
4. **The cache masks it unevenly.** The hydrated cache is content-hash keyed and shared across
   projects, so once any start succeeds, later starts of the same config keep working while
   uncached ones fail. That makes the failure look like it depends on the project or the user,
   which sends diagnosis in entirely the wrong direction. Ours was reported as "members can't
   create agents" and looked like an authorization gap. It was not one — project policies were
   correct and the authorization check passed. The failure is after authorization, at dispatch.

**Suggested fix:** verify harness-config manifests against the configured storage backend at
boot and repair what is missing, exactly as templates already are — the repair machinery
exists, it just is not called on this path. Failing that, raise the hydration-failure log above
DEBUG, since it is the only signal that names the real cause, and consider surfacing
unreachable resource files in `/healthz` so a hub whose agents cannot start does not report
itself healthy.

### 25. The Create Project page calls an admin-only endpoint and shows its 403 as a blocking error 🟠

A non-admin opening **Create Project** sees this immediately, before typing anything:

> You don't have permission to perform this action on this resource.

Project creation is not denied. The page issues `GET /api/v1/github-app` on load — an
admin-only endpoint, most likely to decide whether to offer a git-backed workspace type
alongside "Hub-managed Workspace" — and the 403 is rendered as an unscoped global error toast:

```
GET  /api/v1/github-app   →  authorization denied   reason="not an admin"
```

There is no `POST /api/v1/projects` in the logs at all when this happens. The user has not
submitted anything; the form is still empty behind the toast.

The impact is out of proportion to the cause. **Every non-admin sees a permission error every
time they open the page they are expected to use most**, worded so it appears to refuse the
action they came to perform. The reasonable response is to stop and report it, which is what
our users did — and it cost real time, because it arrived alongside an unrelated agent-start
failure (issue 24) and the two looked like one permissions problem.

Authorization for project creation is intact and unrelated: the seeded
`hub-member-create-projects` policy grants `project: create` at hub scope to the `hub-members`
group, and clicking through the toast creates the project normally.

**Mechanism, confirmed at `aedf89ed`.** The page's own handler already treats the failure as
non-fatal — `checkGitHubApp()` does `if (!res.ok) return;` inside a `try/catch`. The toast does
not come from the caller at all. `apiFetch` (`web/src/client/api.ts`) dispatches a
`scion:access-denied` event on **every** 403 before returning, and the app shell renders it.
So no amount of caller-side handling suppresses it — the fix has to be in the wrapper or the
call has to not happen for non-admins.

**Suggested fix:** skip the call for non-admins, or let this specific failure degrade quietly —
it only gates an optional workspace type. More generally, a 403 from a background capability
probe should not surface as a modal-level error; scoping error toasts to user-initiated
requests would prevent this class of false alarm.

### 28. The Metrics dashboard is offered to non-admins but its endpoint is admin-only 🟠

Same family as issue 25, found the same way — by reading the hub log while a **member** had
the UI open:

```
WARN  authorization denied  principal_type=user  resource_id="/api/v1/metrics/"
      action=manage  reason="not an admin"  path="/api/v1/metrics/"
DEBUG API client error  status=403  code=forbidden  message="Insufficient permissions"
```

Repeating every second or so, in pairs, for as long as the page was open.

`/api/v1/metrics/` is registered admin-only:

```go
s.mux.HandleFunc("/api/v1/metrics/", s.requireAdminHandler(s.handleMetricsDashboard))
```
`pkg/hub/server.go:3628`

`metrics-dashboard.ts` contains **no admin check of any kind** — we grepped it for
`isAdmin`, `role` and `admin` and got nothing. `loadView()` fetches the endpoint and, on
failure, throws into the page's `error` state:

```ts
const response = await apiFetch(`${basePath}?view=${view}&period=${this.periodDays}`);
if (!response.ok) {
  throw new Error(await extractApiError(response, `HTTP ${response.status}`));
}
```

Two things compound it. Each view (`summary`, `sessions`, `model-calls`, …) is a separate
request, so one page visit produces several 403s rather than one. And because `apiFetch`
dispatches `scion:access-denied` on every 403 (see issue 25), a non-admin sitting on this page
gets a stream of permission toasts on a timer, not just a broken chart.

Note this is the **hub-level** dashboard. The project-scoped variant
(`/api/v1/projects/{id}/metrics`) is a different path and is not admin-gated in the same way,
so the page is partly usable — which is likely why the gap was not obvious.

**Suggested fix:** hide the hub-level Metrics view from non-admins, or have the page probe
capability once and render an explicit "admin only" state instead of failing per-view. The
general fix in issue 25 — not letting background probes raise global error toasts — covers the
toast half of this too.

### 30. Chat is enabled by default but its backing store is not, so the UI renders and every send 503s 🟠

A member opened Scion Chat, selected their agent, typed a message, and got a red
**"Chat not available"** above the composer. The agent showed *Working*, the roster listed it,
the page looked entirely functional.

The hub logged:

```
ERROR  API Error  status=503  code=SERVICE_UNAVAILABLE  message="Chat not available"
```

This is **not** an authorization problem, which is where we looked first — the chat routes
answer `401` rather than `404`, so they are registered, and unrelated chat polling
(`/api/v1/chat/dms`) was authenticating fine throughout.

The 503 comes from a nil store:

```go
s.mu.RLock()
wcs := s.webChatStore
s.mu.RUnlock()

if wcs == nil {
    writeError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Chat not available", nil)
    return
}
```
`pkg/hub/handlers_chat_v2.go:418` — and at four other call sites in the same file.

**Two independent switches, defaulting opposite ways.** `nativeChatEnabled()` defaults to
**true** when unset:

```go
if s.config.NativeChatEnabled == nil {
    return true
}
```

so the routes register and the UI ships. But `SetWebChatStore` is only ever called from one
place — inside the message broker's startup block in `cmd/server_foreground.go:609` — and that
block is gated on:

```go
if vs.Server.MessageBroker != nil && vs.Server.MessageBroker.Enabled {
```

with `Enabled bool // Default false`. So out of the box chat is *on*, its store is *nil*, and
every send fails. Nothing at startup says so; `/healthz` is 200 throughout.

The message on screen is also the least useful of the available truths. "Chat not available"
is what an operator sees after they have already enabled chat — it names the feature that *is*
enabled rather than the subsystem that is not.

### The fix is one key, and the schema does not allow it

Adding this to `settings.yaml` and restarting fixes it completely:

```yaml
server:
    message_broker:
        enabled: true
```

We ran it. The broker came up on the default in-process adapter — no NATS, no external
dependency:

```
Message broker spoke added: name=web channel_id=web observer=true
Message broker proxy started
Message broker started: fan-out with 2 spoke(s)
```

But `server.message_broker` **is not in the settings schema**. `settings-v1.schema.json`
declares:

```
server.additionalProperties: false
server properties: auth, broker, database, env, hub, log_format, log_level,
                   oauth, scheduler, secrets, storage
```

Neither `message_broker` nor `native_chat` appears, though both exist on `V1ServerConfig` in
`pkg/config/settings_v1.go`. The chart's `values.schema.json` does not mention
`message_broker` either. So the one key that turns chat on is a key the published schema
forbids. In our case it was accepted and worked — the schema is evidently not enforced on this
load path — but anyone validating their config against the schema, or generating it from the
new GKE chart, has no supported way to express it.

**Suggested fix:** three small things, any of which would have saved the trip. Default
`native_chat.enabled` to *false* unless the broker is enabled, or have the chat routes report
the real reason ("message broker disabled") instead of "Chat not available". Log a line at
startup when chat is enabled without a store. And add `message_broker` and `native_chat` to
`settings-v1.schema.json`, since `additionalProperties: false` currently makes a working
configuration an invalid one.

### 31. Progeny agents still cannot inherit captured credentials after #1292 — two further blockers 🔴

An orchestrator creates sub-agents; the sub-agents come up unauthenticated. Preston diagnosed
this and shipped `4b683622` ("make hasAnyKey progeny-aware", #1292, closing #1252): for a
progeny agent, `agent.OwnerID` is the *creating agent's* ID, so the user-scope lookup misses,
`NoAuth` is set preemptively, and the working `ListProgenySecrets()` path never runs.

**That fix is correct, it is deployed here, and the symptom persists.** We upgraded to
`aedf89ed` (which contains it) at 19:41 and the progeny agents below were created at 20:32 —
after the fix, still with no credentials. Two further conditions have to hold, and neither does.

The state, straight from the hub database:

```
agents (created 20:32, by the orchestrator)
  owner_id = b77a535e…            ← the orchestrator agent, as #1292 describes
  ancestry = ["4d72d36b-…"]  → for progeny: ["4d72d36b-…", "b77a535e-…"]   (len 2 ✓)

secrets
  COPILOT_CONFIG  scope=user     scope_id=4d72d36b-…(the user)
                  created_by='agent:da73beb6-…'   allow_progeny=0
```

`hasAnyKey`'s new progeny branch calls `ListProgenySecrets(ctx, agent.Ancestry)`, which is:

```go
s.client.Secret.Query().Where(
    entsecret.ScopeEQ(store.ScopeUser),
    entsecret.AllowProgenyEQ(true),
    entsecret.CreatedByIn(ancestorIDs...),
)
```
`pkg/store/entadapter/secret_store.go:294`

**Blocker 1 — `allow_progeny` is 0, and the capture flow cannot set it.** The web UI can:
`secret-list.ts` sends `allowProgeny` for user-scoped secrets, and the API accepts it
(`handlers_env_secrets.go:918`). But `sciontool secret set` exposes only `--type`, `--target`,
`--force` and `--scope`:

```
secretSetCmd.Flags().StringVar(&secretScope, "scope", "", "Secret scope: project (default) or user")
```
`cmd/sciontool/commands/secret.go:248-251`

`capture_auth.py` shells out to exactly that command. So a credential captured through the
documented Capture Auth flow is **always** written with `allow_progeny = 0` and can never be
inherited, no matter what the hub does.

**Blocker 2 — `created_by` can never match the ancestry, by format.** Agent-authored secrets
are written as:

```go
CreatedBy: fmt.Sprintf("agent:%s", agentID),
```
`pkg/hub/handlers_env_secrets.go:1211`

while `ancestry` holds bare UUIDs (`["4d72d36b-35fa-…"]`, verified in the DB). `CreatedByIn`
does a literal `IN`, and we found no normalisation of the `agent:` prefix anywhere in the
secret path — the `TrimPrefix(…, "agent:")` calls in the tree are all in messaging and chat.

So `"agent:b77a535e-…"` is compared against `"b77a535e-…"` and never matches. Even with
`allow_progeny = 1`, and even if the *same* orchestrator captured the credential, an
agent-created secret cannot satisfy this query. Only a secret created by a **user** —
`createdBy = userIdent.ID()`, a bare UUID (`handlers_env_secrets.go:395`) — can.

Which means #1292's progeny branch is currently reachable only for credentials created through
the UI, and never for credentials captured by an agent, which is the flow the feature exists to
serve.

**Suggested fix:** normalise the prefix in `ListProgenySecrets` / `ListProgenyEnvVars` (compare
`TrimPrefix(created_by, "agent:")` against the ancestry, or store ancestry and `created_by` in
one consistent form) — that is the actual bug. Then add `--allow-progeny` to
`sciontool secret set` and a `--progeny` pass-through in `capture_auth.py`, so the capture flow
can produce an inheritable credential at all. A hub-side warning when an agent creates a
user-scoped secret that its own progeny will not be able to read would have made this visible
immediately.

**Confirmed empirically.** We set `allow_progeny = 1` and rewrote `created_by` to the bare
user UUID on the existing secret. Progeny agents created afterwards resolve correctly:

```
implementer  20:52:27  ancestry=2  harnessAuth='auth-file'   noAuth=—
analyst      20:51:57  ancestry=2  harnessAuth='auth-file'   noAuth=—
(before)               ancestry=2  harnessAuth='none'        noAuth=true
```

and the credential file is delivered into the containers (`/home/scion/.copilot/config.json`,
mode 600). Changing those two columns — and nothing else — is what moved it, which confirms
both blockers above are real and that they are the only two remaining after #1292.

**The symptom to recognise.** Before the fix the failure surfaced as a complaint about
`COPILOT_GITHUB_TOKEN` not existing, which is misleading: that key belongs to the *other* auth
type. Copilot declares `default_type: api-key` (requiring `COPILOT_GITHUB_TOKEN`) alongside
`auth-file` (requiring `COPILOT_CONFIG`), with autodetect mapping `COPILOT_CONFIG → auth-file`.
When the progeny lookup finds nothing, resolution falls back to `default_type`, and the user is
told a token is missing for an auth type they never chose. Anyone hitting this will search for
the wrong thing.

### Blocker 3 — `resolveSecrets` still returns nothing, even with 1 and 2 fixed

With `allow_progeny = 1` and `created_by` set to the bare user UUID, `hasAnyKey` now succeeds
and auth resolves to the right type:

```
auth: after overlay — selectedType="auth-file"
```

But the credential is still never delivered:

```
resolveSecrets: querying secret backend  ownerID=3f1926b8-…  project_id=1afd7fe5-…
resolveSecrets: resolved secrets  count=0  names=[]
auth: resolved — method="container-script", envVars=map[SCION_HARNESS_SELECTED_AUTH:auth-file], files=0
```

`count=0`, `files=0`. The agent starts, Copilot finds no credentials and writes its own default
`config.json` (175 bytes, keys `firstLaunchAt` and `trustedFolders` only), and the session
reports **"Please use /login to sign in to use Copilot"**. Note the failure is silent from the
hub's side — nothing is logged as an error, and the agent is healthy.

The progeny branch in `resolveSecrets` (`pkg/hub/httpdispatcher.go:2623`) is gated on two
conditions and then filters through an authorization callback:

```go
if len(agent.Ancestry) > 1 && d.authzService != nil {
    resolveOpts = &secret.ResolveOpts{
        AgentAncestry: ancestry,
        AuthzCheck: func(s secret.SecretMeta) bool {
            decision := d.authzService.CheckAccess(ctx, …, Resource{Type: "secret", ID: s.ID}, ActionRead)
            return decision.Allowed
        },
    }
}
```

`len(agent.Ancestry) > 1` holds for these agents (ancestry is 2). We could not determine from
outside which of the remaining conditions fails: **no secret authorization denial appears in
the log at all**, while unrelated denials (e.g. `/api/v1/metrics/`) are logged at WARN. That
asymmetry suggests the branch is not running rather than the secret being rejected — but we are
stating that as an inference, not a conclusion. Either way the observable result is that
progeny secret resolution does not work on this build with the **gcpsm** backend.

Both `localbackend.go:209` and `gcpbackend.go:368` implement the progeny query identically and
gate it on `opts.AgentAncestry`, so the backend choice is not the differentiator; the options
struct simply arrives empty or its `AuthzCheck` rejects everything.

**Net effect:** #1292 fixed the first gate. Two more sit behind it, and a credential captured
by an agent through the documented flow still cannot reach that agent's progeny.

**Practical workaround for operators today:** capture at **project** scope
(`capture_auth.py --scope project --force`). Project-scoped secrets resolve through the ordinary
path with no progeny logic and no authz callback, so every agent in the project — progeny
included — receives them. The cost is that the credential is shared with everyone who can run
agents in that project, which is exactly what user scope exists to avoid.

**Workaround for the earlier blockers, exercised end-to-end:** create the user-scoped
secret from the **web UI** with "allow progeny" enabled rather than via Capture Auth. That
yields `created_by = <bare user UUID>` (in the ancestry) and `allow_progeny = 1`, satisfying
both conditions. Project-scoping the credential also works and sidesteps progeny entirely,
since `hasAnyKey` checks `project` scope directly — at the cost of sharing it with everyone in
the project.

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

> **Appears resolved as of `2b8be982`** — the key is no longer present in `pkg/config`. We
> confirmed this by search rather than by exercising the config path, so treat it as likely
> rather than verified.

`gce-start-hub.sh` writes `default_runtime: ${DEFAULT_RUNTIME}` into `settings.yaml`,
but no such key exists in the Go config schema. The hub **silently strips it** when it
rewrites the file on startup.

This is actively misleading: it reads as though it controls agent placement, and an
operator setting `default_runtime: docker` will believe they've configured something.

**Suggested fix:** remove it from the template, or implement it. Related — see
issue 8 on silent key-dropping.

---

### 33. Clone credentials are injected by string replace, which corrupts any URL that already has a username 🔴

Cloning an Azure DevOps repository fails with:

```
remote: TF401019: The Git repository with name or identifier connections-ai.git does not
exist or you do not have permissions for the operation you are attempting.
fatal: repository 'https://dev.azure.com/jbhunt/…/_git/connections-ai.git/' not found
```

The repository exists and the token is valid. The credential is being mangled before git ever
sees it:

```go
authURL = strings.Replace(cloneURL, "https://", "https://oauth2:"+token+"@", 1)
```
`pkg/util/git.go:567`

That assumes the clone URL has no userinfo. Azure DevOps' Clone dialog hands you
`https://<user>@dev.azure.com/<org>/<project>/_git/<repo>`, so the replace produces:

```
https://oauth2:<TOKEN>@Anthony.Lofton@dev.azure.com/…
                      ↑                ↑   two @ signs
```

Git splits userinfo at the last `@`, so it authenticates as username `oauth2` with password
`<TOKEN>@Anthony.Lofton`. The PAT is corrupted, auth fails, and ADO answers `TF401019` — a
message it uses for both "no such repo" and "no permission", so it points the operator at the
repository name rather than at their credentials. We spent the whole investigation looking at
the wrong half of the error.

GitHub never exposes this because GitHub clone URLs carry no userinfo.

**Correction — this is a latent bug, not the cause of our failure.** We initially reported this
as the reason our Azure DevOps clone failed. It was not. Scion has two clone paths, and only
one has the flaw:

| Path | Function | Behaviour |
|---|---|---|
| Project shared-workspace | `CloneSharedWorkspace` (`pkg/util/git.go:567`) | `strings.Replace` — **broken** for URLs with userinfo |
| Per-agent, in container | `buildAuthenticatedURL` (`cmd/sciontool/commands/init.go`) | `url.Parse` + `url.UserPassword` — **correct** |

Our project uses per-agent clone, which already does the right thing:

```go
parsed.User = url.UserPassword("oauth2", token)
```

`url.UserPassword` replaces any existing userinfo rather than prepending to it, so the username
in our URL was dropped cleanly. The issue below stands as a real defect in the shared-workspace
path — and notably **the correct implementation already exists in the same repository**, so the
fix is to copy it, not to invent it.

**Suggested fix:** parse the URL and set userinfo, rather than string-replacing the scheme:

```go
u, err := url.Parse(cloneURL)
if err != nil { return err }
if token != "" {
    u.User = url.UserPassword("oauth2", token)   // replaces any existing userinfo
}
authURL := u.String()
```

`net/url` already handles this correctly and drops the pre-existing username. The credential
helper path used by pull (`pkg/util/git.go:656`) is not affected — it passes the token out of
band, which is the safer pattern and could be used for clone too.

### The wider gap: the git path only knows GitHub

Worth noting alongside the above, since it shapes the whole experience of connecting a
non-GitHub remote:

- `resolveCloneToken` looks for exactly three things: a GitHub App installation token, a
  project secret named literally `GITHUB_TOKEN`, then the creating user's `GITHUB_TOKEN`.
  There is no provider-neutral key and no per-host credential mapping.
- The failure guidance is hardcoded to `"Check that GITHUB_TOKEN (or GitHub App credentials)
  are valid…"` regardless of the host being cloned.
- The injected username is hardcoded to `oauth2`.

Azure DevOps works despite this — it accepts any username with a PAT as the password — but only
by coincidence. To connect ADO an operator must store an Azure PAT under a secret named
`GITHUB_TOKEN`, which is misleading enough that anyone auditing the secret list later will
misread it.

**Suggested fix:** accept a provider-neutral secret name (`GIT_TOKEN`, or per-host
`GIT_TOKEN_<HOST>`) with `GITHUB_TOKEN` kept as a fallback, and make the error guidance name
the host it actually failed against.

### What actually broke our clone: a `.git` suffix

The cause, after eliminating the two above, was the `.git` suffix on the clone URL. Azure
DevOps treats it as part of the repository identifier:

```
TF401019: The Git repository with name or identifier connections-ai.git does not exist
```

Removing it — `…/_git/connections-ai` rather than `…/_git/connections-ai.git` — made the clone
succeed immediately, with everything else unchanged.

That was our own input, so it is not a defect on its own. What makes it worth recording is that
`ToHTTPSCloneURL` **adds** the suffix unconditionally when normalising a schemeless remote:

```go
// Ensure .git suffix
if !strings.HasSuffix(result, ".git") {
    result += ".git"
}
```
`pkg/util/git.go:530`

That is a GitHub convention. Our project's `git_remote` is stored schemeless
(`dev.azure.com/jbhunt/…/_git/connections-ai`), so any path that normalises it will append
`.git` and produce a URL Azure DevOps rejects. We were saved only because the `clone-url` label
carried an explicit scheme, which `normalizeCloneURLLabel` passes through untouched.

**Suggested fix:** only append `.git` for hosts where it is correct, or drop the behaviour —
GitHub, GitLab and Bitbucket all serve fine without it, and Azure DevOps does not tolerate it.

### 34. A project-scoped `GITHUB_TOKEN` can never authenticate the initial clone 🟠

After fixing issue 33 the clone failed differently:

```
git clone failed (no GITHUB_TOKEN secret configured — the repository may require
authentication): fatal: could not read Username for 'https://dev.azure.com':
terminal prompts disabled
```

The project **did** have a `GITHUB_TOKEN` secret at project scope. It cannot be reached,
because of ordering:

```go
// handlers_projects_core.go:506 — inside project creation
if err := s.cloneSharedWorkspaceProject(ctx, project); err != nil {
```

The clone runs **as part of creating the project**. A project-scoped secret can only be
attached once the project exists, which is strictly after the clone has already run. So the
project-scoped branch of `resolveCloneToken`:

```go
sv, err := s.secretBackend.Get(ctx, "GITHUB_TOKEN", "project", project.ID)
```

is unreachable for the initial clone by construction. It can only ever serve later operations.

**There is no retry.** We grepped for a re-clone or retry path and there is none —
`cloneSharedWorkspaceProject` is called from exactly two places, project creation and project
cloning. Once the initial clone fails, the only recourse is to delete the project and create it
again, which produces a new project ID and therefore loses the project-scoped secret again.
That is a loop an operator can repeat indefinitely without ever succeeding.

The working path is the *user*-scoped fallback:

```go
// Fall back to the creating user's profile-level GITHUB_TOKEN
sv, err = s.secretBackend.Get(ctx, "GITHUB_TOKEN", "user", project.CreatedBy)
```

which exists before any project does. Nothing in the UI or the error message says so. The
error says "no GITHUB_TOKEN secret configured" while a `GITHUB_TOKEN` secret is plainly visible
in the project's own secret list — which reads as a bug in the hub rather than a scope
mismatch.

**Correction — a supported path does exist, and we missed it.** The create-project request
accepts a `gitHubToken` field, and the handler writes it as a project-scoped secret
*before* the clone runs (`handlers_projects_core.go`, with the comment "This must happen before
cloneSharedWorkspaceProject"). So supplying the token in the creation form does work. What does
not work is the far more discoverable route: create the project, watch the clone fail, add a
`GITHUB_TOKEN` secret to the project, and retry. That sequence can never succeed, and it is the
one an operator naturally takes.

**Suggested fix:** the error is the cheap part — distinguish "no token found at user scope" from
"no token configured", and name the scopes searched. Adding a retry-clone action for a project
whose initial clone failed would make the project-scoped secret usable after the fact and close
the loop entirely.

### 35. Recreating a project with the same name leaves a marker pinned to the deleted project, breaking all agent creation 🔴

After deleting and recreating a git project a few times while debugging a clone, every agent
creation failed:

```
Failed to dispatch to runtime broker: runtime broker returned error 500:
Failed to create agent: workspace directory does not exist:
/home/scion/.scion/project-configs/connections-ai-ado__3a57faf5/.scion/agents/test/workspace
(try deleting and recreating the agent)
```

`3a57faf5` is the id of a project that **no longer exists**. The live project is `bf1c7cfb`.

The cause is a marker file keyed by slug rather than by project id:

```
$ cat /home/scion/.scion/projects/connections-ai-ado/.scion
project-id: 3a57faf5-51ae-4afb-b996-6f19946af700
project-name: connections-ai-ado
project-slug: connections-ai-ado
```

`~/.scion/projects/<slug>/` survives project deletion. Creating a project with the same name
reuses that directory, and nothing rewrites the marker, so the broker resolves the *new*
project to the *old* project's config directory — `project-configs/<slug>__<old-short-id>/` —
where the expected agent workspace does not exist.

Once in this state the hub is stuck for that project. Confirming the shape:

```
project-configs/
  anthony-s-main-project__1afd7fe5      ← healthy, id matches
  connections-ai-ado__3a57faf5          ← the deleted project's id
  (no connections-ai-ado__bf1c7cfb)     ← nothing for the live project
```

**The remediation the error suggests makes it worse.** "try deleting and recreating the agent"
cannot help — the agent is not what holds the stale id. And the instinctive next step, deleting
and recreating the *project*, reproduces the fault exactly, because the marker is untouched by
both operations. An operator can loop on this indefinitely. We reached it by recreating one
project five times while debugging something unrelated.

We fixed it by rewriting `project-id` in the marker to the live project and moving the orphaned
`project-configs/<slug>__<old-id>/` directory aside. Agent creation recovered immediately.

**Suggested fix:** rewrite the marker on project creation rather than only on first creation —
it is a three-line write and the id is already in hand. Failing that, key the directory by
project id rather than slug, so a recreated project cannot collide with its predecessor. And
either way, make the error name the mismatch ("project bf1c7cfb resolved to a config directory
belonging to 3a57faf5") instead of printing a path and suggesting an action that cannot work.

Worth noting the same class of staleness appears elsewhere: issue 26 (a deleted harness config
returns on restart because its on-disk directory is re-imported). Deletion consistently removes
the database row while leaving the filesystem artefact that will resurrect or misdirect it.

## Docs that are wrong

### 4. OIDC redirect URI is wrong in the setup guide 🔴

> **Source: the `oidc-setup.md` draft, not a file in this repository.** It was sent to us
> directly rather than published, so it will not be found under `docs/` or `docs-site/`.
> Our understanding is that it is a candidate for release — which is why these are worth
> fixing before it ships rather than after. **Re-confirmed against that draft at
> `2b8be982`: still present.**

The circulating `oidc-setup.md` instructs registering:

```
https://<hub-domain>/api/v1/auth/oidc/callback
```

The wrong URI appears **twice** — once in the setup values and again in the troubleshooting
section, which tells a reader who is already debugging a failed callback to "verify the
redirect URI matches exactly" against the same wrong value. That closes off the most likely
route to self-diagnosis.

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

> **Source: the `oidc-setup.md` draft, not a file in this repository.** It was sent to us
> directly rather than published, so it will not be found under `docs/` or `docs-site/`.
> Our understanding is that it is a candidate for release — which is why these are worth
> fixing before it ships rather than after. **Re-confirmed against that draft at
> `2b8be982`: still present.**

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

> **Source: the `oidc-setup.md` draft, not a file in this repository.** It was sent to us
> directly rather than published, so it will not be found under `docs/` or `docs-site/`.
> Our understanding is that it is a candidate for release — which is why these are worth
> fixing before it ships rather than after. **Re-confirmed against that draft at
> `2b8be982`: still present.**

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

### 23. The same setting is spelled two different ways depending on where you set it 🟡

`gcp_project_id` and `gcpProjectId` are both correct — for different files.

`settings.yaml` is parsed by the v1 schema, where the secrets block is snake_case:

```go
// pkg/config/settings_v1.go
type V1SecretsConfig struct {
    GCPProjectID string `yaml:"gcp_project_id" koanf:"gcp_project_id"`
}
```

Environment variables land in `GlobalConfig`, where the same field is camelCase:

```go
// pkg/config/hub_config.go
type SecretsConfig struct {
    GCPProjectID string `yaml:"gcpProjectId" koanf:"gcpProjectId"`
}
```

and `pkg/config/hub_config.go` carries two lookup tables that disagree by design:

```go
var snakeCaseFields = map[string]string{ "gcpprojectid": "gcp_project_id", ... }
var camelCaseFields = map[string]string{ "gcpprojectid": "gcpProjectId",   ... }
```

Neither spelling is wrong; each is right in its own path. But there is no error, no warning,
and no hint at the point of use — a snake_case key in the camelCase path is simply dropped.
Adjacent settings make it easy to draw the wrong conclusion: `telemetry.cloud.gcp_project_id`
in the same `settings.yaml` really is snake_case, so the file appears to establish a
convention that the env path does not follow.

**Suggested fix:** accept both spellings at the config layer, or warn when a recognised field
appears under the wrong casing. This compounds issue 8 — unknown keys are already silently
ignored, so a casing mistake is indistinguishable from a typo.

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


### 29. Agent telemetry is enabled by default but cannot work until a GCP service account is assigned, and it fails silently forever 🟠

Every agent container we start is given:

```
SCION_TELEMETRY_ENABLED=true
SCION_TELEMETRY_DEBUG=true
GCE_METADATA_HOST=localhost:18380
GCE_METADATA_ROOT=localhost:18380
```

so the telemetry client authenticates through Scion's in-container metadata proxy. That proxy
returns **403 for the token endpoint**:

```
$ curl -H "Metadata-Flavor: Google"     http://localhost:18380/computeMetadata/v1/instance/service-accounts/default/token
Forbidden
```

**This is not a GCP IAM problem, and that is worth stating clearly** — we assumed it was at
first. The host's own service account works fine (`http=200` from the VM, `cloud-platform`
scope). The proxy is refusing because there is nothing to mint a token *from*:

```
gcp_service_accounts: 0 rows
```

No service account has been registered with the hub, so the proxy correctly declines. The
telemetry exporter, however, does not treat that as terminal — it retries indefinitely:

```
[sciontool] INFO: [slog] failed to export to Google Cloud Trace: rpc error:
  code = Unauthenticated ... cannot fetch token: compute: Received 403 `Forbidden`
```

| Agent | occurrences of that line |
|---|---|
| `agent-A` (up ~25h) | 3,015 |
| `agent-B` (up ~19h) | 2,337 |

Three things make this worse than a missing feature flag:

1. **It is on by default.** An operator who never opts into GCP telemetry still gets an agent
   that tries, and fails, thousands of times per day.
2. **It is logged at `INFO`.** A continuously failing authenticated export is not an
   informational event. At INFO it is invisible in normal operation and pure noise in debug.
3. **Nothing surfaces it.** The hub reports healthy, the agent works normally, and the metrics
   dashboard is simply empty — which reads as "no activity yet" rather than "telemetry has
   never once succeeded".

This is the same root cause as issues 14 and 15 seen from the agent side: the telemetry path
has several independent prerequisites and no single place tells you which one is missing.

**Suggested fix:** do not enable the cloud exporter unless a service account is actually
resolvable; log the first failure at WARN with the reason ("no GCP service account assigned to
this agent") and then stop or back off hard rather than retrying every few seconds forever. A
one-line hub-side preflight — "telemetry enabled but 0 service accounts registered" — would
have saved the whole investigation.

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

**Re-tested at `aedf89ed`, and the result is partly inconclusive — worth stating plainly.**
We appended an unknown top-level key to a live `settings.yaml` and restarted. The key was
**not** removed, and **no warning was logged**. The no-warning half of this issue therefore
still stands. The dropping half we could not reproduce this time: the rewrite is what discards
unknown keys, and on this hub `server.broker.broker_id` is already present, so no rewrite was
triggered. We are leaving the issue open rather than claiming either outcome — the silent
acceptance of an unrecognised key is confirmed, the discarding is not re-confirmed.

**Suggested fix:** log at WARN for each unrecognised key encountered during load.
Cheap to implement, and it turns a silent misconfiguration into an obvious one.

### 9. The image build cannot be pointed at an internal package registry 🟠

Originally filed as an `npm install` annoyance in `make web`. It is broader than that: **the
container image build has no way to reach an internal mirror**, and on a network that blocks
public registries it stops the build outright.

Six of the eleven images fetch from a language package manager — `core-base` and the
`claude`, `codex`, `gemini-cli` and `opencode` harnesses run `npm install -g`; `hermes` runs
`pip install`. All of them address the public registry directly:

```
npm error code ECONNRESET
npm error network request to https://registry.npmjs.org/chrome-devtools-mcp failed
```

```
ERROR: Could not find a version that satisfies the requirement hermes-agent[vertex]
       (from versions: none)
```

`core-base` is the root of the DAG, so this is not a partial failure — **none of the eleven
images build**. Worth noting that `deb.debian.org`, `dl.k8s.io`, `go.dev` and
`raw.githubusercontent.com` all succeeded in the same build. Only npm and pip are affected.

### The fix is small, and we have it running

Because every image descends from `core-base`, a single `ENV` there covers the whole DAG —
and agents at runtime as well:

```dockerfile
# Optional npm mirror. Defaults to the public registry, so behaviour is
# unchanged when unset.
ARG NPM_REGISTRY=https://registry.npmjs.org/
ENV NPM_CONFIG_REGISTRY=${NPM_REGISTRY}
```

with a matching passthrough in `image-build/scripts/lib/targets.sh` so the orchestrator emits
the build-arg only when `NPM_REGISTRY` is set.

**The credential must not be a build-arg.** Mirrors generally require authentication, and a
build-arg is recoverable from `docker history` — publishing those images would leak the
token. A BuildKit secret keeps it out of every layer:

```dockerfile
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc,required=false npm install -g chrome-devtools-mcp
```

fed by `--secret id=npmrc,src=...` in the local-docker and local-podman builders, gated on an
optional `NPM_CONFIG_FILE`. `required=false` keeps unauthenticated builds working unchanged.
We verified the token does not survive into the images (`docker history | grep -c authToken`
→ `0`).

With those changes all npm-based images build against an internal Artifactory mirror. `hermes`
still fails — the same treatment for `PIP_INDEX_URL` would close it, and we have not written
that half.

**One trap worth documenting for anyone doing this.** Our mirror returns **404 for any package
not already in its cache**, and only an *authenticated* request causes it to fetch from
upstream. An unauthenticated build therefore fails with `E404 ... is not in this registry` —
indistinguishable from "this package does not exist". We lost time concluding the packages were
blocked by policy before testing a known-good package cold and watching it go
`404 anonymous → 200 authenticated → 200 anonymous`. If the docs mention the mirror case at
all, this failure mode is worth a sentence.

**Suggested fix:** take the `ARG NPM_REGISTRY` / secret-mount pattern above (happy to send it
as a PR), add the `pip` equivalent for `hermes`, and document both in the image-build README.

### 26. No supported way to hide a harness config, and deleting one reverts on restart 🟠

A hub ships eight global harness configs. Most teams use two or three, but every one of them
appears in the agent-creation picker, including harnesses whose images the operator never
built — picking one of those produces a runtime failure rather than a clear "not available".

There is no disable or hide operation. The CLI offers `scion harness-config delete <name>`,
but for a bundled config that does not stick: `BootstrapHarnessConfigsFromDir`
(`pkg/hub/harness_config_bootstrap.go`) re-imports any directory present under
`~/.scion/harness-configs/` whose row is missing —

```go
if existing == nil {
    if err := s.bootstrapSingleHarnessConfig(ctx, name, dirPath, hcDir, stor); err != nil {
```

— so the config is deleted, the hub restarts, and it comes straight back. This is the same
shape as issue 16's seeded-policy problem, which `65482def` (#1254) fixed for policies with an
`Origin` field and deletion tombstones. Harness configs did not get that treatment.

The schema already has what is needed. `harness_configs.status` accepts
`pending | active | archived`, and the list handler filters to active by default:

```go
// Default to active harness configs only
if filter.Status == "" {
    filter.Status = store.HarnessConfigStatusActive
}
```
`pkg/hub/harness_config_handlers.go:170`

But **nothing an operator can reach ever sets `archived`**. The only writer is
`ArchiveObsoleteBundledHarnessConfigs`, which archives configs dropped from the binary — not
ones an operator wants to hide. We ended up setting `status='archived'` directly in SQLite and
moving the four unwanted directories out of `~/.scion/harness-configs/`, which held across a
restart. That is not something an operator should have to do.

**Update — it did survive an upgrade.** We later moved the hub from `2b8be982` to `aedf89ed`,
a 23-commit jump that *added* a `grok-build` harness, and all four archived configs stayed
archived. So the workaround is more durable than we expected. It is still a workaround: it
requires writing to the hub's database by hand, and nothing in the product surfaces it.

**Suggested fix:** expose the existing `archived` status — `harness-config disable/enable`, or
an admin toggle — and give bundled harness configs the same tombstone treatment policies got in
#1254 so a delete is not silently undone.

### 27. The image build cannot target a single image, so one broken image blocks the rest 🟡

`build-images.sh --target` accepts only groups:

```
Error: unknown --target 'scion-opencode'
Allowed: core-base thick-prep scion-base harnesses hub common all thick
```

Steps run in a fixed order and the run aborts on the first failure. `hermes` sorts before
`opencode`, so when `hermes` failed on its `pip install` (issue 9) the run stopped and
`opencode` and `scion-hub` were never attempted — despite having nothing to do with the
failure and being perfectly buildable.

There is no `--only`, no skip-on-failure, and no resume. To get the one image we needed we
dropped to a hand-written `docker build`, reproducing the `BASE_IMAGE` wiring that
`step_build_args` normally computes — easy to get subtly wrong, and it bypasses the tag
scheme the orchestrator applies.

This matters more in an enterprise than upstream, because the images likeliest to fail are the
ones reaching a blocked registry, and they take unrelated images down with them.

**Suggested fix:** let `--target` accept any step id (the ids already exist in
`step_dockerfile`/`step_parent`), and/or add `--continue-on-error` so one bad image does not
abort the rest of the group.

### 32. Agents cannot create a chat thread — the chat API is user-identity-only *(feature request)* 🟡

An orchestrator that spawns a team has no way to open a thread for it. We wanted a newly
created agent to start a thread so its human owner had somewhere to follow along; there is no
path to it. Verified three ways against `1befe923`:

**1. No agent-facing command.** `sciontool` has no chat or thread subcommand at all. The
`scion-messaging` platform skill offers `--thread-id`, but the flag only *targets* a thread
that already exists:

```
--thread-id <id>   Use this to reply within a specific project thread
```

and `cmd/message.go:117` requires it to accompany `--channel`. There is no create verb.

**2. Every chat endpoint requires a user identity.** All 26 handler entry points across
`handlers_chat_v2.go` and `handlers_chat.go` begin the same way:

```go
user := GetUserIdentityFromContext(r.Context())
if user == nil {
    Forbidden(w)
    return
}
```

and that helper is a type assertion:

```go
if user, ok := identity.(UserIdentity); ok {
    return user
}
return nil
```

An agent principal is not a `UserIdentity`, so it returns nil and every chat call from an agent
is a 403. We grepped the chat handlers for any agent-identity path — `GetAgentIdentityFromContext`,
`AgentTokenClaims`, `agentIdentity` — and there is none.

**3. Agent-sent messages never create thread state.** In the broker inbound path, thread and
channel affinity are recorded only for user senders:

```go
if s.webChatStore != nil && req.Message.Channel != "" && strings.HasPrefix(req.Message.Sender, "user:") {
        … RecordChannel(…)
        … TouchThread(…)
```
`pkg/hub/handlers_broker_inbound.go:266`

So even sending a message with a fresh `--thread-id` does not bring a thread into being. A
thread can only originate from a human action.

**Why it matters.** The orchestrator pattern the product encourages — one agent spawning a
team of specialists — has no way to give that team a home in chat. The human has to create the
thread first and hand the ID down, which inverts the flow and cannot be automated from a
template.

**Suggested fix:** accept an agent principal on the conversation-creation path, scoped to the
agent's own project, with the creating agent's owner as the thread's user. Everything else can
stay user-only. Note `9668909c` (#1331, "conversation model foundation") lands a `Conversation`
ent model but no agent-facing API — if agent-created conversations are wanted eventually, that
schema is the natural place to allow an agent principal rather than retrofitting later.

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
| **35** | **Rewrite the project marker on creation — a recreated project inherits the deleted one's id and all agent creation fails** | **Blocking** | **Trivial** |
| **33** | **Build the authenticated clone URL with `net/url` instead of `strings.Replace` — any remote with a username currently gets corrupted credentials** | **Blocking** | **Trivial** |
| **31** | **Progeny credential inheritance is unreachable for agent-captured secrets: `created_by` carries an `agent:` prefix the ancestry match does not strip** | **Blocking** | Low |
| **11** | **Local backend stores plaintext while its comment claims writes are rejected** | **Security** | Low–Med |
| **16** | **All authenticated users can read all projects by default; `visibility` is inert** | **Security** | Low |
| **17** | **`viewer` role implies a restriction it does not enforce** | **Security** | Low |
| **18** | **Per-project member seed omits `project: read` — membership confers no visibility** | **Security** | Low |
| **20** | **`hub_id` derives from the hostname; a hostname change silently orphans every secret** | **Security** | Low |
| **21** | **Secret Manager values are rewritten to SQLite in cleartext on every boot** | **Security** | Low |
| **22** | **Signing keys derive from `SESSION_SECRET`; rotation is undocumented and leaves old versions enabled** | **Security** | Low |
| **24** | **Harness-config files unreachable in both resolution paths break every agent start, while the hub reports healthy** | **Blocking** | Low |
| **25** | **Create Project shows a permission error to every non-admin on page load** | **High** | Trivial |
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
| 34 | Make the clone-token error name the scopes searched, and add a retry-clone action | High | Low |
| 30 | Chat ships enabled with a nil store when the message broker is off; add `message_broker`/`native_chat` to the settings schema | High | Low |
| 28 | Hide the hub-level Metrics view from non-admins, or render an explicit admin-only state | High | Trivial |
| 29 | Do not enable the cloud telemetry exporter without a resolvable service account; WARN once and back off | High | Low |
| 26 | Expose the existing `archived` status so harnesses can be hidden; tombstone bundled configs so delete sticks | High | Low |
| 6 | Fix dev-auth cleanup user (`scion@localhost`) | Medium | Trivial |
| 9 | Accept an internal package registry in the image build; without it no image builds at all (patch available) | High | Low |
| 23 | Accept both `gcp_project_id` and `gcpProjectId`, or warn on wrong casing | Medium | Low |
| 27 | Let `--target` accept a single image id; add `--continue-on-error` | Medium | Low |
| 19 | Accept a zip upload for template import (extractor already exists) | Low (feature) | Low |
| 32 | Let an agent principal create a conversation in its own project | Low (feature) | Medium |
| 10 | `--version` alias; drop NATS; placeholder registry | Low | Low |

Happy to supply logs, configs, or test any of these against our environment — we have
a working internal deployment we can iterate on.
