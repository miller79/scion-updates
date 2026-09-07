# Notes from a Scion starter-hub deployment inside an enterprise

*Anthony Lofton — August 2026*

We stood up a Scion Hub on an internal-only GCE VM (Ubuntu 24.04) with Keycloak SSO and TLS
handled by an F5 BIG-IP. Running `main` @ `aedf89ed`.

**It works.** But we hit enough snags getting there that it seemed worth writing down —
partly so the next person in a similar environment has an easier time, and partly because a
few of these look like real bugs rather than just "our setup is unusual".

> **A note on freshness:** we deployed at `90bf246e`, then pulled 24 commits (through PR
> #1201), then a further 16 (through PR #1217) — rebuilding and re-checking every item each
> time. **All 19 issues then filed were still present at `1933d359`.** We later pulled through
> `89ed0fe8` and added issues 20-25, then `2b8be982` and added 26-27, then `aedf89ed` and added
> 28-43. Issues 20-23 surfaced while moving the hub onto GCP Secret Manager and GCS object
> storage; 24 and 25 surfaced when agent creation broke for three days and the hub reported
> nothing wrong throughout; 9 was substantially rewritten and 26-27 added while rebuilding all
> container images from source behind a corporate proxy; 31 and 37-41 came out of running
> orchestrator/progeny agents and giving them Docker; 42-43 out of ordinary daily use.
>
> **Currently deployed and re-verified at `aedf89ed`.** Three issues have been fixed upstream
> since we started — 11, 16 (partially) and 3 — and each is marked as such at its own heading
> and struck through in the priority table. Everything else here is open. The checks are made
> against the files each issue cites, not from memory: issue 1's two scripts still pin
> `go1.23.0`, and issue 21's `backupSigningKeyToStore` still assigns `EncryptedValue =
> encodedValue` directly.
>
> `1befe923` is available upstream but not yet deployed here at the maintainer's suggestion, so
> nothing in this report has been checked against it.
>
> One thing worth flagging from an earlier round: **PR #1205 ("add shellcheck gate and fix
> existing findings") edited eight files under `scripts/starter-hub/`**, including the two
> scripts most of this report concerns. Those edits were pure lint hygiene — `# shellcheck`
> directives, `read -r`, quoting `--labels` and `--create-disk`. The `git push origin main`,
> the stale Go pin, and the `--session-secret` on the systemd `ExecStart` line all came
> through untouched, which is entirely expected since shellcheck has no opinion on any of
> them. Noted just to make clear these aren't things a linter will surface.

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
instead. Numbers 11–19 came while we were hardening things for a wider test group and trying to
get telemetry working. Numbers 20–25 came when we moved secrets into GCP Secret Manager and
storage into a GCS bucket. Numbers 26 onward came from ordinary daily use by a real team:
running orchestrators with progeny agents, cloning from Azure DevOps, and giving agents the
ability to run containers.

**If you only look at four:**

**31** first, because it is live work — the `hasAnyKey` fix in #1292 is correct and deployed
here, and progeny agents still get no credentials. Three conditions sit behind it, one of them
a one-line prefix mismatch. Worth seeing before #1252 is closed.

**16 and 18** together are what most enterprises will care about: every authenticated user can
read every project out of the box, and the obvious fix hides projects from their own members.

**13** is a one-line fix that now also protects the new encryption at rest — since 11's fix
derives its key from the very secret 13 leaks into `ps`.

**30** is the cheapest win: chat ships enabled with a nil store whenever the message broker is
off, so it renders fully and 503s on every send — and the key that fixes it is absent from the
settings schema.

**2** is still the one that stops a stock deployment dead at step 1.

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

> **RESOLVED as of `fd818e08` (verified 2026-09-02, static).** The seeded roles were rebuilt.
> `hubMemberPermissionIDs()` in `pkg/hub/seed.go` is now an explicit curated list that
> deliberately excludes `project.list`, `project.read`, `agent.list` and `agent.read` at system
> scope, with a comment naming the exact risk we reported — *"Including them would grant
> cross-project admin-view visibility to every hub member via the hasAdminView handler
> pattern"* — and a regression test, `TestGolden_CrossProjectVisibilityRegression`. Cross-project
> visibility is now handled by project-scoped bindings. Left in place for the record.

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

> **RESOLVED as of `fd818e08` (verified 2026-09-02, static).** `hub-viewer` is now a distinct
> seeded role with its own curated permission set (`hubViewerPermissionIDs()`), read-only and
> carrying the same cross-project exclusions as `hub-member` but without `project.create`. It is
> no longer identical to `member`.

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

> **RESOLVED as of `fd818e08` (verified 2026-09-02, static).** `projectMemberPermissionIDs()`
> now grants the `read` and `list` actions over `permissions.ResourceProject`, so project
> membership confers project visibility. This was the specific gap that made 16's natural fix
> hide projects from their own members; both sides are now addressed together.

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

> **Issues 16, 17 and 18 are symptoms of the same gap: there is no coherent role model to
> anchor them to.** Rather than only report them, we wrote up a target state —
> [`role-model-proposal/`](role-model-proposal/role-model-proposal.md) — covering scopes,
> assignable principals, agents as non-principals, and private-by-default projects. It is a
> proposal, not a description of how Scion behaves today.

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

> **PARTIALLY RESOLVED; remainder not reproducible at `8f66d97d`.** The schema half is fixed —
> `message_broker` and `native_chat` are accepted keys. The nil-store behaviour cannot be
> re-observed on our hub because we run with `message_broker.enabled: true`; reproducing it
> means deliberately turning the broker off on a live hub, which we have not done. Re-verified on a live hub at `8f66d97d` (2026-09-07).

> **PARTIALLY RESOLVED as of `fd818e08` (verified 2026-09-02, static).** The schema half is
> fixed: `message_broker` and `native_chat` are both accepted keys now
> (`pkg/config/hub_config.go:1033-1034`), so the setting that fixes this is no longer invisible
> to `settings.yaml`. The default-enabled behaviour is unchanged on its face — `NativeChat` is
> documented as *"Nil (absent) means enabled"* (`hub_config.go:461`) — but whether the UI still
> renders against a nil store needs a live retest on this build, which we have not done.

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

### 31. Progeny agents still cannot inherit captured credentials after #1292 — three further blockers 🔴

An orchestrator creates sub-agents; the sub-agents come up unauthenticated. Preston diagnosed
this and shipped `4b683622` ("make hasAnyKey progeny-aware", #1292, closing #1252): for a
progeny agent, `agent.OwnerID` is the *creating agent's* ID, so the user-scope lookup misses,
`NoAuth` is set preemptively, and the working `ListProgenySecrets()` path never runs.

**That fix is correct, it is deployed here, and the symptom persists.** We upgraded to
`aedf89ed` (which contains it) at 19:41 and the progeny agents below were created at 20:32 —
after the fix, still with no credentials. Three further conditions have to hold, and none of
them does.

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
both blockers above are real. A third remains behind them, described next.

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

### 40. File secrets are delivered twice — as a `0600` file *and* as an environment variable containing the same bytes 🔴

Scion writes file secrets to disk with tight permissions:

```
-rw------- 1 scion scion  /home/scion/.scion/harness/secrets/GITHUB_TOKEN
-rw------- 1 scion scion  /home/scion/.m2/settings.xml
```

and then puts the **same content** into a container environment variable:

```
$ printenv SCION_STAGED_SECRETS | base64 -d
file_secrets:
  name=COPILOT_CONFIG  target=/home/scion/.copilot/config.json   value=864 chars base64
  name=MAVEN_SETTINGS  target=/home/scion/.m2/settings.xml       value=2492 chars base64
```

`PD94bWwgdmVy` decodes to `<?xml ver` — the whole `settings.xml`, including the plaintext
Artifactory password inside it. The 864-char value matches the 648-byte `config.json`.

**The file mode is therefore decorative.** Environment variables are inherited by every child
process, so anything the agent runs sees every staged secret:

- a build script in the cloned repository
- an npm `postinstall`, a Maven plugin, a Gradle task
- any test the agent is asked to run
- any subprocess of the harness

The threat model this breaks is the one that matters for an agent platform: the agent executes
code it did not write, from a repository the user asked it to work on. Careful `0600` files
defend against that; an environment variable does not. One `printenv` exfiltrates the lot.

It also spreads: environment variables surface in process listings for the same user, in crash
dumps, in `docker inspect` output, and in any log line that dumps the environment.

**Suggested fix:** deliver file secrets by file only. The staging manifest needs the *name* and
*target path* so the harness knows what landed where — it does not need the contents, which are
already on disk at the path the manifest names. If some consumer genuinely needs the value
in-process, pass a path and let it read the file, so the `0600` still means something.

### 41. Anything an agent prints is persisted durably, secrets included 🟠

> **CONFIRMED still present at `8f66d97d`.** No redaction exists on the message-ingest path —
> nothing in `handlers_agent_messaging.go` or `messagebroker.go` scrubs or masks. (Our own
> journal shows no credential-shaped lines in the last 24h, but that is a property of what our
> agents happened to print, not of the code.) Re-verified on a live hub at `8f66d97d` (2026-09-07).

During a build our agent echoed an Artifactory token into a status message. It was redacted in
the UI within seconds. The value is still in the database:

```
messages table: 1592 rows
  'ARTIFACTORY_TOKEN'  41 messages      project: Connections AI (ADO)
  'AP53Yox…'            1 message       (the Artifactory password)
  '_authToken'          1 message
```

and in the system journal:

```
journalctl -u scion-hub | grep -c 'AP53Yox'   -> 2
journalctl -u scion-hub | grep -c '_authToken' -> 2
```

Agent status messages are stored permanently in `messages`, published to the project's chat, and
written to the host journal. There is no redaction on the ingest path and no way to retract a
message once sent — deleting it from the UI does not remove it from the journal, and the journal
is readable by anyone with host access, which on this deployment is a wider set than the project's
members.

This is not the agent misbehaving in an exotic way. Agents narrate what they are doing, and what
they are doing involves credentials; the platform stores that narration verbatim, forever, in
two places.

**Suggested fix:** run inbound agent messages through the same redaction the telemetry pipeline
already has — `settings.yaml` already declares `redact: [prompt, user.email, tool_output,
tool_input]` for telemetry, so the machinery exists and simply is not applied here. Pattern-match
known credential shapes (`reftkn:`, `ghp_`, `_authToken=`, base64 JWTs) at ingest and store a
marker instead. Also worth offering an operator command to purge a message from the store and
journal, since "rotate the credential" is currently the only remedy.

**Credit where due:** the telemetry pipeline *is* configured correctly — `redact` covers prompts,
user email, tool input and output, `session_id` is hashed, and `agent.user.prompt` is excluded
from export entirely. Telemetry is not the leak path here. The message store is.

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

> **RESOLVED upstream.** Our PR was merged: `authenticatedCloneURL` builds the URL with
> `net/url`. Review surfaced a further bug in our own patch — `url.Parse` succeeds on `ssh://`,
> so the first draft injected an OAuth token into SSH remotes. The merged version guards on
> `Scheme == "https"`. Filed as miller79/scion#2, closed. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

> **RESOLVED as of `8f66d97d`.** The token is now written as a project secret *before*
> `cloneSharedWorkspaceProject`, with a comment stating exactly why: *"This must happen before
> cloneSharedWorkspaceProject so that resolveCloneToken can find it during the initial clone."*
> (`pkg/hub/handlers_projects_core.go:556`). That was the whole of our complaint. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

> **CONFIRMED still present at `8f66d97d`.** Nothing rewrites the on-disk marker at project
> creation. The artefact of the original incident is still visible on our VM as
> `project-configs/connections-ai-ado__3a57faf5.stale` beside the live
> `connections-ai-ado__bf1c7cfb`. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

### 37. The `git-sandbox` platform skill can never reach a clone-per-agent workspace, and its content is wrong for one that has network access 🟠

> **CONFIRMED still present at `8f66d97d`.** `shouldInjectSkill` still returns `injCtx.IsGit`
> for `inject_when: git_workspace` (`pkg/agent/provision.go:1448`), and `IsGit` is still forced
> to false inside a container when `SCION_HOST_UID` is set (`provision.go:486`). The two
> together still make the condition unreachable in a clone-per-agent workspace. Re-verified on a live hub at `8f66d97d` (2026-09-07).

> **NEEDS RETEST as of `fd818e08`.** `git-sandbox` no longer appears anywhere in the Go
> sources — only in `docs-site/`, `changelog/` and `.design/`. The platform-skill seed we cited
> is gone, so the injection path has been reworked and this finding cannot be confirmed or
> retired by static inspection. The `SCION_HOST_UID` worktree-suppression gate it depends on
> (`pkg/agent/provision.go`) is still present.

Two problems that compound: the skill is not injected where it should be, and where it *is*
injected its instructions may be false.

### It cannot be injected during in-container provisioning

The skill declares a condition:

```yaml
name: git-sandbox
inject_when: git_workspace
```

which resolves to a single boolean:

```go
case "git_workspace":
    return injCtx.IsGit
```
`pkg/agent/provision.go:1448`

and that boolean is deliberately forced false whenever provisioning runs inside an agent
container:

```go
isGit := util.IsGitRepoDir(projectDir)
if isGit && os.Getenv("SCION_HOST_UID") != "" {
    // Inside an agent container: treat as non-git to prevent worktree
    // creation. Container worktrees produce path-identity mismatches
    // because --relative-paths are computed against the container mount
    // layout, not the host filesystem.
    isGit = false
}
```
`pkg/agent/provision.go:485-492`

The override is reasonable on its own terms — it exists to stop worktree creation in a
container, and the comment explains why. The defect is that **one boolean is serving two
unrelated questions**: "may I create a worktree here?" and "is this a git workspace?" Those are
not the same claim, and collapsing them means a `git_workspace` skill can never be injected
during in-container provisioning, whatever the project's actual git configuration.

There is a second path to the same outcome. `IsGit` is computed from `IsGitRepoDir(projectDir)`
— the **host-side** project directory. In a clone-per-agent project the repository is cloned
into `/workspace` *inside the container*, so the host-side directory is not a git repo and
`IsGit` is false there too. Either way, clone-per-agent git projects never receive the skill.

Only the shared-workspace mode, where the host directory really is a clone, satisfies the
condition — which is consistent with the skill's own content assuming a worktree/sandbox layout.

### Confirmed on a live hub

Every running agent, with the skill directory checked directly in each container:

```
AGENT                                    MODE          GIT   HOST_UID  git-sandbox
connections-ai-ado--final-fixes-impl…    shared-plain  true  set       (absent)
connections-ai-ado--fix-template-orch…   shared-plain  true  set       (absent)
carrier-onboarding--…-orchestrator       shared-plain  —     set       (absent)
anthony-s-main-project--default-orch…    shared-plain  —     set       (absent)
```

and the hub log, at debug level:

```
provision: skipping platform skill "git-sandbox" (inject_when="git_workspace" not satisfied)
```

The two Azure DevOps agents report `SCION_WORKSPACE_GIT=true` and a git-backed workspace, and
still do not receive the skill. **The signal that would answer the question correctly is present
in the very same environment** — the broker emits `SCION_WORKSPACE_GIT`, the provisioner ignores
it and consults a boolean that was deliberately zeroed for an unrelated reason. `SCION_HOST_UID`
is set in every container, so the override fires universally.

Note also that `shared-plain` is reported for *every* agent, including projects with no git
remote at all, so workspace mode does not distinguish these cases either — only
`SCION_WORKSPACE_GIT` does.

> **Not a bug, so nobody else chases it:** the same log shows
> `optional skill "scion-platform://git-sandbox" skipped: no resolver registered for scheme
> "scion-platform"`. That is intended. Those URIs are seeded into `hub_settings` for display
> only and marked optional; `platform_skills_seed.go:33-37` says so outright. Real injection
> happens through `injectPlatformSkills()`. We flag it because it reads exactly like the cause
> and is not.

### Its content asserts an air-gap that does not exist

```
## 1. Local-Only Operations (No Network Access)
- **Restriction:** The environment is air-gapped from `origin`. Commands like
  `git fetch`, `git pull`, or `git push` will fail.
- **Directive:** Always assume the local `main` branch is the source of truth.
```

Our agents clone over the network from an Azure DevOps remote at startup, so they demonstrably
have git network access. An agent given this skill is instructed not to attempt operations it
can perform — the failure mode is a capable agent declining to push or fetch and reporting the
environment as restricted.

The maintainers appear to know: `.design/workspace-mode-env.md` records that the skill
"assumes" a particular workspace mode and lists *"consolidating or rewriting the `git-sandbox`
platform skill"* as a follow-on.

**Suggested fix:** separate the two meanings — keep the container override for worktree
creation, and give the injection context its own signal for "this workspace is git-backed"
(the broker already emits `SCION_WORKSPACE_MODE` and `SCION_WORKSPACE_GIT`, so the information
exists). Then make the skill's content conditional on mode, or split it: the air-gap and
worktree guidance belongs to worktree-per-agent, while a clone-per-agent agent needs ordinary
remote-capable git instructions.

**A note on how this was found, because the failure is silent.** The skip is logged only at
debug level:

```go
util.Debugf("provision: skipping platform skill %q (inject_when=%q not satisfied)", ...)
```

so an operator sees a skill listed in the hub's injected-skills settings, no error anywhere, and
no such directory in the agent. Two separate investigations on our side concluded the skill did
not exist at all before we checked the binary. A single INFO line naming the skill and the
unsatisfied condition would have ended it immediately.

### 38. Profile-level `env` is accepted by the schema and silently ignored 🟠

> **CORRECTED 2026-09-02 — our original framing was wrong.** We reported this as a missing merge
> and suggested restoring it. It is not an oversight. `pkg/config/settings_v1.go:53` records that
> `profiles.<name>.env` was removed deliberately in Gap 3 ("G3-full") as a breaking change, on a
> product-owner rationale — *"settings schema has gotten pretty rich, need to pare down the number
> of control and injection points"* — and states plainly: *"Do not restore the merge because a
> caller appears to want profile env: the removal is the feature, not an oversight."* Two tests pin
> it. We had not read far enough up the file.
>
> **What survives is narrower.** The `Env` field is still declared on `ProfileConfig`
> (`settings.go:61`) with yaml/koanf tags, so the key parses, validates, is written back on
> rewrite, and does nothing — with no warning. `volumes` sits beside it in the same struct and
> does work, which is what made it look supported. The fix we should have asked for is to remove
> the field or reject the key, naming the documented migration path `harness_configs.<hc>.env`
> (explicitly *not* `harness_overrides.<hc>.env`).
>
> Filed as [#11](https://github.com/miller79/scion/issues/11), rewritten there with the original
> claim preserved in a comment.

We set two things in the same `profiles.local` block. One took effect, the other vanished:

```yaml
profiles:
    local:
        volumes:
            - source: /opt/scion-docker-cli/docker
              target: /usr/local/bin/docker      # ← arrived in the container
        env:
            DOCKER_HOST: unix:///run/...          # ← never arrived
```

Verified inside a running agent: the mounted binary was present at
`/usr/local/bin/docker`; `printenv DOCKER_HOST` returned nothing.

The resolver merges one and not the other:

```go
// Merge profile-level volumes
if profile.Volumes != nil {
    result.Volumes = append(result.Volumes, profile.Volumes...)
}
```

There is no `profile.Env` merge anywhere in that function. The asymmetry is stark because the
*override* level immediately below merges both:

```go
if override.Env != nil {
    result.Env = mergeMaps(result.Env, override.Env)
}
if override.Volumes != nil {
    result.Volumes = append(result.Volumes, override.Volumes...)
}
```
`pkg/config/settings.go:214-236`

A nearby comment refers to "G3-full" reducing the number of env injection points, so dropping
profile-level env may well be deliberate. **If so, the schema was not updated to match.**
`profileConfig` still advertises `env` alongside `volumes`, `resources`, `secrets` and the rest,
so an operator writes it, the file validates, the hub starts clean, and nothing happens.

That is the whole cost: not that the feature is missing, but that the config surface promises it.
We spent a debugging cycle assuming a socket permission problem because the environment variable
we had set was absent, and nothing anywhere said it never could be.

**Suggested fix:** whichever is intended — merge `profile.Env` like `override.Env`, or remove
`env` from the `profileConfig` schema and reject it at load with a message naming
`harness_overrides.<harness>.env` as the supported place. Either is fine; the current state is
the one that costs people time.

### 39. Agents that use Docker are sibling containers, and nothing tells them so 🟠

> **CONFIRMED still present at `8f66d97d`.** No marker of the sibling topology is exposed to
> agents. The word "sibling" appears in the sources only in the unrelated sense of agents
> sharing a workspace directory. Re-verified on a live hub at `8f66d97d` (2026-09-07).

An agent doing container work talks to a daemon whose filesystem is **not** the agent's
filesystem. Every path in a `docker run` argument is resolved by the daemon, on the host. Two
failures follow from this, and our agent hit both.

**The loud one — socket path.** `pack build --docker-host=inherit` asks the daemon to mount
`$DOCKER_HOST` into its lifecycle containers. Inside the agent the socket sits at
`/var/run/docker.sock`; on the host that path is a *different* daemon's socket, so:

```
mount /var/run/docker.sock          -> permission denied
mount /run/user/1002/docker.sock    -> server=29.7.2      (same daemon, real host path)
```

No `pack` flag can bridge that, which is why every attempt failed identically. The fix is
path identity: mount the socket at the same path inside the agent as on the host.

**The quiet one, and much worse — bind mounts silently succeed empty.** The agent mounted a
directory containing a Maven `settings.xml` into a buildpack binding. The daemon resolved that
host path, found nothing there, and — as Docker does — **created an empty directory and mounted
it**. No error. The buildpack saw an empty binding, ignored the mirror configuration, went
straight to Maven Central, and failed on egress.

The agent then spent hours verifying the `settings.xml` was byte-for-byte correct. It was. It
was never being read. A wrong-but-loud failure would have cost minutes.

The eventual fix was to stop using host paths entirely and pass the binding through a **named
volume**, populated via `docker cp`, since named volumes are resolved by the daemon in its own
namespace and cannot silently miss.

**Why this belongs to Scion rather than to Docker.** The sibling-container topology is Scion's
architectural choice, and it is invisible from inside an agent — nothing in the environment, the
platform skills, or the docs says "the daemon you are talking to does not share your
filesystem." An LLM agent will reason from the container's own view, conclude its file is
correct, and keep going. Both of ours did.

**Suggested fix:** a platform skill, or a section in the existing `git-sandbox`/`scion-cli-operations`
skills, stating the topology and the two consequences: mount socket paths by their *host* path,
and pass file bindings by named volume rather than host path. Setting an explicit marker in the
agent environment (e.g. `SCION_DOCKER_TOPOLOGY=sibling`) would let a skill trigger on it. This is
cheap and would have saved us most of a day.

> **A proposal follows from this one.** Agents cannot run containers at all today, which makes
> Testcontainers and buildpack builds impossible. See
> [`docker-support-proposal/`](docker-support-proposal/docker-support-proposal.md) for a way to
> allow it without granting host root — including the rootless-daemon reference implementation
> we run on our own hub, and an A/B test showing why the socket has to be mounted at an
> identical path on both sides.

### 42. A message containing `<template>` silently loses everything after it 🟠

An agent posted a status update ending:

> Any future `scion start ... -t <template>` will now pick up the correct content. Sync agent
> torn down; only I'm running. Thanks for asking — that would've been a silent gap otherwise.

The UI rendered it up to `-t ` and stopped. No ellipsis, no "show more", no error. **Copying
the message yields the full text**, so the content is intact in the store and only the rendering
is lost.

### Why

Chat markdown is rendered with HTML passthrough enabled, then sanitised:

```ts
const rawHtml = marked.parse(markdown, { async: false }) as string;
return purify.sanitize(rawHtml);
```
`web/src/utils/markdown.ts:57-58`

`marked` is not told to escape raw HTML, so `<template>` in prose is emitted as an actual tag.
The browser's parser then does what the spec requires: **everything following `<template>` becomes
its inert `.content` DocumentFragment**, not its child nodes. DOMPurify walks child nodes, does
not find that text, removes the disallowed `<template>` element, and the fragment goes with it.

This is specific to elements with special parsing. For an ordinary unknown tag — `<foo>` —
DOMPurify's default `KEEP_CONTENT: true` strips the tag and keeps the text, so nothing is lost.
`<template>` is the pathological case; `<style>`, `<textarea>` and `<title>` consume following
content as raw text in similar ways and are worth checking too.

### Why it will keep happening

Angle-bracket placeholders are ubiquitous in exactly the text agents produce:

```
scion start <name> -t <template>
export GITHUB_TOKEN=<your-token>
--project <project-id>
```

`<template>` is not an exotic string here — it is the literal placeholder in Scion's own CLI
help for the `-t` flag. Any agent explaining that command truncates its own message from that
point on, and neither the agent nor the reader is told.

**This is not an XSS finding.** DOMPurify is present, correctly configured, and doing its job —
the hook that forces `target="_blank" rel="noopener noreferrer"` on anchors is a nice touch. The
defect is that HTML passthrough is enabled at all for user- and agent-authored prose, where it
buys nothing and costs message content.

**Suggested fix:** escape HTML in the source before parsing, or override marked's `html`
renderer to emit escaped text:

```ts
marked.use({ renderer: { html: (t: string) => escapeHtml(t) } });
```

Fenced code and inline backticks are unaffected — those are handled by the markdown grammar, not
HTML passthrough — so nothing legitimate is lost. If raw HTML in chat is deliberately supported,
then `template` needs adding to DOMPurify's `ALLOWED_TAGS` *and* the content fragment reattached,
which is considerably more work for no obvious benefit.

### 43. A project's git branch can be set only at creation, and never changed 🟠

**What happened:** we created a project from an Azure DevOps repo while working on a feature
branch, `jisaal1/add-scion-templates`. Once that branch merged we wanted the project to track
`main` instead. There is no way to do this in the product.

The branch lives in the project's label map as `scion.dev/default-branch`. It is **read** in
three places, each falling back to `main` when the label is absent:

- `pkg/hub/handlers_agent_create_helpers.go:138` and `:165` — the branch an agent is created on
- `pkg/hub/handlers_projects_core.go:1093` — the branch used for the shared-workspace clone

It is **written** in exactly one place: `web/src/components/pages/project-create.ts:603`, the
create-project form. `project-settings.ts` has no branch field in any of its tabs.

So the value is write-once at creation, and every later consumer silently keeps using it.

**Three separate obstacles to changing it**, each of which matters on its own:

1. **No UI.** Nothing in project settings edits labels, and the branch is not surfaced as its
   own first-class field anywhere.

2. **The API can do it, but the shape is a trap.** `PATCH /api/v1/projects/{id}` accepts a
   `labels` object, but `handlers_projects_core.go:2557` assigns it wholesale:

   ```go
   if updates.Labels != nil {
       project.Labels = updates.Labels
   }
   ```

   A caller who sends only `{"labels":{"scion.dev/default-branch":"main"}}` — the natural thing
   to send, and what a partial-update verb like PATCH implies — silently destroys
   `scion.dev/clone-url`, `scion.dev/source-url`, and `scion.dev/workspace-mode`. The project
   then has no clone URL and every subsequent agent creation fails. Recovering means knowing
   the label scheme well enough to reconstruct it by hand. There is no merge, and no validation
   that the labels a project depends on survived the write.

3. **Permission.** `PATCH /projects` requires project-owner. A `member` — including the person
   who uses the project daily — is denied, so even the raw API is not a workaround for most
   users.

The only route left is editing the `labels` JSON in `hub.db` directly, which is what we did.
That is not a reasonable ask for a routine, expected operation: repos rename their default
branch, feature branches merge, and teams switch from `master` to `main`.

**Suggested fix**, roughly in order of value:

- Add a branch field to project settings — it is a one-line label write and the highest-value
  part of this.
- Make `PATCH` **merge** labels rather than replace them, or add an explicit
  `labelsReplace: true` flag so the destructive behaviour is opt-in. Merging is the behaviour
  the verb already implies.
- Reject a `PATCH` that would leave a git-backed project without `scion.dev/clone-url`, rather
  than accepting it and failing later at agent-creation time.
- Consider promoting branch and clone-url out of the free-form label map into real project
  columns. They are load-bearing configuration rather than user metadata, and the label map
  gives them no schema, no validation, and no protection from a clobbering write.

**Note on scope:** this is only about the *default* branch recorded on the project. Per-agent
branch selection at agent-creation time works fine, and is unaffected.

### 44. No way to start an agent with a clean, private workspace — a project is mandatory, and a non-git project shares one directory across every agent 🟠

Two related gaps, one a feature request and one a defect we have already been bitten by.

**A project is required, always.** `pkg/hub/handlers_agents_core.go:392`:

```go
if req.ProjectID == "" {
    ValidationError(w, "projectId is required", nil)
    return
}
```

There is no way to create an agent without first creating a project. For a great many tasks
this is ceremony with no payoff: the agent is going to `git clone` what it needs, or write
throwaway scratch code, or answer a question about a repo it fetches itself. Anchoring it to a
project first means naming a thing, creating it, and then remembering to clean it up.

Agents are already perfectly capable of fetching their own inputs — that is most of what they
do. The project is doing real work when it carries shared secrets, membership and a canonical
checkout. When it carries none of those, it is an empty shell we are obliged to create anyway.

**The closest thing available today is a project with no git remote, and it is not private.**
Every workspace mode is gated on the remote being set. `pkg/store/models.go:374`:

```go
func (p *Project) IsSharedWorkspace() bool {
    return p.GitRemote != "" && p.Labels[LabelWorkspaceMode] == WorkspaceModeShared
}
func (p *Project) IsWorktreePerAgent() bool {
    return p.GitRemote != "" && p.Labels[LabelWorkspaceMode] == WorkspaceModeWorktreePerAgent
}
```

So does the label that would set one — `handlers_projects_core.go:359`:

```go
if normalizedRemote != "" {
    switch req.WorkspaceMode {
    case store.WorkspaceModeShared, store.WorkspaceModeWorktreePerAgent:
        req.Labels[store.LabelWorkspaceMode] = req.WorkspaceMode
    }
}
```

Pass `workspaceMode` on a project with no git remote and it is **silently dropped** — not
rejected, not warned about. The request field's own comment says so
(`handlers_projects_core.go:53`): *"only meaningful when gitRemote is set"*.

With no mode possible, every agent in a non-git project falls through to the same branch of
`populateAgentConfig` (`handlers_agent_create_helpers.go:150`) and receives
`hubManagedProjectPath(project.Slug)` — a path derived from the **project slug alone**. Nothing
in it varies per agent. Ten agents in a non-git project all get the same directory, mounted
read-write, with no isolation and nothing announcing it.

`WorkspaceModePerAgent = "per-agent"` is defined at `models.go:237` and documented as the
default, but it is only ever the default *for git projects*, meaning clone-per-agent. It cannot
be selected for a project that has nothing to clone.

**This is not theoretical.** We hit it: a set of agents in a non-git project came up with each
other's identities. The harness writes its system prompt into a file in the workspace, every
agent had the same workspace, and the last writer won. The agents were not misconfigured and
the hub reported nothing wrong — they were simply sharing a directory we had no idea was
shared, because we had not asked for a shared workspace and the UI never offered us the choice.
We moved the work to a git-backed project to get isolation back.

**What we would like:** an *empty shell* — a workspace that starts empty, belongs to exactly
one agent, and is discarded with it. No remote, no clone, no seeding. The agent brings its own
content.

**Suggested fix**, smallest first:

- **Honour `per-agent` for non-git projects.** The constant exists and the semantics are
  obvious: give each agent its own empty directory instead of one keyed by project slug. This
  alone fixes the collision and delivers most of the value.
- **Stop silently dropping `workspaceMode` on non-git projects** — either apply it or reject it
  with a message. Silently ignoring a field the caller set is how the above stayed invisible.
- **Make `projectId` optional**, resolving to a per-user personal or scratch project when
  absent. That keeps every downstream assumption (secrets scope, membership, authorization)
  intact while removing the ceremony — a smaller change than making projects genuinely optional
  throughout, and it gets the ergonomics we are asking for.
- Consider marking such agents ephemeral, so the workspace is reclaimed on delete rather than
  accumulating. Related: we already prune Docker state on a timer for this reason.

**Note on scope:** we are not asking for projects to go away. They earn their place when they
carry shared secrets, membership, or a canonical checkout. The ask is that an agent which needs
none of those should not have to invent one, and that when it does, its workspace should be its
own.

### 45. No protected or break-glass administrator: `AdminEmails` is all-or-nothing 🟠

`ReconcileSuperAdminBindings` (`pkg/hub/seed.go:1038`) makes `AdminEmails` authoritative on every
startup:

> - If the user is in adminEmails: promote Role to "admin" (if needed) and ensure a super-admin
>   binding exists.
> - If the user is NOT in adminEmails AND adminEmails is non-empty: demote Role from "admin" to
>   "member" (if needed) and delete any super-admin binding.

The safety net is a single global guard: when `AdminEmails` is nil or empty, **all** reconciliation
is disabled and a warning is logged. The comment is explicit that this is deliberate — *"An empty
list is almost always a config load failure, not an instruction to remove every administrator."*
There is a further effect guard that refuses to proceed if the intended admin set would be empty.

Both are good. Neither is what an enterprise needs, because both are all-or-nothing: they protect
**every** administrator or **none**. There is no way to say *this one account must always retain
access*, which is the ordinary break-glass requirement — a service owner, an on-call operator, or
a named individual who must not be removable by a config edit.

**Why this bites in practice.** We demoted our own user for testing by commenting the
`AdminEmails` line out. That emptied the list, which silently disabled demotion globally — which
is the only reason a *second* administrator, promoted directly and never present in
`AdminEmails`, kept his access. Re-enabling the line later with one address would have made the
list non-empty, re-armed demotion, and stripped him on the same restart. Nothing in the UI, the
config, or the logs would have connected the two events: an edit naming one user removes a
different user.

Two properties combine to make it sharp:

- **Membership of the list is the only durable source of admin.** A directly-created super-admin
  binding is not a stable state; it survives only while the list is empty.
- **Revocation is deferred to restart.** The code says so: *"super-admin revocation takes effect
  on next hub restart."* So the damage lands at an unrelated moment — a routine upgrade, days
  later — rather than when the edit was made.

**What we did**, for anyone in the same position: a `systemd` `ExecStartPre` hook that re-adds the
protected address to `AdminEmails` before the hub reads it, with an explicit
`SCION_PROTECTED_ADMIN=` off-switch for deliberate removal. It works, and it is a workaround for
a missing product concept.

**Suggested fix**, smallest first:

- **A protected-admin setting** — e.g. `hub.protected_admins`, a list the reconciler refuses to
  demote regardless of `AdminEmails`. Small, declarative, and covers break-glass directly.
- **Warn on the asymmetry.** When reconciliation is about to demote an administrator who is not
  in `AdminEmails`, log it at WARN *naming the user*, before doing it. Today the demotion is a
  side effect of an edit about someone else, and nothing announces it.
- **Consider making a directly-granted super-admin binding a first-class state** that
  reconciliation leaves alone, rather than one it deletes. The distinction between "granted by
  config" and "granted deliberately in the UI" is currently lost.

## Docs that are wrong

### 4. OIDC redirect URI is wrong in the setup guide 🔴

> **OBSOLETE AS WRITTEN as of `fd818e08` (verified 2026-09-02).** The draft has since been
> published, as the *External OIDC Login Provider Support* section of
> `docs-site/src/content/docs/hosted/single-node/auth.md`. **The wrong URI did not ship** — the
> draft's two occurrences of `/api/v1/auth/oidc/callback` are absent from the published guide.
>
> A smaller issue replaces it: the published guide states **no redirect URI at all**, while the
> reader must register one in their IdP to complete setup. The correct value is still
> `BaseURL + "/auth/callback/" + provider` (`pkg/hub/web.go:1906`) with the provider slug `oidc`
> (`OAuthProviderOIDC`), i.e. `https://<hub-domain>/auth/callback/oidc`. Worth one line in the
> guide. Downgraded from 🔴 to 🟡.

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

> **RESOLVED as of `fd818e08` (verified 2026-09-02).** The draft's prerequisite line — *"A
> running Scion Hub instance with HTTPS (Caddy or similar TLS termination)"* — is not present in
> the published guide. The adaptive behaviour we relied on is unchanged:
> `Secure: strings.HasPrefix(cfg.BaseURL, "https://")` at `pkg/hub/web.go:517`.

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

> **OBSOLETE as of `8f66d97d`.** `scion@localhost` appears nowhere in the Scion sources — only
> in an unrelated Postgres test URL. The development user is now keyed by a well-known UUID
> (`DevUserID`, `pkg/hub/devauth.go:30`) with its email read from the store, so the identity no
> longer depends on matching an email at all. Retired rather than filed. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

> **RESOLVED upstream.** Our PR was merged; `roles/monitoring.viewer` is now granted alongside
> `logging.viewer`. Filed as miller79/scion#17, closed. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

> **NOT REPRODUCIBLE on our hub at `8f66d97d`.** With `gcp_project_id` set, startup now logs a
> single line — *"Telemetry project ID from settings: jbh-dev-reference"* — and no retry spam.
> We could not re-observe the forever-retry behaviour because our configuration no longer
> triggers it. Neither confirmed nor retired; it needs a hub with the project ID absent. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

> **CONFIRMED still present at `8f66d97d`.** `handlers_resource_import.go:561` still rejects
> with *"sourceUrl or workspacePath is required"*; there is no multipart or zip path. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

> **PARTIALLY ADDRESSED as of `8f66d97d`.** `docs-site/.../hosted/ha/auth-proxy-iap.md` now exists
> and covers an IAP-fronted deployment, which did not before. The single-node path is unchanged:
> `hosted/single-node/hub-setup-gce.md:50` still states that Caddy TLS provisioning *"Requires a
> domain name pointed at the VM's external IP"*, which is exactly the case an internal-only host
> cannot satisfy. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

> **RESOLVED upstream.** Our PR was merged: `NPM_REGISTRY` build-arg plus a BuildKit secret for
> credentials, documented in `image-build/README.md`. **pip is still not covered**, so `hermes`
> remains unbuildable behind a PyPI-blocking proxy. Filed as miller79/scion#13, closed. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

> **PARTIALLY RESOLVED as of `8f66d97d`.** The revert-on-restart half is addressed:
> `resource_bootstrap.go:151` now sets `HarnessConfigStatusArchived` on obsolete *bundled*
> configs instead of resurrecting them. The other half stands — there is still no user-facing
> way to archive or hide a harness config; `harness_config_handlers.go` exposes no archive
> action. We still hide ours with an out-of-band `harness-configs-disabled/` directory. Re-verified on a live hub at `8f66d97d` (2026-09-07).

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

### 36. The terminal link in the chat members sidebar forces a new browser tab *(UX)* 🟡

> **RESOLVED upstream.** Our PR was merged; only the pop-out link keeps `target="_blank"`.
> Filed as miller79/scion#22, closed. Re-verified on a live hub at `8f66d97d` (2026-09-07).

Clicking the terminal icon next to an agent in the chat members sidebar opens a new browser tab
rather than navigating within the app. Nothing signals that it will, and for the normal case —
glance at what an agent is doing, come back to the conversation — a tab is the wrong unit. Ten
agents inspected is ten tabs to close.

Both agent links are hardcoded:

```ts
<a href="/agents/${a.id}/terminal" target="_blank" class="agent-terminal" title="Open terminal">
  <sl-icon name="terminal"></sl-icon>
</a>
<a href="/agents/${a.id}" target="_blank" class="agent-popout" title="Open agent detail">
  <sl-icon name="box-arrow-up-right"></sl-icon>
</a>
```
`web/src/components/shared/chat/chat-members.ts:511-527`

What makes this a defect rather than a preference is the pairing. The **second** link is
explicitly a pop-out: it is classed `agent-popout` and drawn with the `box-arrow-up-right`
icon, so a new tab is exactly what a user expects. The **first** is drawn with a plain terminal
glyph and titled "Open terminal", carries no pop-out affordance, and behaves identically. Two
adjacent controls, visually distinguished, functionally the same — so the distinction the icons
promise is not real.

Worth noting the rest of the chat UI navigates in place; these are the only two `target="_blank"`
in the chat components, so this is a local inconsistency rather than a house style.

**Suggested fix:** drop `target="_blank"` from the terminal link and let it route in-app, keeping
the pop-out link as the deliberate new-tab affordance — that makes the two icons mean two
different things. If a new tab is wanted for both, give the terminal link a pop-out indicator so
the behaviour is predictable before the click. Users who want a tab can still ctrl/cmd-click,
which works on a normal in-app link and does not today.

### 10. Minor items 🟡

> **Re-checked at `fd818e08` (2026-09-02):** `scion --version` still has no alias — `version`
> remains a subcommand only. NATS is still installed by cloud-init. Unchanged.

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
| **40** | **Stop duplicating file-secret contents into `SCION_STAGED_SECRETS` — the env var defeats the `0600` file it accompanies** | **Security** | Low |
| **41** | **Redact credentials from agent messages at ingest; they persist in the message store and journal permanently** | **Security** | Low |
| **35** | **Rewrite the project marker on creation — a recreated project inherits the deleted one's id and all agent creation fails** | **Blocking** | **Trivial** |
| **33** | **Build the authenticated clone URL with `net/url` instead of `strings.Replace` — any remote with a username currently gets corrupted credentials** | **Blocking** | **Trivial** |
| **31** | **Progeny credential inheritance is unreachable for agent-captured secrets: `created_by` carries an `agent:` prefix the ancestry match does not strip** | **Blocking** | Low |
| ~~11~~ | ~~Local backend stores plaintext while its comment claims writes are rejected~~ — **resolved** in `af102183` (#1253). Kept for the caveats it leaves behind: see 13 and 21 | — | Done |
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
| ~~3~~ | ~~Remove or implement `default_runtime`~~ — **resolved**: gone from `pkg/config` as of `2b8be982` | — | Done |
| 5 | Correct the HTTPS-prerequisite claim | High | Trivial |
| 8 | WARN on unknown `settings.yaml` keys | High | Low |
| 7 | Support internal/BYO-cert/IAP deployments | High | Medium |
| 45 | Add a protected-admin list the reconciler will not demote; warn by name before demoting an admin absent from `AdminEmails` | High | Low |
| 44 | Honour `per-agent` workspaces for non-git projects — today every agent in one shares a single directory keyed by project slug, silently; and let an agent be created without a project | High | Low |
| 43 | Add a branch field to project settings; make `PATCH /projects` **merge** labels instead of replacing them — a partial label write silently destroys the project's clone URL | High | Low |
| 42 | Escape HTML in chat markdown instead of passing it through — `<template>` in prose silently truncates the message | High | Trivial |
| 38 | Drop `env` from `ProfileConfig` or reject the key — its removal from the resolvers was deliberate, but the field still parses and is silently ignored | Medium | Trivial |
| 39 | Tell agents they are sibling containers: host-path bind mounts silently mount empty dirs | High | Low |
| 37 | Give `inject_when: git_workspace` its own signal instead of the worktree-suppression boolean; make the skill's air-gap content mode-conditional | High | Medium |
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
| 36 | Drop `target="_blank"` from the chat sidebar terminal link so it navigates in-app | Low (UX) | Trivial |
| 32 | Let an agent principal create a conversation in its own project | Low (feature) | Medium |
| 10 | `--version` alias; drop NATS; placeholder registry | Low | Low |

Happy to supply logs, configs, or test any of these against our environment — we have
a working internal deployment we can iterate on.
