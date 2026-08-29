# Letting agents run containers, safely

*A proposal for Scion — Anthony Lofton, August 2026*

## The problem

Agents cannot run Docker. There is no daemon, no socket, and no CLI in any image, and no
supported option to change that. Verified on a live hub:

```
docker CLI            (no docker binary)
/var/run/docker.sock  No such file or directory
Privileged=false   CapAdd=[CAP_NET_ADMIN]   Runtime=runc
mounts: agent home, /workspace, one shared scratchpad — nothing else
```

That is a defensible default, and we are not asking for it to change. The difficulty is that
two ordinary Java workflows need a *local* daemon and cannot be delegated elsewhere:

- **Testcontainers.** Integration tests start real Postgres/Kafka containers in-process. Moving
  them to CI means the agent cannot run the test suite it is being asked to fix.
- **Cloud Native Buildpacks (`pack build`).** The lifecycle pulls a builder image and runs
  ephemeral containers against a daemon.

Both are the normal way this shop builds and tests. An agent that cannot do either is limited to
editing code it cannot verify.

## Why the obvious workaround is wrong

The `volumes` setting already permits it:

```yaml
volumes:
  - source: /var/run/docker.sock
    target: /var/run/docker.sock
    type: local
```

This works. It also hands the agent **root on the host**. Anything that can reach that socket can
start a privileged container, bind-mount `/`, and read `hub.db`, `hub.env`, and the signing keys
— for an LLM-driven process executing code from a freshly cloned repository. It defeats every
boundary the hub otherwise maintains.

We are not proposing it, and we would like Scion to make it harder rather than easier.

## What we propose

### 1. OCI runtime passthrough — small change, most of the value

`pkg/runtime/docker.go` assembles the `docker run` argv in one place, immediately beside the
existing resource flags:

```go
newArgs := []string{"run", "-t"}
...
newArgs = append(newArgs, "--memory", ...)
newArgs = append(newArgs, "--cpus", ...)
```

Adding `--runtime <name>`, sourced from a new `oci_runtime` field on `harnessConfig` /
`profileConfig`, is a few lines beside code that already exists. `podman.go` carries the same
shape.

That unlocks **Sysbox**, which exists precisely for this case. It uses user namespaces and
virtualises `procfs`/`sysfs`, so root inside the container is not root on the host. An agent can
then run a genuine `dockerd` inside its own container with **no `--privileged` and no socket
mount**. Testcontainers and `pack build` work unmodified, because a real local daemon is present.

The operator installs Sysbox on the node and sets `oci_runtime: sysbox-runc` on the harness
configs that need it. Nothing else changes, and hosts without Sysbox are unaffected.

**Why this one first:** it is the only option that makes the agent's own environment capable.
Every other approach moves the work somewhere else, which is exactly what Testcontainers cannot
tolerate.

### 2. A first-class remote build endpoint — moderate

Formalise what operators can already hand-roll: a `build_backend` block that injects
`DOCKER_HOST`, mounts TLS client material from secrets, and sets `TESTCONTAINERS_HOST_OVERRIDE`.

Today this is achievable with `env` plus file secrets — the config surface exists. Making it
first class buys validation, documentation, and a cert-rotation story, and gives operators a
supported answer that does not involve the host daemon.

`TESTCONTAINERS_HOST_OVERRIDE` is the part people miss: without it Testcontainers hands tests
`localhost:<port>` for containers living on another machine.

### 3. A managed DinD companion — larger, and only after (1)

Scion runs a per-agent `dind` container on a private network, lifecycle-tied to the agent, with
`DOCKER_HOST` pointed at it. Attractive because it needs no host-level install.

**It is only safe on top of (1).** A plain DinD companion must be privileged, which is host root
again — the same exposure as the socket mount, with more moving parts. Worth building once an
isolating runtime can back it; not before.

## Guardrails worth having regardless

These stand on their own merits, whether or not any of the above is adopted.

### `VolumeMount.Validate()` does not restrict the host path

```go
func (v VolumeMount) Validate() error {
    if v.Target == "" { ... }
    switch volumeType {
    case "", "local":
        if v.Source == "" { ... }
```
`pkg/api/types.go:267`

It checks that required *fields are present*, nothing more. `source: /var/run/docker.sock`
passes. So does `source: /`. There is no denylist, no warning, and nothing in the schema
documentation notes that a `local` volume can confer host root.

**Scope, measured rather than assumed.** On our hub this is *not* reachable by ordinary users.
The seeded policy grants members `["read","list"]` on `harness_config` and there is no
member-facing `create`, so writing such a config requires an administrator. We checked before
reporting, because the escalation story would have been more dramatic and wrong.

It remains worth fixing: a config surface that can grant host root should say so, and should be
hard to reach by accident.

**Suggested:** deny `local` sources matching the container socket paths and a small set of
sensitive prefixes (`/`, `/proc`, `/sys`, `/var/run`, `/etc`), with an explicit operator override
for people who genuinely mean it; and note in the schema docs what a `local` mount can confer.

### Elevated agents should be visible

If an agent runs under a non-default OCI runtime, with a build backend, or with a host mount
outside its own workspace, that should be visible on the agent — in the UI and in
`scion agent status` — rather than only discoverable by reading a harness config. Operators
should be able to answer "which agents can touch the host?" without grepping YAML.

## What we are not asking for

- Not asking for the socket mount to be supported. The opposite.
- Not asking Scion to bundle or install Sysbox. Passing `--runtime` through is enough; the
  install is the operator's problem, as it should be.
- Not asking for Docker-in-agent to be a default. Opt-in per harness config, admin-gated.

## Summary

| Option | Effort | Agent can run Testcontainers | Host exposure |
|---|---|---|---|
| **OCI runtime passthrough (Sysbox)** | Small | Yes | None — user-namespaced |
| Remote build endpoint | Moderate | Yes | A separate, disposable host |
| Managed DinD companion | Large | Yes | None *if* on (1); host root without it |
| Socket mount *(status quo workaround)* | None | Yes | **Host root** |
| Delegate to CI / Cloud Build | None | **No** | None |

The last row is why this proposal exists: it is the only option available today that keeps the
host safe, and it is the one that does not work for the use case.
