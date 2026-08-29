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

## A working reference implementation

We built option 2 on our own hub and it works today, with **no changes to Scion**. Recording it
here because it demonstrates the config surface is already sufficient for a safe answer — what
is missing is that nothing points an operator at it.

### What we did

A rootless Docker daemon under a dedicated unprivileged user on the same host as the hub:

```
useradd builder                       # uid 1002, its own /etc/subuid range
loginctl enable-linger builder
dockerd-rootless-setuptool.sh install # as builder
```

Then wired it to agents purely through existing `profileConfig` fields:

```yaml
profiles:
    local:
        volumes:
            - source: /run/user/1002
              target: /run/docker-rootless
            - source: /opt/scion-docker-cli/docker
              target: /usr/local/bin/docker
              read_only: true
        env:
            DOCKER_HOST: unix:///run/docker-rootless/docker.sock
            TESTCONTAINERS_RYUK_DISABLED: "true"
```

The second volume mounts a static `docker` CLI binary into every agent, because no Scion image
ships one. That avoids rebuilding images to add a single file.

### The isolation, measured

The claim worth testing is not "it runs" but "an agent cannot reach the host." We ran a
container under the rootless daemon that bind-mounts **the entire host filesystem** and runs as
root inside its namespace:

| Attempt | Result |
|---|---|
| read `hub.db` | denied |
| read `hub.env` | denied |
| list `/home/scion` | denied |
| reach the root `docker.sock` | denied |

Throughout: hub `active`, `/healthz` 200, agents running, disk unchanged. The container's `root`
is `builder` in a user namespace, and the hub's files are `600 scion:scion`, so the boundary is
enforced by the kernel rather than by convention.

For comparison, the same test against the **root** daemon's socket would have returned the
contents of every one of those files.

### What this validates, and what it does not

**Validates:** the `volumes` + `env` surface is enough to attach agents to an external daemon
safely. Option 2 needs no new mechanism — only documentation, and ideally a named config block
so operators do not have to derive this.

**Does not validate option 1.** This is still an *external* daemon. Agents cannot run a daemon
inside their own container, which is what `--runtime` passthrough would enable, and which is the
only arrangement where an agent is genuinely self-contained.

### Honest limitations

- **Same kernel.** A container-escape vulnerability still lands on the hub host. A separate
  build VM contains that; this does not. Lower risk than the root socket by a wide margin,
  higher than a separate machine.
- **Ryuk disabled.** Testcontainers' reaper is unreliable rootless, so test containers are not
  auto-removed. We run an hourly prune with a disk-pressure escalation that reaps
  `org.testcontainers` containers older than four hours.
- **Disk is the live risk.** The rootless daemon's images live under `/home/builder`, on the
  same filesystem as `hub.db`. If it fills, the hub stops writing. The prune timer exists
  specifically for this.
- **Profile scope is hub-wide.** Attaching at the profile level gives *every* agent the socket.
  Per-project or per-harness-config attachment would be better; the fields exist at
  `harnessConfig` level too, but selecting per project requires a project-scoped harness config.

### What upstream could take from this

1. Document this arrangement. It is the safe answer available today and nothing points to it.
2. Add a named `build_backend` block so it is declarative rather than three fields an operator
   has to assemble correctly.
3. Ship a `docker` CLI in the base image, or make it an opt-in build arg. Mounting a binary
   works but is a workaround for a missing 40 MB.
4. The `VolumeMount` denylist above matters more once this pattern is documented — the same
   field that attaches a *rootless* socket safely attaches the *root* one catastrophically, and
   nothing distinguishes them.

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
| *Rootless daemon on the hub host (built, see above)* | *None — config only* | *Yes* | *None — user-namespaced; same kernel* |

The last row is why this proposal exists: it is the only option available today that keeps the
host safe, and it is the one that does not work for the use case.
