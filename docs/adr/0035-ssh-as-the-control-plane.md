# ADR-0035: SSH is the control plane — the mesh's coordination plane is not a new service

**Date:** 2026-11-12
**Status:** proposed
**Deciders:** the maintainer
**Relates to:** ADR-0027 (mesh as an external agent), ADR-0034 (the file is the enrolment), ADR-0013 (server provisioning is a CLI)
**Answers:** the maintainer's question — "you would connect via peers and keys, right? SSH should be used for the mesh plugin we made, I think around ADR-0028?"

## Context

### The first half of the question is already true

**The tunnel is peers and keys.** SSH is not in the data plane at all: the
daemon never speaks SSH, the peer set is `public_key` + `allowed_ips` +
`endpoint` over UAPI, and ADR-0034 made the file the enrolment. Nothing about
the datapath needs revisiting.

### The second half is not — and the ADRs are numbered differently

The mesh ADR is **0027** ("Mesh topology as an external agent"), not 0028.
0028 is the seccomp filter; it *relates to* 0027 but is not the mesh.

ADR-0027's decision is that the mesh is an external agent (`vallum-mesh`) that
"registers with a coordination plane and receives a signed peer set", and it
names a `vallum-coord` service as that plane. So the mesh's control plane is
**a new service with a new protocol and a new auth scheme**.

Meanwhile SSH today appears in exactly **one** place in the whole tree:

```
crates/vallum/src/commands/setup.rs:552
    let mut child = std::process::Command::new("ssh")
        .arg(remote)
        .arg(&format!("sudo vallum peer enroll {name}… --public-key-file /dev/stdin --json"))
```

That is the *enrolment* transport — the operator's SSH access to a server
authorises a peer on it. So the product has two control planes in two
subsystems: the operator's SSH trust anchor, and (proposed) a bespoke one.

### The mesh does not exist, so this costs nothing to decide

There is no `vallum-mesh` crate, no `vallum-coord`, no code — `grep` over
`crates/` finds nothing. ADR-0027 is *proposed*. The decision about how the
mesh's peer set is distributed is therefore free **today**, and expensive
later.

### The signed-artifact machinery already ships

Vallum already verifies signed files with SSH keys. `scripts/install.sh:150`
downloads `SHA256SUMS.sig` and verifies it with `ssh-keygen -Y verify` against
an embedded `allowed_signers` file. So "a signed configuration file, verified
with SSH keys, distributed by SSH" is **not a new mechanism** — it is one that
is already built, tested and shipped.

## Decision

**SSH is the control plane. The mesh's coordination plane is not a new service.**

1. **The mesh's peer set is a signed file**, distributed over SSH (scp, rsync,
   or git) and verified with `ssh-keygen -Y verify` against an `allowed_signers`
   file — the same verification install.sh already performs on a release.
2. **The node list *is* the `allowed_signers` file.** The agent connects to each
   host listed there. Discovery is operator-managed rather than service-managed,
   and it is auditable: the file that says who may talk to whom is a file you
   can read.
3. **Enrolment keeps the same anchor.** `setup --remote` over SSH is the
   control plane's enrolment face, not a separate mechanism — which is why the
   phrase "your SSH access to a server authorises peers on it" now covers both
   joining a single server and joining a mesh.
4. **`vallum-coord` is not built.**

## What this keeps

Everything the datapath already has — roaming, endpoint tracking, live peer
apply over UAPI, identity documents — and everything ADR-0027's agent owns:
traversal (STUN), candidate exchange, hole punching, the relay fallback, and
the topology reporting that satisfies ADR-0016's "a tunnel that silently
degrades to a relay is a lie about its own topology". ADR-0027's step 2
(apply the peer set to the local daemon) is unchanged.

It also keeps the **signature verification**: the peer set is signed, and the
signature is checked before anything is applied. SSH changes who *delivers* the
set, not whether it is authentic.

## What this gives up

Honest costs, stated as costs:

- **Automatic discovery.** Nodes must be listed. The operator is the discovery
  mechanism.
- **One service to push policy to a fleet.** A change to the mesh means
  distributing a new signed file to N nodes rather than pushing to one
  endpoint. For tens of nodes this is fine; for thousands it is not.
- **Dynamic membership.** A node joins or leaves when the operator updates the
  file. Revocation is still immediate — remove the key from `allowed_signers`,
  or remove the peer from the signed set — but it is operator-driven.
- **A scale cliff.** SSH fan-out of N connections per node is acceptable into
  the low tens of nodes and becomes the wrong shape somewhere around a hundred.
  At that point a coordination plane returns, and it would return with the
  peer-set *format* and *signature verification* already settled — which is
  most of the design.

## What it costs in work

1. A peer-set file format: node id, public key, `allowed_ips`, candidate
   endpoints, expiry, and a signature.
2. `vallum mesh verify` — verify a signed peer set offline, before anything
   touches the daemon.
3. `vallum mesh apply` — apply a verified set to the local daemon over UAPI
   (ADR-0027 step 2, unchanged).
4. `vallum mesh fetch` — pull the set from the node list over SSH and verify
   before applying.
5. Traversal, STUN and relay remain separate work; they are orthogonal to how
   the peer set travels.

## Alternatives considered

### Keep ADR-0027 as written — build `vallum-coord`
- **Pros:** discovery, one push point, dynamic membership, better scale.
- **Cons:** a new service to deploy, secure, monitor and trust; a bespoke
  peer-set distribution protocol to design and get right; and two control
  planes for one product — the operator's SSH anchor *and* the plane's.
- **Rejected because:** it is the more expensive answer to a problem the
  operator's existing access already solves, taken on before anything has
  needed it.

### Keep the split — SSH for enrolment, a plane for the mesh
- **Pros:** no change to ADR-0027.
- **Cons:** two control planes, two trust anchors, two ways to reason about
  "who may add a peer".
- **Rejected because:** it is today's state, and today's state is the thing
  the question was asked about.

### No control plane — configure every node by hand
- **Pros:** nothing to build.
- **Cons:** a mesh of any size becomes a configuration-management project.
- **Rejected because:** it throws away the agent ADR-0027 got right.

## Risks

- **`allowed_signers` is a write authority.** Whoever can write that file can
  add peers to the mesh. A coordination plane has the same property, so this is
  not a new risk — but it is a risk that now lives in a file the operator's
  SSH tooling already protects.
- **SSH is a large attack surface** compared with a purpose-built protocol. The
  mitigation is that it is the operator's *existing* access, not a new service
  exposed to the world.
- **Two mechanisms in one product.** If the mesh's peer set arrives over SSH
  and a peer is authorised over SSH, the "one anchor" property holds only if
  both keep using it. This ADR is the record of that intent.

## Status of the code

Nothing implements any of this. ADR-0027 is proposed and unimplemented; this
ADR amends its coordination-plane decision. If the maintainer prefers
`vallum-coord`, this ADR is simply withdrawn and ADR-0027 stands unchanged —
the only cost of choosing either way now is the argument.
