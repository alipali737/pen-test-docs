```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

> This methodology targets **Kubernetes clusters and their orchestration-level configuration** (RBAC, admission control, NetworkPolicy, secrets, exposure), independent of underlying infrastructure (self-managed, EKS, AKS, GKE, OpenShift, etc.). Cloud-provider-specific control plane concerns (eg. EKS endpoint access, IRSA, Azure AD Pod Identity) are only lightly touched here - cross-reference the relevant cloud methodology ([[AWS Testing#4.4 - EKS|AWS Testing §4.4/§8]]) for those. Hands-on testing of a specific container's runtime/escape surface - once a workload has been identified as worth that depth of testing - is its own dedicated methodology: **[[Container Testing]]**. The focus here is the cluster layer; that doc is the container layer.
>
> Each section includes: **purpose/context**, **possible vulnerabilities**, **commands to run**, and **what a positive finding looks like**. Sections are ordered roughly by attacker kill-chain stage (external recon → initial access → in-cluster enumeration → privilege escalation → lateral movement/escape → persistence), so a black-box engagement can largely work top-to-bottom, while a white-box config review can jump straight to the section matching whatever access was granted.

---

## 0 - Scoping & Access Prep
### Scoping Questions
- Is this a black-box engagement (no cluster access, attacking from outside/via a workload) or a white-box config review (`kubeconfig` provided)?
- What's the trust level of the credentials/access provided? (unauthenticated, a specific namespace's service account, a read-only cluster role, cluster-admin)
- Is active exploitation in scope (container breakout attempts, actually escalating privilege, pivoting to the underlying cloud account) or is this a configuration review only?
- How many clusters/namespaces are in scope? For large multi-tenant clusters, is a representative sample acceptable or does every namespace need coverage? (drives the automation decisions in [[#11 - Scaling for Large Clusters]])
- Is the underlying infra known (EKS/AKS/GKE/on-prem/kubeadm)? If so, note the matching cloud methodology for IAM/identity federation concerns
- Is container image/registry access in scope (pulling and scanning images directly), or only running workloads?
- Are there production workloads where a crash/restart would cause real impact? (affects whether DoS-adjacent tests like resource exhaustion are permitted)
- Who is the technical point of contact if a test causes a pod eviction, node drain, or unexpected restart?

### Access Model
- Preferred: a **read-only, namespace-scoped** `kubeconfig` as a starting point, escalating manually as findings justify broader access, rather than starting with cluster-admin
- If testing is meant to simulate "attacker who popped a specific workload", request only that workload's mounted service account token rather than a separate kubeconfig
- Confirm whether the kubeconfig uses client certs, a bearer token, an OIDC/exec plugin (common for managed clusters - `aws eks get-token`, `az aks get-credentials`, `gcloud container clusters get-credentials`), or static tokens
- Get the API server endpoint and confirm reachability before assuming VPN/network access issues are a cluster misconfiguration

### Tooling Setup
```bash
kubectl version --client
kubectl config get-contexts
kubectl config use-context <context>
kubectl auth whoami          # K8s 1.28+; falls back to `kubectl auth can-i --list` on older clusters
kubectl cluster-info
kubectl get ns
```
- Install `kubectl` matching (or within one minor version of) the target cluster's version
- Set up separate contexts per in-scope cluster (`~/.kube/config`) to avoid accidentally running commands against the wrong one
- See [[#10 - Tooling]] for the full list of enumeration/exploitation tools used throughout this methodology

---

## 1 - External Recon & Attack Surface (Black-Box)
### Purpose
Identify what's exposed to the internet before any cluster access is assumed - the API server itself, exposed dashboards, and application-layer services fronted by the cluster (Ingress/LoadBalancer).

### Possible Vulnerabilities
- Kubernetes API server exposed to the internet with weak/no authentication
- Anonymous access enabled on the API server (`system:anonymous` mapped to a usable role)
- Exposed dashboards (Kubernetes Dashboard, Kubecost, Weave Scope, kube-ops-view) with no auth in front of them
- Kubelet API (port `10250`) or read-only kubelet port (`10255`, deprecated but still seen) reachable directly
- etcd exposed and unauthenticated (port `2379`)

### Commands
```bash
# API server discovery / version leak (often exposed even when auth is enforced)
curl -sk https://<target>:6443/version
curl -sk https://<target>:6443/healthz

# Anonymous access check
curl -sk https://<target>:6443/api/v1/namespaces

# kube-hunter for broad passive/active external recon
kube-hunter --remote <target-ip>
kube-hunter --cidr <cidr-range>          # scan a range for clusters

# Common exposed ports/services
nmap -p 6443,8443,10250,10255,2379,2380,30000-32767 <target>
```
- `30000-32767` is the default NodePort range - sweep it for inadvertently exposed Services

### What to Look For
- `/version` or `/healthz` responding without authentication confirms the API server is reachable - note the version for known-CVE triage (see [[#9 - Known CVE Checklist]])
- `/api/v1/namespaces` returning actual namespace data with no credentials = anonymous access is misconfigured (should 403/401)
- A dashboard login page with default creds, or no login page at all serving live cluster data
- kube-hunter flags with "Vulnerability" severity (not just "Open Port" info) are the ones worth chasing manually

---

## 2 - Authentication & RBAC Enumeration
### Purpose
Once any credential is obtained (service account token, kubeconfig, OIDC identity), establish exactly what it can do. RBAC misconfiguration is the Kubernetes equivalent of IAM misconfiguration in a cloud review - this is usually where the real findings are.

### Possible Vulnerabilities
- Over-permissive `ClusterRoleBindings`/`RoleBindings` (eg. a CI service account bound to `cluster-admin`)
- Wildcard verbs/resources in `Role`/`ClusterRole` rules (`"*"` on `resources` or `verbs`)
- Default service account (in any namespace) granted meaningful permissions instead of the intended least-privilege one
- `system:authenticated` or `system:unauthenticated` groups bound to anything beyond the absolute minimum
- Ability to `impersonate` other users/groups/service accounts

### Commands
```bash
# What can I do? (single most useful command in this whole methodology)
kubectl auth can-i --list
kubectl auth can-i --list --namespace=<ns>
kubectl auth can-i create pods --namespace=<ns>
kubectl auth can-i '*' '*' --all-namespaces   # test for the holy grail directly

# Enumerate all bindings cluster-wide (requires broader read access)
kubectl get clusterrolebindings -o wide
kubectl get rolebindings --all-namespaces -o wide

# Find who/what is bound to cluster-admin
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'

# Dump a role's actual permissions
kubectl describe clusterrole <name>
kubectl describe role <name> -n <ns>

# Automated privilege-escalation path graphing (essential at scale - see §11)
rbac-tool rbac-lookup                       # who can do what, cluster-wide
rbac-tool viz --kubeconfig ~/.kube/config -o rbac-graph.png
rbac-police audit                            # risky-permission detection (wildcards, escalate verbs, etc.)
```

### RBAC Privilege Escalation Patterns
> Mirrors the IAM privesc graphing done in [[AWS Testing#2.4 - Privilege Escalation Paths]] - same idea, different permission model.

Check whether the current principal (or anything it can modify) holds any of:
- `create` on `clusterrolebindings`/`rolebindings` - bind yourself to a more privileged role
- `create`/`update`/`patch` on `roles`/`clusterroles` - grant yourself new permissions directly
- `escalate` verb on `clusterroles`/`roles` (a built-in K8s RBAC bypass specifically for this)
- `bind` verb (lets you bind a role you don't already hold, if combined with `create` on bindings)
- `impersonate` on `users`/`groups`/`serviceaccounts`
- `create`/`patch` on `pods` combined with the ability to specify a privileged `serviceAccountName` or `securityContext` - lets you run a pod as a more privileged identity
- `get`/`list` on `secrets` cluster-wide - harvest other service accounts' tokens directly
- `exec`/`attach` subresource on `pods` in a namespace with more privileged workloads

### What to Look For
- `kubectl auth can-i --list` returning `*` for resources or verbs
- Any non-system `ClusterRoleBinding` targeting `cluster-admin`
- A namespace's `default` service account with a non-empty `RoleBinding` (it should almost always have none)
- `rbac-police`/`rbac-tool` flagging escalate/bind/impersonate verbs on a principal reachable from a low-trust starting point (eg. CI pipeline SA, a public-facing app's pod SA)

---

## 3 - Workload & Pod Security Configuration
### Purpose
Assess whether running workloads are configured to minimise blast radius if compromised - this determines how bad a container compromise actually is, independent of the application vulnerability that got you there.

### Possible Vulnerabilities
- `privileged: true` containers (full host device/capability access)
- `hostPID` / `hostIPC` / `hostNetwork` enabled unnecessarily
- Containers running as root (`runAsUser: 0` or unset, no `runAsNonRoot`)
- Writable root filesystem (`readOnlyRootFilesystem: false`/unset)
- Dangerous Linux capabilities retained (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_RAW`, `CAP_SYS_MODULE`)
- Host path volume mounts, especially writable, especially under `/etc`, `/var/run`, `/proc`, or the kubelet directories
- Docker/containerd socket mounted into a pod (`/var/run/docker.sock` or `/run/containerd/containerd.sock`)
- No resource `limits` set (noisy-neighbour/DoS risk on shared nodes)
- Service account tokens auto-mounted into pods that never call the API (`automountServiceAccountToken` left at default `true`)

### Commands
```bash
# Pull full pod specs for manual/scripted review
kubectl get pods --all-namespaces -o json > all-pods.json

# Quick greps against the dump for the worst offenders
jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace+"/"+.metadata.name' all-pods.json
jq -r '.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true or .spec.hostIPC==true) | .metadata.namespace+"/"+.metadata.name' all-pods.json
jq -r '.items[] | select(.spec.volumes[]?.hostPath != null) | .metadata.namespace+"/"+.metadata.name' all-pods.json

# Automated at scale - this replaces most manual jq-ing on large clusters (see §11)
kube-bench run --targets node,policies
trivy k8s cluster --report summary
trivy k8s cluster --compliance=k8s-nsa      # or k8s-cis
popeye --kubeconfig ~/.kube/config          # cluster-wide "linting" for risk, resource, and RBAC issues
```

### What to Look For
- Any `privileged: true` container that isn't an explicitly-justified system/CNI/CSI component (those legitimately need it - flag unexpected ones only)
- `hostPath` mounts pointing at sensitive host paths with `readOnly: false`
- Applications (not infra DaemonSets) running with `hostNetwork`/`hostPID`/`hostIPC`
- `kube-bench` / `popeye` output with high-severity findings concentrated in a few namespaces (often indicates a team/pipeline that skipped hardening, worth calling out specifically rather than just the aggregate count)

---

## 4 - Pod Security Admission & Policy Enforcement
### Purpose
Determine whether the hardening expected in §3 is actually *enforced* at admission time, or just a convention that's been drifted away from. A cluster with great-looking existing pods but no enforcement is one bad deployment away from a bad pod.

### Possible Vulnerabilities
- No admission controller enforcing Pod Security Standards at all (anything goes on `kubectl apply`)
- Pod Security Admission (PSA) labels set to `privileged` or missing entirely on sensitive namespaces
- Legacy PodSecurityPolicy (PSP) still referenced in docs/configs, but PSPs were removed in K8s 1.25+ - confirm the cluster actually migrated to PSA/OPA/Kyverno rather than silently losing enforcement
- OPA Gatekeeper / Kyverno installed but policies only in `audit`/`dryrun` mode, not `enforce`/`deny`
- Admission webhook `failurePolicy: Ignore` - if the webhook is down, enforcement silently disappears

### Commands
```bash
# Pod Security Admission labels per namespace
kubectl get ns -o custom-columns='NAME:.metadata.name,ENFORCE:.metadata.labels."pod-security.kubernetes.io/enforce"'

# Gatekeeper
kubectl get constrainttemplates
kubectl get constraints -A
kubectl get constraints -A -o json | jq '.items[] | {name: .metadata.name, action: .spec.enforcementAction}'

# Kyverno
kubectl get clusterpolicies -o custom-columns='NAME:.metadata.name,ACTION:.spec.validationFailureAction'

# Validating/Mutating webhook failure policy
kubectl get validatingwebhookconfigurations -o json | jq '.items[].webhooks[] | {name: .name, failurePolicy: .failurePolicy}'
```

### What to Look For
- Namespaces with no `pod-security.kubernetes.io/enforce` label (defaults to `privileged` cluster-wide unless an admission controller fills the gap)
- Gatekeeper constraints with `enforcementAction: dryrun` on anything security-critical
- Kyverno policies with `validationFailureAction: audit` left in that state long-term (fine temporarily during rollout, a finding if permanent)
- `failurePolicy: Ignore` on any security-relevant webhook

---

## 5 - Secrets Management
### Purpose
Kubernetes `Secret` objects are base64-encoded, not encrypted, by default. Assess how secrets actually reach workloads and whether that chain has any weak link.

### Possible Vulnerabilities
- Secrets stored as plain `Secret` objects with no envelope encryption at the etcd layer (encryption-at-rest for Secrets not configured)
- Hardcoded credentials in `ConfigMaps` or plain environment variables instead of `Secret`/external secret managers
- Secrets mounted as environment variables (visible via `kubectl describe pod`, process environ, crash logs) rather than files
- Any principal with `get`/`list` on `secrets` cluster-wide (ties back to [[#RBAC Privilege Escalation Patterns]])
- External secret operators (External Secrets Operator, Vault Agent) misconfigured so the backing secret store's credentials are themselves over-exposed in-cluster

### Commands
```bash
# Can the current principal read secrets broadly?
kubectl auth can-i list secrets --all-namespaces
kubectl auth can-i get secrets -n <ns>

# Enumerate secrets (if permitted) and decode
kubectl get secrets -n <ns>
kubectl get secret <name> -n <ns> -o jsonpath='{.data}' | jq 'map_values(@base64d)' 2>/dev/null \
  || kubectl get secret <name> -n <ns> -o json | jq -r '.data | to_entries[] | .key + ": " + (.value | @base64d)'

# ConfigMaps that look like they hold secrets anyway
kubectl get configmaps --all-namespaces -o json | jq -r '.items[] | select(.data | tostring | test("password|secret|token|key"; "i")) | .metadata.namespace+"/"+.metadata.name'

# etcd encryption-at-rest config (requires node/control-plane access, white-box only)
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep encryption-provider-config
```

### What to Look For
- Secrets decodable to real credentials (DB passwords, API keys, cloud provider keys) rather than placeholders
- `ConfigMaps` containing obvious secret material - a very common finding, teams often "know" Secrets exist but still put something sensitive in a ConfigMap
- No `EncryptionConfiguration` applied to the API server (secrets stored as base64 only, in plaintext in etcd)
- A low-privilege service account that can read secrets outside its own namespace

---

## 6 - Network Policy & Segmentation
### Purpose
By default, Kubernetes allows all pod-to-pod traffic within a cluster regardless of namespace. Assess whether intended tenant/environment isolation is actually enforced at the network layer or just assumed via namespacing.

### Possible Vulnerabilities
- No `NetworkPolicy` resources at all (fully flat network - any pod can reach any pod/service)
- `NetworkPolicies` defined but the CNI plugin doesn't enforce them (eg. basic kubenet, or AWS VPC CNI without the network policy add-on) - gives a false sense of security
- Default-allow instead of default-deny - policies defined per-app without a namespace-wide default-deny baseline, so anything *not* explicitly covered is still fully open
- Egress unrestricted, allowing data exfiltration or C2 callback from a compromised pod
- Multi-tenant clusters relying on namespace boundaries alone with no corresponding NetworkPolicy

### Commands
```bash
kubectl get networkpolicies --all-namespaces

# Confirm actual enforcement by testing from inside a pod lacking an explicit policy
kubectl run netpol-test --rm -it --image=busybox -n <ns> -- sh
# From inside: attempt to reach a pod/service in another namespace that should be isolated
wget -qO- --timeout=2 http://<other-ns-service>.<other-ns>.svc.cluster.local

# Check which CNI is in use (determines whether NetworkPolicy is even enforceable)
kubectl get pods -n kube-system -o wide | grep -iE 'calico|cilium|weave|flannel|aws-node|azure-cni'
```

### What to Look For
- Zero `NetworkPolicy` objects in a namespace that's supposed to be isolated from others
- A cross-namespace connection succeeding from the test pod when the intended design says it shouldn't
- CNI identified as one with limited/no NetworkPolicy enforcement (eg. plain `kubenet`, Flannel without a policy add-on) despite policies being defined - the policies are decorative
- Egress policies entirely absent (every pod can reach the internet/exfil destinations freely)

---

## 7 - Ingress, Services & Exposure
### Purpose
Identify unintended exposure paths - Services and Ingress resources that expose more than intended, and misconfigurations in the ingress controller itself.

### Possible Vulnerabilities
- `Service` of type `LoadBalancer`/`NodePort` exposing something meant to be internal-only
- Ingress resources with no TLS, or TLS termination misconfigured
- Ingress controller admin/metrics endpoints exposed alongside application traffic
- Overly permissive Ingress annotations (eg. `nginx.ingress.kubernetes.io/whitelist-source-range` misconfigured or missing where expected)
- Wildcard/default backend misconfiguration leaking information about other hosted services on a shared ingress controller

### Commands
```bash
kubectl get svc --all-namespaces -o wide | grep -E 'LoadBalancer|NodePort'
kubectl get ingress --all-namespaces -o wide
kubectl describe ingress <name> -n <ns>

# Enumerate ingress controller admin surfaces (commonly left open)
curl -sk https://<ingress-host>/nginx_status
curl -sk https://<ingress-host>:10254/metrics   # nginx-ingress-controller default metrics port
```

### What to Look For
- A `Service` type that doesn't match the workload's intended exposure (eg. an internal admin panel on `LoadBalancer`)
- Ingress with no `tls:` block serving sensitive data over plain HTTP
- Metrics/status endpoints reachable without auth, leaking internal hostnames, upstream IPs, or request data

---

## 8 - Container & Supply Chain
### Purpose
Shift from cluster configuration to what's actually running inside the containers - image provenance, known vulnerabilities, and registry security.

### Possible Vulnerabilities
- Container images with known-vulnerable OS packages or application dependencies
- Images pulled from `:latest` or other mutable tags (no guarantee of what's actually running, breaks reproducibility of findings)
- Hardcoded secrets baked into image layers (even if removed in a later layer, still present in history)
- Public/unauthenticated container registries, or registries with weak push-access control allowing image tampering
- Base images from unverified/untrusted sources
- No image signing/verification (Cosign/Notary) enforced at admission

### Commands
```bash
# Image vulnerability + misconfig + secret scanning - the standard tool for this
trivy image <registry>/<image>:<tag>
trivy image --scanners vuln,secret,misconfig <image>

# Enumerate images actually running cluster-wide, then scan all of them in bulk (see §11 for scaling this)
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u > running-images.txt
while read -r img; do trivy image --quiet --severity HIGH,CRITICAL "$img"; done < running-images.txt

# Check for mutable tags in use
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | grep -E ':latest$|^[^:]+$'

# Grype as a second scanner / cross-validation
grype <image>

# Dig through image layer history for leaked secrets without a full pull
dockle <image>
```

### What to Look For
- `CRITICAL`/`HIGH` CVEs in packages that are actually reachable/exploitable given the workload's exposure (don't just report raw CVE counts - correlate with network exposure from §7 for severity)
- Secrets flagged by Trivy's secret scanner inside image layers
- A significant fraction of running images on `:latest` across the cluster - a process finding worth calling out even without a specific CVE attached
- Registries reachable without authentication, or with push access broader than the CI pipeline that should own it

---

## 9 - Container Escape & Node Compromise (Active Exploitation)
### Purpose
> Requires explicit authorisation beyond passive config review. This confirms the *theoretical* blast radius identified in §3 is actually achievable, framed as: *"if an attacker got RCE in this specific container, what's the real impact?"*
>
> The full hands-on methodology for this - container fingerprinting, capability/namespace/mount enumeration, the low-footprint testing workflow (no package installs, no binaries left on disk), named escape techniques with PoCs, and how to approach testing many containers at scale - now lives in its own dedicated doc: **[[Container Testing]]**. This section stays scoped to the Kubernetes-specific entry points into that methodology.

### Possible Vulnerabilities / Escape Vectors
- Privileged container → full host access
- Mounted Docker/containerd socket → trivial container creation on the host
- Writable sensitive `hostPath` mount (eg. `/var/lib/kubelet`, cron directories, systemd unit paths)
- Retained dangerous capabilities (`CAP_SYS_ADMIN` allows numerous escape techniques; `CAP_SYS_PTRACE` allows ptracing host processes if `hostPID` is also set)
- Kernel vulnerabilities exploitable from within a container's namespace (shared kernel with host)
- Kubelet API (`10250`) reachable without client cert auth, allowing arbitrary `exec` into any pod on that node

> For all of the above except the kubelet-specific one, go to [[Container Testing#5 - Low-Footprint Testing Workflow|Container Testing §5]] for the tiered no-install testing approach and [[Container Testing#6 - Known Escape Techniques|§6]] for the technique-by-technique PoCs.

### Commands
```bash
# Getting into a specific pod to hand off to the Container Testing methodology
kubectl exec -it <pod> -n <ns> -- sh

# Kubernetes-specific: kubelet API unauthenticated check (from a node-level debug pod per Container Testing §5 Tier 3, or externally if exposed per §1)
curl -sk https://<node-ip>:10250/pods
curl -sk https://<node-ip>:10250/exec/<ns>/<pod>/<container>?command=id&input=1&output=1&tty=1 -X POST
```

### What to Look For
- Kubelet `/pods` or `/exec` endpoints responding without a valid client certificate - this is a critical finding (unauthenticated RCE on the node, no container escape technique even required)
- Everything else - successful privilege/capability/mount-based escape, confirmed via [[Container Testing]] - rolls back up into this section's findings when reporting on this cluster

---

## 10 - Lateral Movement, Pivoting & Persistence
### Purpose
From an initial foothold (stolen SA token, compromised container, or node access), determine how far an attacker can actually move - across pods, namespaces, and out to the underlying cloud account.

### Possible Vulnerabilities
- A stolen service account token with broad API permissions (ties directly back to [[#2 - Authentication & RBAC Enumeration]])
- Cloud credentials reachable from inside a pod (IRSA/Workload Identity tokens, or IMDS reachable with the node's own role if not properly isolated - see [[AWS Testing#8.3 - IMDS Exposure]] for the AWS-specific angle)
- Ability to create new pods/deployments with a more privileged service account or `hostPath` mounts, enabling a slower but reliable persistence/escalation path
- Weakly-protected CI/CD service accounts with cluster-wide `deploy`/`create` rights, giving a path from "compromised pipeline" to "cluster-admin"
- Backdoor-able admission webhooks or controllers running with excessive privilege

### Commands
```bash
# Confirm what the stolen/current token can actually do cluster-wide
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces
kubectl --token="$TOKEN" auth can-i --list

# Peirates - automates SA-token-to-cluster-privesc chains (K8s equivalent of Pacu for AWS)
peirates

# Cloud credential reachability from inside the pod (cloud-agnostic checks)
env | grep -iE 'aws_|azure_|google_|gcp_'
cat /var/run/secrets/kubernetes.io/serviceaccount/token    # fed to cloud STS/AAD if workload identity is federated
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ --max-time 2   # AWS IMDS, if reachable
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01" --max-time 2   # Azure IMDS

# Attempt to create a privileged pod for escalation
kubectl run privesc --image=alpine --overrides='{"spec":{"hostPID":true,"containers":[{"name":"privesc","image":"alpine","securityContext":{"privileged":true},"command":["sleep","3600"]}]}}' -n <ns>
```

### What to Look For
- A low-trust starting token (eg. a public-facing app's SA) that can reach Secrets or create pods outside its own namespace
- Workload identity federation (IRSA, Azure Workload Identity, GKE Workload Identity) tokens that map to a cloud role/identity broader than the specific workload needs
- Successful creation of a privileged pod from an identity that shouldn't be able to - confirms the RBAC gap from §2 is exploitable, not just theoretical
- `peirates` surfacing a path to `cluster-admin` or an equivalently privileged `ClusterRoleBinding`

---

## 11 - Scaling for Large Clusters
> Manual, pod-by-pod and policy-by-policy review (as described in the sections above) works fine for a handful of namespaces. For clusters with hundreds of workloads or many namespaces/tenants, manual review alone won't give adequate coverage in a time-boxed engagement - lean on automation to get full-cluster coverage, then triage manually.

- **Run the aggregator tools first, every time**: `kube-bench`, `trivy k8s cluster`, and `popeye` each produce a full-cluster report in minutes and should be the *first* thing run on any sizeable cluster, before any manual `kubectl get`/`describe` looping. Treat their output as the finding backlog to triage, not as a supplement to manual review.
- **Bulk image scanning**: extract every unique image reference cluster-wide in one `kubectl` call (§8.3) and feed the whole list through `trivy image` in a loop or `trivy` in `--list-all-pkgs`/CI mode - don't scan images one `kubectl describe pod` at a time.
- **RBAC graphing over manual reading**: on a cluster with more than a handful of roles, `rbac-tool`/`rbac-police` will find escalation paths far faster and more reliably than manually cross-referencing `Role`/`RoleBinding`/`ClusterRoleBinding` objects by eye. Reserve manual `describe` for confirming/deep-diving a specific path the tool flags.
- **Sample, don't exhaustively check, repeated patterns**: if 200 namespaces are all deployed from the same Helm chart/GitOps template, confirm the template's security posture once, then spot-check a handful of namespaces for drift rather than reviewing all 200 individually. Flag drift as its own finding category.
- **Namespace/workload triage by exposure, not alphabetically**: prioritise manual deep-dive time (container escape testing, RBAC privesc confirmation) on workloads that are internet-facing, hold the most sensitive data, or run with the broadest permissions per the automated scan output - not in whatever order `kubectl get ns` happens to return.
- **Export once, query many times**: pull `kubectl get <resource> --all-namespaces -o json` once per resource type into local files and query them repeatedly with `jq`/`rbac-tool`/custom scripts rather than re-querying the live API for every check - faster, and avoids hammering the API server on a shared/production cluster.
- **Report aggregate + exemplar**: for findings that repeat across many namespaces (eg. "47 pods run as root"), report the aggregate count plus 2-3 representative examples rather than listing all 47 individually - keeps the report usable while still proving the finding is real and widespread.

---

## 12 - Tooling

| Tool | Summary | Useful For | Install |
| ---- | ------- | ---------- | ------- |
| [kubectl](https://kubernetes.io/docs/reference/kubectl/) | Official Kubernetes CLI | Everything - baseline enumeration, applying test manifests, `exec`/`auth can-i` throughout this methodology | [Install guide](https://kubernetes.io/docs/tasks/tools/) |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Active/passive cluster attack-surface scanner | External recon (§1) - finds exposed API servers, dashboards, kubelets from outside the cluster | `pip install kube-hunter` or `docker run aquasec/kube-hunter` |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS Kubernetes Benchmark checker | Baseline control-plane/node/policy hardening checks at scale (§3, §11) | [Install guide](https://github.com/aquasecurity/kube-bench#installation) (binary release, or run as a cluster Job) |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerability, misconfig, and secret scanner for images, filesystems, and live K8s clusters | Image scanning (§8), cluster-wide misconfig scanning via `trivy k8s cluster` (§3, §11) | [Install guide](https://trivy.dev/latest/getting-started/installation/) |
| [Grype](https://github.com/anchore/grype) | Container image vulnerability scanner | Second-opinion image scanning / cross-validation against Trivy (§8) | [Install guide](https://github.com/anchore/grype#installation) |
| [Dockle](https://github.com/goodwithtech/dockle) | Container image linter for best-practice/CIS checks on image layers | Catching leaked secrets/bad practice baked into image history (§8) | [Install guide](https://github.com/goodwithtech/dockle#installation) |
| [Popeye](https://github.com/derailed/popeye) | Cluster "sanitizer" - scans live resources for misconfig, risk, and waste | Fast full-cluster triage across workloads, RBAC, and resource config (§3, §11) | [Install guide](https://popeyecli.io/doc/install) |
| [rbac-tool](https://github.com/alcideio/rbac-tool) | RBAC analysis, lookup, and visualisation for Kubernetes | Graphing who-can-do-what and privilege escalation paths at scale (§2, §11) | [Install guide](https://github.com/alcideio/rbac-tool#install) |
| [kubescape](https://github.com/kubescape/kubescape) | Kubernetes security posture scanner (NSA/CISA, MITRE ATT&CK, CIS frameworks) | Framework-aligned full-cluster scanning, alternative/complement to kube-bench+Trivy | [Install guide](https://kubescape.io/docs/getting-started/installation-cli/) |
| [Peirates](https://github.com/inguardians/peirates) | Kubernetes penetration testing tool for privilege escalation and lateral movement from a stolen service account token | Automating SA-token-to-cluster-privesc chains (§10) | [Install guide](https://github.com/inguardians/peirates#installation) |
| [netshoot](https://github.com/nicolaka/netshoot) | Network/container troubleshooting image bundling common CLI tools (curl, nmap, tcpdump, etc.) | Default image for `kubectl debug` ephemeral/node debug containers - gets tooling onto a pod/node without altering the target (§9) | `docker pull nicolaka/netshoot` (pulled automatically by `kubectl debug --image=nicolaka/netshoot`) |
| [Gatekeeper](https://github.com/open-policy-agent/gatekeeper) | OPA-based policy admission controller | Reviewing/assessing policy-as-code enforcement (§4) | [Install guide](https://open-policy-agent.github.io/gatekeeper/website/docs/install/) |
| [Kyverno](https://github.com/kyverno/kyverno) | Kubernetes-native policy engine | Reviewing/assessing policy-as-code enforcement (§4) | [Install guide](https://kyverno.io/docs/installation/) |
| [kubeaudit](https://github.com/Shopify/kubeaudit) | Audits clusters against common security hardening checks | Alternative/complement to Popeye for workload hardening checks (§3) | [Install guide](https://github.com/Shopify/kubeaudit#installation) |
| [checkov](https://github.com/bridgecrewio/checkov) / [tfsec](https://github.com/aquasecurity/tfsec) | Static analysis for IaC (Terraform/Helm/Kustomize) | IaC review if cluster manifests/Helm charts are provided as source (cross-ref [[AWS Testing#10.4 - IaC Review (if source available)]]) | [checkov install](https://www.checkov.io/2.Basics/Installing%20Checkov.html) / [tfsec install](https://aquasecurity.github.io/tfsec/latest/getting-started/installation/) |

> Container-escape-specific tools (deepce, amicontained, CDK, BOtB) and the full low-footprint escape testing workflow now live in [[Container Testing#10 - Tooling|Container Testing §10]] - not duplicated here.

---

## 13 - Manual Enumeration Cheat Sheet

| Goal | Command(s) | Notes |
| ---- | ---------- | ----- |
| Confirm current identity/permissions | `kubectl auth whoami` / `kubectl auth can-i --list` | Always run first on any new credential |
| List all namespaces | `kubectl get ns` | |
| All pods, all namespaces | `kubectl get pods -A -o wide` | |
| Full pod spec dump | `kubectl get pods -A -o json > all-pods.json` | Feed into `jq` for bulk checks, see §3.3 |
| Cluster role bindings | `kubectl get clusterrolebindings -o wide` | Grep for `cluster-admin` |
| Who can do X | `kubectl auth can-i <verb> <resource> --as=<user/SA>` | Requires impersonation rights to test *as* another identity |
| Service account tokens in a pod | `kubectl exec <pod> -n <ns> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token` | |
| Secrets in a namespace | `kubectl get secrets -n <ns>` then `kubectl get secret <name> -o json \| jq -r '.data \| map_values(@base64d)'` | |
| NetworkPolicies | `kubectl get networkpolicies -A` | Empty = flat network by default |
| Pod Security Admission labels | `kubectl get ns -o custom-columns='NAME:.metadata.name,ENFORCE:.metadata.labels."pod-security.kubernetes.io/enforce"'` | |
| Images actually running | `kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' \| sort -u` | Feed into Trivy in bulk |
| Events (recent cluster activity) | `kubectl get events -A --sort-by=.lastTimestamp` | Useful for spotting recent crashes/restarts/admission denials |
| API server version | `kubectl version` or unauthenticated `curl -sk https://<api>:6443/version` | Cross-reference against §9 CVE list |
| Node details (white-box) | `kubectl get nodes -o wide` / `kubectl describe node <name>` | Kubelet version, capacity, taints |

---

## 14 - Known CVE Checklist
> Kubernetes/container-ecosystem CVEs move fast - treat this as a starting point to check version-specific advisories against, not an exhaustive list. Always confirm the in-scope cluster/runtime version against current NVD/vendor advisories before reporting.

- Confirm Kubernetes control plane, kubelet, and container runtime (containerd/CRI-O/Docker) versions and cross-reference against:
	- [Kubernetes official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
	- [NVD search for "kubernetes"](https://nvd.nist.gov/vuln/search/results?query=kubernetes)
	- Runtime-specific advisories (containerd, CRI-O, runc - runc escape CVEs have historically been some of the highest-impact in this space)
- Check Ingress controller version (nginx-ingress, Traefik, HAProxy) against its own CVE history - ingress controllers are internet-facing by design and a common source of critical findings
- Check CNI plugin version (Calico, Cilium, Flannel) for known policy-bypass or RCE advisories
- Check any admission controllers/operators (Gatekeeper, Kyverno, cert-manager, external-secrets) for known CVEs - these run with elevated cluster permissions by design, making them high-value targets

---

## 15 - Reference Frameworks
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/) - useful for framing findings as attack paths rather than just checklist gaps
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmarks) - the primary baseline for control-plane/node/policy hardening, operationalised by [[#12 - Tooling|kube-bench]]
- [NSA/CISA Kubernetes Hardening Guidance](https://www.cisa.gov/resources-tools/resources/kubernetes-hardening-guidance) - operationalised by `kubescape`'s NSA framework
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) - the baseline/restricted/privileged tiers referenced throughout §3/§4
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- Cross-reference cloud-specific control plane concerns: [[AWS Testing#4.4 - EKS|AWS Testing §4.4/§8]] for EKS-specific identity/IMDS/IRSA detail
- Cross-reference container runtime/escape testing: [[Container Testing]] for the hands-on methodology once inside a specific workload
