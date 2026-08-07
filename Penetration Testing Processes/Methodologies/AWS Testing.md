```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

> This methodology targets an **authenticated AWS configuration review** (white-box, read-only IAM access) rather than a black-box external attack simulation. The goal is to assess configuration against best practice / CIS benchmarks and identify realistic misconfiguration-driven attack paths (priv esc, lateral movement, data exposure), not to actively exploit production.

## 0 - Scoping & Access Prep
### 0.1 - Scoping Questions
- Is this a single account or an AWS Organization? How many accounts are in scope?
	- If Organization: is the management/root account in scope, or only member accounts?
- Which regions are in scope? (default to "all enabled regions" - don't just assume `us-east-1`)
- Which services/workloads are explicitly in/out of scope? (eg. is production data access out of scope even if reachable?)
- Is this purely a config review, or does it include active exploitation (priv esc chains, pivoting into EC2/containers)?
- Is IaC source available for review (Terraform/CloudFormation/CDK)? [[#10.4 - IaC Review (if source available)|Jump]]
- Is there a specific compliance framework to assess against (CIS AWS Foundations, PCI, Well-Architected Security Pillar)?
- Who is the technical point of contact for account access issues / lockouts?

### 0.2 - Access Model
- Request **read-only** access via a dedicated cross-account IAM role rather than long-lived user credentials
	- AWS managed policies: `SecurityAudit` + `ViewOnlyAccess` cover the vast majority of what's needed for a config review
	- If IAM privilege-escalation graphing is in scope, `iam:List*` / `iam:Get*` is required at minimum (covered by `SecurityAudit`)
- Confirm whether MFA / external ID is required to assume the role
- Confirm session duration - long reviews across many services can exceed default 1hr STS token lifetime, request up to 12hrs if possible
- Get the list of in-scope Account IDs up front - useful for quickly spotting cross-account trust to *unexpected* accounts later

### 0.3 - Tooling Setup
```bash
aws configure --profile client-review
aws sts get-caller-identity --profile client-review

# Assuming a cross-account role
aws sts assume-role --role-arn arn:aws:iam::<account-id>:role/<review-role> \
  --role-session-name pentest-review --external-id <if-required>
```
- Set up separate named profiles per in-scope account (`~/.aws/config`) to avoid accidentally running commands against the wrong account
- Confirm the identity being used has no write/delete permissions before running any tooling (`aws iam simulate-principal-policy` or just attempt something authoritatively read-only first)

---

## 1 - Account & Organisation Structure
- Map the AWS Organization: management account, OUs, member accounts
	- `aws organizations describe-organization` / `list-accounts` / `list-organizational-units-for-parent`
- Review Service Control Policies (SCPs) attached at Org/OU/account level - are they actually restrictive, or just deny lists with gaps?
	- `aws organizations list-policies --filter SERVICE_CONTROL_POLICY`
- Identify delegated administrator accounts for services (GuardDuty, Security Hub, Config)
- Check consolidated billing / cost anomaly alerts (can be an early indicator of resource abuse/compromise)
- Confirm which regions are actually in use vs enabled-but-unused (unused regions still need a baseline config check - "forgotten region" resources are common findings)
	- `aws account list-regions` / check per-region for resources rather than trusting the client's stated scope

---

## 2 - Identity & Access Management (IAM)
### 2.1 - Root Account
- MFA enabled on root? Hardware MFA for high-value accounts?
- Root access keys should not exist at all
- Root account should not be used for day-to-day activity - check CloudTrail for recent root usage
	- `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root`

### 2.2 - Users, Roles & Federation
- Is IAM Identity Center (SSO) used, or are there many long-lived IAM users? (SSO federation is best practice)
- Password policy: length, complexity, reuse prevention, expiry
	- `aws iam get-account-password-policy`
- MFA enforced for all human users? (`aws iam list-virtual-mfa-devices` vs `list-users`)
- Access key age and rotation - flag keys >90 days old
	- `aws iam generate-credential-report` then `aws iam get-credential-report`
- Unused users/roles/credentials (no activity in 90+ days) - `IAM Access Analyzer` unused access findings or `get-credential-report`
- Console access for service/automation accounts (should be API-only)

### 2.3 - Policies & Least Privilege
- Wildcard actions/resources in customer-managed and inline policies (`"Action": "*"`, `"Resource": "*"`)
- Full admin policies (`AdministratorAccess`) attached directly to users rather than assumed via role
- Inline policies vs managed policies (harder to audit/version-control at scale - not inherently bad but worth noting)
- Use **Cloudsplaining** ([[#10.2 - IAM-Specific]]) or IAM Access Analyzer to flag privilege escalation and resource exposure risk at scale rather than manually reading every policy document

### 2.4 - Privilege Escalation Paths
> IAM misconfig is usually where the real findings are in a config review - a single overly-broad policy can undermine dozens of other controls.

- Enumerate for the classic IAM-to-IAM privesc patterns (any principal that can do the below against a *more privileged* principal):
	- `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion` on a policy they don't otherwise control
	- `iam:CreateAccessKey` / `iam:UpdateLoginProfile` on another (privileged) user
	- `iam:AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` / `Put*Policy`
	- `iam:PassRole` combined with a compute/orchestration action that lets you *run code as* that role:
		- `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` (or `AddPermission`)
		- `iam:PassRole` + `ec2:RunInstances` (with an instance profile)
		- `iam:PassRole` + `ecs:RegisterTaskDefinition` / `RunTask` (task role)
		- `iam:PassRole` + `glue:CreateDevEndpoint` / `UpdateDevEndpoint`
		- `iam:PassRole` + `cloudformation:CreateStack`
	- `sts:AssumeRole` chains - does a low-priv principal have a path (possibly multi-hop) to assume a high-priv role via a permissive trust policy?
	- `iam:UpdateAssumeRolePolicy` - can a principal modify a role's trust policy to add themselves?
- Use **[[PMapper]]** (Principal Mapper) to auto-graph these paths across the whole account rather than manually chaining permissions
- Reference: [Rhino Security Labs - AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

### 2.5 - Trust Relationships & Cross-Account Access
- Enumerate all IAM role trust policies - who can assume each role?
	- Look for `"Principal": {"AWS": "*"}` or wildcard account IDs
	- Cross-account roles for third parties (SaaS integrations, MSPs) - is `sts:ExternalId` enforced to prevent the [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)?
	- Are trusted account IDs actually the ones expected, or unfamiliar/unexplained accounts?
- Resource-based policies granting cross-account or public access:
	- S3 bucket policies, KMS key policies, Lambda resource policies, SNS topic policies, SQS queue policies, ECR repo policies
	- IAM Access Analyzer surfaces most of this automatically - `aws accessanalyzer list-findings`

### 2.6 - Credential Hygiene
- Check for hardcoded credentials in Lambda env vars, EC2 user-data, ECS task defs, CodeBuild buildspecs
- Access keys belonging to service accounts that could instead use roles (EC2 instance profiles, ECS task roles, Lambda execution roles)
- Old/unrotated KMS-encrypted secrets, or secrets stored in plaintext SSM Parameter Store instead of SecureString/Secrets Manager

---

## 3 - Networking (VPC)
### 3.1 - VPC Layout & Segmentation
- Enumerate all VPCs, CIDR ranges, and whether the **default VPC** is still present/in-use (should generally be removed if unused)
	- `aws ec2 describe-vpcs`
- Public vs private subnet segregation - are workloads that shouldn't be internet-facing actually in private subnets with no route to an IGW?
- VPC Peering / Transit Gateway connections - review route tables for unintended reachability between environments (eg. dev VPC routable to prod VPC)
- CIDR overlap between VPCs that are peered (breaks routing, sometimes silently)

### 3.2 - Security Groups & NACLs
- Security Groups with `0.0.0.0/0` (or `::/0`) ingress on sensitive ports: `22`, `3389`, `3306`, `5432`, `1433`, `6379`, `9200`, `27017`, and management/DB ports generally
	- `aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0`
- Overly-permissive egress (`0.0.0.0/0` on all ports) - not always a finding but worth noting for data exfiltration risk assessment
- Security groups referencing other SGs vs hardcoded IPs (SG-to-SG references are best practice for dynamic environments like ECS/EKS)
- Unused/orphaned security groups (housekeeping finding, low severity)
- NACLs - usually left at default allow-all; only worth deep review if the client says they rely on NACLs for segmentation

### 3.3 - Ingress/Egress Paths
- Internet Gateways - which VPCs have one attached, and does anything actually need it?
- NAT Gateway placement - are private subnets routing egress through NAT rather than directly exposing instances?
- Any EC2 instances with public IPs that shouldn't have them (`aws ec2 describe-instances` cross-referenced with subnet/route table)
- Elastic IPs - enumerate and confirm all are attached/justified (unattached EIPs cost money and are a housekeeping flag)

### 3.4 - DNS & Endpoints
- Route 53 public hosted zones - check for internal hostnames/IPs leaking infrastructure detail
- VPC Endpoints (Gateway - S3/DynamoDB; Interface/PrivateLink - most other services) in use to avoid traffic egressing to the public internet for AWS API calls
- Interface endpoint security groups - are they open to the whole VPC when they shouldn't be?
- Split-horizon DNS / Route 53 Resolver rules for hybrid connectivity

### 3.5 - Flow Logs
- VPC Flow Logs enabled at VPC (or at least subnet/ENI) level for all in-scope VPCs
	- `aws ec2 describe-flow-logs`
- Destination: CloudWatch Logs vs S3 - check retention and access controls on the destination too

---

## 4 - Compute
### 4.1 - EC2
- IMDSv1 vs IMDSv2 enforcement (`HttpTokens: required`) - IMDSv1 is a classic SSRF-to-credential-theft vector
	- `aws ec2 describe-instances --query 'Reservations[].Instances[].MetadataOptions'`
- Instance profile roles - overly broad permissions attached to instances with a large network attack surface (eg. public-facing web servers with admin-ish roles)
- Public AMIs / snapshots shared publicly (see [[#5.2 - EBS & Snapshots]])
- Unencrypted EBS volumes attached to instances
- SSH key management - shared keys across many instances, no rotation path
- Patch/AMI currency - is the client using golden AMIs / SSM Patch Manager, or are instances drifting?

### 4.2 - Lambda
- Execution role permissions - least privilege per function, or one shared over-permissioned role reused everywhere?
- Environment variables containing plaintext secrets (should reference Secrets Manager/SSM instead)
- Function URLs / resource policies exposing functions publicly without auth
- Lambda layers and dependencies - outdated/vulnerable packages
- VPC-attached vs not - does the function need VPC access, and if so is it in the right subnet/SG?

### 4.3 - ECS
- **Task Role vs Task Execution Role** - confirm the distinction is respected (execution role pulls images/logs/secrets for the agent; task role is what the *application* assumes) - a common misconfig is granting application-level permissions on the execution role
- Task definitions - `aws ecs describe-task-definition` - check for:
	- Hardcoded secrets in `environment` blocks instead of `secrets` (Secrets Manager/SSM references)
	- `privileged: true` containers
	- Host network mode (`networkMode: host`) - removes network isolation between tasks
	- Read-only root filesystem not set where it could be
- Cluster capacity providers - EC2-backed clusters: is the underlying EC2 IMDS reachable from containers? (relevant if `networkMode` isn't `awsvpc`)
- Service auto-scaling and deployment configuration (not usually a security finding, but worth noting for availability)

### 4.4 - EKS
- Cluster endpoint access: public, public+private, or private-only? If public, is it restricted via `--public-access-cidrs`?
	- `aws eks describe-cluster --name <cluster> --query 'cluster.resourcesVpcConfig'`
- Cluster authentication: `aws-auth` ConfigMap (legacy) vs EKS Access Entries (newer) - who/what is mapped to `system:masters`?
	- `kubectl -n kube-system get configmap aws-auth -o yaml` (if cluster access is in scope) or `aws eks list-access-entries` / `describe-access-entry`
- RBAC - review `ClusterRoleBindings` for `cluster-admin`, check for overly broad `Role`/`ClusterRole` grants
- IRSA (IAM Roles for Service Accounts) - are pods using scoped-down IRSA roles, or is everything running on an overly-permissive node instance role?
	- Check the OIDC provider trust policy condition (`sub` claim) is scoped to the specific namespace/service account, not wildcarded
- Secrets - K8s Secrets are only base64-encoded by default; confirm envelope encryption via KMS is enabled (`aws eks describe-cluster --query 'cluster.encryptionConfig'`)
- Logging - control plane logging enabled (API server, audit, authenticator logs) and shipped to CloudWatch
- Managed node groups vs self-managed vs Fargate profiles - node IAM role scope, and whether IMDS is reachable from pods (see 8.3)

### 4.5 - Fargate
- No underlying host to assess, but the same **task/pod-level IAM role** and secrets-handling concerns from ECS/EKS apply
- Confirm workloads that don't need persistent storage aren't over-provisioned with EFS mounts granting broader filesystem access than needed
- Fargate task/pod still has network-level access to the IMDS-equivalent metadata endpoint for its own credentials - confirm least privilege on that role since there's no "compromise the host" step needed, just the container

---

## 5 - Storage & Data
### 5.1 - S3
- **Account-level** Block Public Access settings, then **per-bucket** overrides
	- `aws s3control get-public-access-block --account-id <id>`
	- `aws s3api get-public-access-block --bucket <name>`
- Bucket ACLs (legacy) and bucket policies - any `Principal: "*"` without a condition
- Default encryption (SSE-S3 vs SSE-KMS) and bucket key usage
- Versioning + MFA delete on buckets holding critical/backup data
- Access logging / CloudTrail data events enabled for sensitive buckets
- Cross-account replication targets - confirm destination account is expected
- Public buckets found via automated scan should be manually verified for actual sensitive content before reporting severity

### 5.2 - EBS & Snapshots
- Default EBS encryption enabled account/region-wide
	- `aws ec2 get-ebs-encryption-by-default`
- Public snapshots (`aws ec2 describe-snapshots --restorable-by-user-ids all --owner-ids self`)
- Public AMIs (`aws ec2 describe-images --owners self --executable-users all`)

### 5.3 - RDS / Aurora / DynamoDB
- Publicly accessible RDS instances (`PubliclyAccessible: true`) and whether that's actually required
- Encryption at rest enabled, and in-transit enforcement (`rds.force_ssl` parameter)
- Automated backups/snapshots - encrypted, and not publicly shared
- IAM database authentication vs static DB credentials
- DynamoDB - encryption at rest (KMS), point-in-time recovery, and table-level resource policies

### 5.4 - EFS
- Encryption at rest/in-transit
- File system policy - public/cross-account access
- Access points scoping POSIX permissions appropriately per-application

---

## 6 - Secrets & Key Management
### 6.1 - KMS
- Key policies - avoid `"Principal": "*"` combined with permissive `Action` unless intentionally cross-account with tight conditions
- Key rotation enabled for customer-managed keys (`aws kms get-key-rotation-status`)
- Use of AWS-managed vs customer-managed keys for sensitive data (CMKs give auditability/control via CloudTrail)
- Key deletion protection / pending-deletion window review (has anything been scheduled for deletion that shouldn't be?)

### 6.2 - Secrets Manager / SSM Parameter Store
- Secrets Manager rotation configured for DB credentials etc.
- Resource policies on secrets/parameters for unintended cross-account or overly broad access
- SecureString usage in Parameter Store vs plaintext String for sensitive values
- Access logged via CloudTrail data events

### 6.3 - Certificate Manager
- Certificate expiry monitoring
- Private CA usage and root key protection if ACM Private CA is in use

---

## 7 - Logging, Monitoring & Detection
### 7.1 - CloudTrail
- Multi-region trail enabled, covering management + data events for critical resources (S3, Lambda)
	- `aws cloudtrail describe-trails` / `get-trail-status`
- Log file validation enabled (integrity)
- Trail's destination S3 bucket - encrypted, not publicly accessible, and ideally in a separate "log archive" account
- CloudTrail itself not disabled/deleted by an over-privileged principal without alerting (check for `StopLogging`/`DeleteTrail` events historically)

### 7.2 - AWS Config
- Config enabled in all in-scope regions, recording all resource types
- Conformance packs / managed rules mapped to CIS AWS Foundations Benchmark
- Config aggregator set up for multi-account visibility (if Organization-wide)

### 7.3 - GuardDuty & Security Hub
- GuardDuty enabled in all in-scope regions, with an Organization delegated admin if multi-account
- Findings triaged/actioned, or just accumulating unread? (Process gap, not a technical one, but worth noting)
- Security Hub enabled with relevant standards (CIS, AWS FSBP) and integrated with GuardDuty/Config/Inspector findings

### 7.4 - CloudWatch Alarms
- Alarms for security-relevant CloudTrail events (root usage, IAM policy changes, unauthorized API calls, console sign-in without MFA, security group changes) - typically shipped as CIS-aligned metric filters + alarms
- SNS topics behind alarms actually have subscribers who'll act on them

---

## 8 - Container & Kubernetes Deep-Dive
### 8.1 - ECR
- Repository policies - public repos or unintended cross-account pull/push access
- Image scanning on push enabled (basic or enhanced/Inspector-based)
- Lifecycle policies to expire old/untagged images (housekeeping, but stale images can hide unpatched vulnerabilities)
- Immutable tags enabled to prevent tag-overwrite supply-chain tricks

### 8.2 - Task/Pod Identity (IAM Roles vs IRSA)
- ECS: confirm application code only has the **task role**, not the broader **execution role**, and that the task role is scoped per-service rather than one shared role for the whole cluster
- EKS: confirm IRSA (or EKS Pod Identity) is used per-service-account rather than pods inheriting the **node's** IAM role wholesale - the node role is often broader than any single workload needs

### 8.3 - IMDS Exposure
- For EC2-backed ECS/EKS nodes: is IMDSv2 enforced, and is the **hop limit** low enough (`HttpPutResponseHopLimit: 1`) to prevent containers from reaching the node's IMDS and stealing the *node role* credentials (rather than their own scoped task/pod role)?
- For EKS specifically, check `aws-node`/hostNetwork pods and any pod with `hostNetwork: true` - they inherit node-level network access to IMDS
- Fargate has no reachable node IMDS at all - not applicable there

### 8.4 - EKS Cluster & RBAC
- (cross-ref [[#4.4 - EKS]] for endpoint/auth basics)
- Namespace isolation - are multi-tenant workloads actually separated by namespace + NetworkPolicy + RBAC, or just by convention?
- Kubernetes NetworkPolicies in place (default allow-all pod-to-pod traffic otherwise) - requires a CNI that enforces them (Calico, Cilium; the default AWS VPC CNI has limited enforcement without add-ons)
- Service accounts - default service account token auto-mounted into pods that don't need API access (`automountServiceAccountToken: false` where not needed)

### 8.5 - Pod/Container Hardening
- Privileged containers / `hostPID`, `hostIPC`, `hostNetwork`
- Containers running as root vs non-root (`runAsNonRoot`, `readOnlyRootFilesystem`)
- Resource limits set (availability/DoS consideration between tenants on shared nodes)
- Pod Security Standards / admission control (PSA, OPA/Gatekeeper, Kyverno) enforced vs advisory-only
- Secrets mounted as env vars vs files, and whether K8s Secrets are actually necessary vs external-secrets synced from Secrets Manager

### 8.6 - Fargate-Specific Notes
- No host to break out to, so focus shifts entirely to task/pod IAM scope and network reachability between Fargate tasks (SGs, NetworkPolicies where supported)
- Confirm logging (awslogs driver / Fargate log router) actually captures what's needed since there's no host-level log access for later investigation

---

## 9 - Other Managed Services (Quick Hits)
- **API Gateway** - authorizers configured (IAM/Cognito/Lambda), throttling/usage plans, resource policies, request validation
- **CloudFront** - Origin Access Control/Identity restricting direct S3 origin access, WAF association, viewer protocol policy (HTTPS enforced)
- **ELB/ALB/NLB** - listener security policies (TLS versions/ciphers), access logging enabled, WAF attached where relevant
- **SNS/SQS** - topic/queue resource policies for public or unintended cross-account publish/subscribe
- **Systems Manager (SSM)** - Session Manager preferred over open SSH/RDP; document/automation permissions scoped
- **Cognito** - user pool MFA policy, app client secret handling, identity pool unauthenticated role permissions (a classic source of overly-broad public/anonymous access)
- **Elastic Beanstalk** - underlying resources (EC2/ASG/ELB) often drift from org baseline since EB manages them - review as if they were manually provisioned

---

## 10 - Tooling
### 10.1 - Automated Scanners
- **[[Prowler]]** - broad CIS/best-practice checks across most services, good first pass for coverage
- **[[ScoutSuite]]** - similar broad coverage, strong HTML report for client-facing evidence
- **[[Steampipe]]** - SQL-queryable AWS API for custom/ad-hoc checks not covered by the above

### 10.2 - IAM-Specific
- **[[PMapper]]** - graphs IAM privilege escalation and access paths across an account
- **Cloudsplaining** - offline IAM policy analysis for risky permissions (privesc, resource exposure, credentials exposure)
- **[[Pacu]]** - AWS exploitation framework, useful if active exploitation of priv-esc/lateral movement is in scope beyond pure config review

### 10.3 - Container / K8s
- **kube-bench** - CIS Kubernetes Benchmark checks against the cluster (limited applicability on EKS since AWS manages the control plane - focus on node/workload-level checks)
- **kube-hunter** - active K8s attack surface enumeration (only if active testing, not pure config review, is in scope)
- **Trivy** - image scanning for ECR images (vulnerabilities + misconfig + exposed secrets in layers)

### 10.4 - IaC Review (if source available)
- **checkov** / **tfsec** - static analysis of Terraform/CloudFormation/CDK for the same class of misconfig, often faster and more precise than reading live resources when source is available
- Cross-reference live-account findings against IaC to establish whether drift exists (manual console changes outside of pipeline)

---

## 11 - Manual Enumeration Cheat Sheet

| Goal | Command(s) | Notes |
| ---- | ---------- | ----- |
| Confirm current identity | `aws sts get-caller-identity` | Always run first per profile/role |
| Account password policy | `aws iam get-account-password-policy` | |
| Credential report (keys, MFA, age) | `aws iam generate-credential-report && aws iam get-credential-report` | Report generation is async, retry `get` |
| List all roles + trust policies | `aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]'` | Grep output for `"AWS": "*"` |
| Access Analyzer findings | `aws accessanalyzer list-findings --analyzer-arn <arn>` | Requires an analyzer to already exist |
| Public S3 buckets | `aws s3api list-buckets` + `get-public-access-block` / `get-bucket-policy` per bucket | Scripts like Prowler do this at scale |
| Default EBS encryption | `aws ec2 get-ebs-encryption-by-default` | Per region |
| SGs open to the world | `aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0` | |
| CloudTrail status | `aws cloudtrail describe-trails && aws cloudtrail get-trail-status --name <trail>` | Check `IsMultiRegionTrail` |
| GuardDuty enabled? | `aws guardduty list-detectors` | Empty result = not enabled in that region |
| EKS cluster config | `aws eks describe-cluster --name <cluster>` | Endpoint access, encryption config, logging |
| ECS task definition | `aws ecs describe-task-definition --task-definition <name>` | Check `executionRoleArn` vs `taskRoleArn`, `secrets` vs `environment` |
| Enumerate all regions with resources | loop `aws ec2 describe-instances`/etc across `aws account list-regions` | Don't trust the client's stated region list |

---

## 12 - Reference Frameworks
- [CIS Amazon Web Services Foundations Benchmark](https://www.cisecurity.org/benchmarks) - the primary baseline for this kind of review
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/) - useful for framing findings as attack paths rather than just checklist gaps
- [Rhino Security Labs - AWS IAM Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [AWS Security Reference Architecture (SRA)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html) - useful for judging what "good" multi-account architecture looks like
