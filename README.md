# Wearden Linux agent

Go agent with native checks, enrollment, heartbeat, core-assigned schedules, and durable report delivery. One-shot scans and default daemon operation are read-only. Confirmed, typed remediation and rollback require the explicit `-allow-remediation` daemon flag; see [CAPABILITIES.md](CAPABILITIES.md). No SSH or shell execution.

## Build

With the local sibling workspace described in `../proto/README.md`:

```powershell
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
go build -o ./agent-linux/bin/wearden-agent-linux-amd64 ./agent-linux/cmd/agent
```

The compiled binary is for a Linux lab. The CLI refuses to scan a Windows host. To run in the Linux lab:

```sh
./wearden-agent-linux-amd64 -rules ./filesystem.json -agent-id YOUR_ENROLLED_AGENT_ID > report.json
```

Use `ruleset/native/linux/ubuntu-24.04/catalog.json` (`ubuntu-24.04-native`, version `native-linux-3`) or `ruleset/native/linux/ubuntu-22.04/catalog.json` (`ubuntu-22.04-native`, version `native-linux-2204-1`) for the matching release. The original `filesystem.json` (`ubuntu-24.04-native-filesystem`, version `1`) remains accepted for existing CLI deployments. Both manifests are restricted to exact locally approved IDs, targets, kinds and severities; reviewed subsets are allowed. Unknown fields, changed definitions, duplicate IDs and trailing JSON are rejected. Legacy YAML commands are never executed or parsed by the agent.

For optional one-shot submission, set `WEARDEN_AGENT_TOKEN` in the process environment and pass `-core-url https://YOUR_CORE_ORIGIN -rules-sha256 EXPECTED_DIGEST_FROM_CORE`. Do not put a real token on the command line or in committed files. Digest mismatch stops scanning. The report is written to stdout before upload; upload failure returns a nonzero exit code. Save stdout to a protected file if needed. One-shot mode does not use the daemon spool.

## Scheduled operation

Supply `WEARDEN_ENROLLMENT_TOKEN` through the process/service environment on first start:

```sh
./wearden-agent-linux-amd64 -daemon -core-url https://YOUR_CORE_ORIGIN -state-dir /var/lib/wearden
```

The default state directory is `/var/lib/wearden` for root and the user's configuration directory plus `wearden` otherwise. Use a private local filesystem that supports directory fsync and flock. Only one daemon can hold the state directory lock. State directories use 0700 and state/report files use 0600. The enrollment identity, core origin and agent token are atomically persisted and synced before the first scan. Restart uses the stored identity; an enrollment token is no longer needed. Treat the directory as a secret and preserve it across upgrades. To provision an already enrolled agent, supply `WEARDEN_AGENT_TOKEN` and `-agent-id` on its first daemon start. Existing stored credentials take precedence on restart; token rotation is not automatic.

The daemon calls `/api/agent/v1/enroll`, `/heartbeat`, `/config`, `/ruleset` and `/reports`. HTTPS is required except for literal loopback IP addresses; redirects are refused. Every scan fetches the current assignment and checks the SHA-256 of the exact ruleset response bytes and its benchmark/version against the configuration before loading approved native checks. Configuration polling also runs at heartbeat wakes, so a pending dashboard scan runs within roughly one minute when core is reachable, even before the periodic deadline. Reports carry the assigned `scan_id` for dashboard correlation. The configured interval must be 60..604800 seconds. The next scan time persists across restarts. Heartbeats are attempted every minute while enrolled, including during report retries.

Reports receive stable random IDs before being atomically spooled. Pending reports are retried before any new scan, and are removed only after a matching accepted receipt. A failed upload preserves the same ID and findings across restarts, so core deduplication handles a lost acknowledgment. The spool accepts at most 100 reports and 64 MiB total, with an 8 MiB per-report limit; capacity or invalid-file errors retain existing records and stop new scanning until resolved. Delivery/config failures retry with exponential delays from one second up to one minute; enrollment retries back off up to five minutes. No new scan runs while core is unavailable or old reports remain unacknowledged. SIGINT and SIGTERM cancel network requests and scheduled waits; an in-progress native filesystem observation finishes before exit. A scan-only systemd unit is supplied in deploy/; installation is an explicit administrator action, not performed automatically.

An interrupted atomic write may leave a private `.write-*` file. Spool startup stops on such a file and retains it for operator recovery instead of silently discarding potentially complete evidence. A persistence error after enrollment stops the daemon rather than repeatedly creating new enrolled identities. The client now durably records an enrollment request ID and full metadata before its first POST. Matching receipt-loss retries recover the same identity for up to24hours without creating another asset; do not change core origin or pending metadata during recovery.

## Coverage and semantics

Ubuntu24.04 preserves all88 legacy control IDs and severities, with87 connected evaluator entries. Ubuntu22.04 preserves all100 IDs and severities, with99 connected entries. Both retain the explicit manual USR006 entry. Ubuntu22.04 adds auditd package/enablement inspection and read-only loaded audit-rule selectors; see the matching ruleset README for limits. This is a separately versioned native baseline, not verified CIS compliance or exact replication of old shell commands. File-policy findings describe the reviewed files and do not attest loaded daemon configuration, effective PAM activation or arbitrary service launch overrides.

| Native kind | Entries | Scope |
| --- | ---: | --- |
| kernel_module | 7 | Runtime loaded state and reviewed modprobe policy |
| mount_options | 3 | Effective process-namespace mount safety options |
| package_installed | 7 | Bounded dpkg status database parsing |
| apt_https | 1 | Explicit credential-free HTTPS apt source URI syntax |
| service_disabled | 12 | Explicit systemd masks or observed enablement dependency; other manager states return error |
| sysctl | 12 | Runtime numeric values from fixed `/proc/sys` paths |
| journald_config | 2 | Reviewed main configuration and priority-selected sorted drop-ins |
| file_metadata | 9 | Permission/owner metadata, without reading protected file contents |
| sshd_config | 14 | Explicit file policy, first-value precedence and reviewed includes |
| policy_config | 8 | Explicit password-policy configuration values |
| uid_zero | 1 | Local passwd UID-zero entries |
| apt_authentication |1| Explicit apt authentication policy |
| sudo_logfile |1| Reviewed global sudo logfile policy |
| pam_history |1| Required history placement and options |
| filesystem_metadata |3| Bounded root-device metadata inspection |
| ufw_runtime |5| Read-only current-namespace nftables subset |
| unsupported |1| Specific errors, never automatic pass |

The authoritative full manifest is copied exactly into `internal/config/catalog.json` and embedded in the binary. Catalog SHA-256: `9ab1d9cdcbc84b1f5e8b6a7ea4a290e17fa19a945b90e520b3c536928b938155`. A new catalog requires rebuilding the agent; remote rules cannot introduce new paths or modify rule definitions.

SSH parsing supports the standard `/etc/ssh/sshd_config.d/*.conf` include at its original position, with sorted files and first-value precedence. Match blocks, recursion, alternate include paths, complex quoting, unavailable evidence and implicit defaults return error. Journald symlinked masks/configuration and unsupported continuations also return error. Password-policy observations use the exact files audited by the legacy control; password quality drop-ins require manual merged-policy review. Zero-valued idle/login timeouts and account lockout/expiration limits cannot pass by disabling the intended policy.

The explicit manual entry is `LNX-USR-006`, which would require credential-file content access. FW002..006 use a bounded read-only nftables interpreter; unreviewed backends and packet predicates still return error. The agent never opens shadow/gshadow contents, SSH private keys or root-home file contents. Metadata audits never read regular-file contents and error on incomplete traversal or unprovable ownership. Read the authoritative native ruleset README for exact parser and traversal scope.

UFW observations combine fixed persistent settings with generation-stable kernel evidence. Matching files alone cannot pass a runtime control. Unsupported expressions/backends remain explicit errors; see the native ruleset README for the exact supported subset.

Module checks read `/proc/modules`, `/sys/module` and priority-selected modprobe configuration files. Both blacklist and a reviewed blocking install directive are required, and an active module fails. Conflicting directives, wildcard patterns, relevant aliases/softdeps, continuations and unavailable evidence yield error. This intentionally conservative subset does not pretend to fully emulate kmod. Module applicability (for example a module absent from the kernel build) is not established; such systems may require manual review instead of not_applicable.

Mount checks read `/proc/self/mountinfo`, reject missing or symlinked target paths, select the longest containing mountpoint, and require nodev/nosuid/noexec VFS options together. Ambiguous stacked mounts return error. These are process-namespace observations: container scans describe the container view, not an attested host view. Mount state may change after inspection. No snapshot/attestation guarantee is claimed.

Existing tests use synthetic filesystem evidence and loopback HTTP fixtures. No tests, builds, host scans or native Linux validation were run for this runtime implementation, at the user's request. Native Linux lab validation and deployment hardening remain necessary. Windows native checks live in the separate agent-windows implementation.

The full catalog now also has native apt authentication, sudo logfile, PAM history and bounded root-device metadata providers. The remaining explicit manual check is USR006, which would require credential-file content access. UFW live checks use nftables v0.3.0 without any mutation API calls. Filesystem metadata audits inspect names/modes/owners only, never regular-file contents, and incomplete scope yields error. See the authoritative native ruleset README for scope/limits.

Linux apply tasks now arm a separate root-controlled recovery process. Details, matching-revision receipt semantics and local operator recovery are described in CAPABILITIES.md. This does not automatically enable additional high-risk mutations.

## Distribution applicability

Initial enrollment requires explicit ID=ubuntu and VERSION_ID=22.04 or24.04 from os-release metadata. One-shot scanning, scheduled scans and fetching new task work additionally require the assignment to match that release. The ordinary /etc/os-release file or its exact standard link to /usr/lib/os-release is accepted; missing/duplicate/dynamic identity fields, arbitrary links and unsafe parent paths are refused. The original ten-control filesystem catalog follows the same distribution requirement. This checks metadata in the current filesystem namespace, not a whole-host or kernel attestation.

Already enrolled agents perform local recovery and deliver retained reports/results before refusing new incompatible work. Local manual task recovery remains available even after a distribution change. No OS metadata or live host was read while implementing this guard; only source compilation was performed. The retained Ubuntu22.04 SSH fixture can match the new22.04 assignment only after separately provisioning the native agent; its SSH service alone does not implement the agent protocol.
