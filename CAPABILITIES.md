# Linux native mutation capabilities

Scanning is the default. Only daemon mode started as root with `-allow-remediation` accepts confirmed apply or rollback tasks:

```sh
./wearden-agent-linux-amd64 -daemon -allow-remediation -core-url https://YOUR_CORE_ORIGIN -state-dir /var/lib/wearden
```

The server sends IDs and task metadata, never executable commands, writable paths, ownership values or file contents. Every rule resolves from the agent's embedded catalog. Tasks require version 1, unique IDs, a lifetime no longer than 24 hours and a 30..600 second safety window. Apply additionally requires `confirmed: true`. The window bounds dispatch, local recheck and acknowledged acceptance. A separate recovery helper is now provided as described below. IP forwarding, firewall, SSH/PAM content and other mutations outside the reviewed allowlist remain disabled until their own typed write/restore plans are implemented; the presence of a watchdog alone does not grant new write capabilities.

| Writable controls | Action | Limits |
| --- | --- | --- |
| LNX-FS-001..005,007,008 | Dedicated blacklist/blocking install files in `/etc/modprobe.d` | Seven modules; active modules, ambiguous evidence or incompatible existing directives are refused. Nothing is unloaded. |
| LNX-NET-002..008 | Runtime redirect/source-route parameters set to zero, with a dedicated `/etc/sysctl.d` file per control | Requires explicit risk confirmation, local opt-in and an armed independent watchdog. Each runtime value and managed file is backed up and restored. Existing-interface versus all/default policy interactions and boot-time precedence are not attested. |
| LNX-NET-009..012 | Runtime log_martians, broadcast echo suppression, SYN cookies and ASLR, with dedicated `/etc/sysctl.d` files | Native runtime recheck required. Boot-time configuration precedence is not attested. IP forwarding remains read-only. |
| LNX-LOG-001..002 | Dedicated journald Storage/Compress drop-ins | File policy is rechecked. No daemon restart/reload or claim of loaded configuration. |
| LNX-LOG-003 | Authentication log mode 0600 | Metadata only; owner retained. Log contents are not read. |
| LNX-SSH-001 | sshd_config mode 0600, root:root | Metadata only; no SSH directives, keys, service reload or content backup. |
| LNX-USR-001,003 | passwd/group mode 0644, root:root | Metadata only; no account contents read by the mutation engine. |
| LNX-USR-002,004 | shadow/gshadow mode 0640, root:shadow | Metadata only; content is never read or backed up. Unique local shadow group resolution is required. Core requires risk confirmation. Original owner/mode is restored independently of current group lookup. |
| LNX-PAM-002..006,008..010 | Fixed password-quality, faillock deny and new-account aging configuration values | Per-control appended blocks, bounded existing files, metadata retained, selected-option drift refused. Rollback removes only its exact block and preserves other controls. No PAM activation, existing-account password aging or credential contents are changed. Core requires risk confirmation. |
| LNX-USR-010 | Root home mode 0700 | Metadata only; owner retained. Directory contents are not read. |
| LNX-USR-011..012 | crontab 0600 and sudoers 0440, root:root | Metadata only; no cron/sudo policy contents read or changed. |

These37 shared controls have mutation handlers on the matching Ubuntu22.04 and24.04 assignments. The12 additional Ubuntu22.04 audit controls are read-only. All other controls return an explicit failed change with a reason. Password-database content mutation, package installation, shell execution, firewall rules, mount changes, account modifications and arbitrary file edits are unavailable. A handler can still refuse a particular host when evidence or safe filesystem conditions are unavailable.

Targets and their ancestors must not follow symlinks. Mutation parents and root task-state ancestors must be root-controlled without group/world write access. Hard-linked regular files and targets with extended attributes or ACLs are refused because this backup format does not preserve those attributes. Do not independently change managed targets while tasks or rollbacks are pending; explicit rollback restores the saved original state.

Before the first write, the agent atomically saves and syncs a private backup identified by `run_id/rule_id`. Metadata controls store only mode/UID/GID. Managed configuration controls store the original dedicated configuration file, or its prior absence. Sysctl controls save both original runtime value and persistent drop-in state. Files are 0600 and task directories are 0700. Backup contents never enter network results. A run/rule backup is never overwritten by another apply.

If a reviewed configuration drop-in directory is absent, its absence is recorded before creating it. Rollback removes the task-created policy file but retains empty created directories as local artifacts. Atomic replacement can require temporary disk space beyond the retained-state quota.

The agent rechecks each applied rule using its native evaluator. A failed write, failed recheck or elapsed acceptance window triggers restoration and backup verification. Rollback restores the exact saved data and metadata and verifies them; its resulting native status may intentionally be non-compliant because it describes the original state. Restoration failures are reported as failures, never successful rollback.

Task journals are durable before mutation. On restart, incomplete authorized tasks restore their own prepared backups before any upload, new task fetch or scan. Apply is not replayed after an interruption. New tasks and result submission run serially between report uploads and scans. Completed results are retained and resent unchanged until the matching accepted receipt arrives; repeated task IDs reuse the retained result. A changed payload with an existing task ID is refused. Internal orphan temporary writes are retained and ignored during journal recovery.

Task journals stop accepting new task IDs at 512 records. Combined task/backups state is checked against 10,000 files and 128 MiB; originals and acknowledgment records are retained for operator archival. The agent does not silently evict backups or its task replay history. Preserve replay history when archiving: deleting acknowledged task records can permit a core that reuses those IDs to treat them as new.

No test, build, agent execution, live task, host mutation or Linux lab verification was performed for this implementation, as requested. The mechanism needs subsequent authorized lab validation before deployment.

## Independent connectivity recovery helper

Apply tasks now arm a separate session-detached instance of the installed agent binary before the first write. The helper reads only a private, root-owned task scope, announces PID/fingerprint readiness, shares the task lock with the parent, and waits for a durable matching core acknowledgement before the safety deadline. No token or executable command is passed in its arguments. A binary/path that is not root-controlled cannot arm it, and no mutation begins without readiness.

If the deadline elapses without an acknowledged receipt, the helper restores the task's prepared local backups and writes result revision1. Core retains result history: revision1 can correct an accepted revision0 whose receipt was lost, so a recovered host is not left permanently displayed as applied. A receipt after the deadline cannot disarm recovery. Normal task IDs and immutable revision payloads remain idempotent.

If restoration cannot be fully verified, a failed revision1 correction is retained, uploaded, and subsequent scans/mutations stop for local operator intervention. The private journal records the detailed recovery error. Recovery state is never silently cleared or evicted. Interrupted startup without a completed result still restores locally before networking.

The supplied systemd unit uses KillMode=process so a recovery helper survives the main process exiting or being stopped. The default unit remains scan-only. Add -allow-remediation only after local review. Do not change KillMode to control-group while relying on child helpers; reboot/startup recovery remains separate from a running independent process. This mechanism does not interrupt blocked kernel I/O or protect against a privileged administrator killing every recovery process. No watchdog was executed or tested in this session.

The recovery lease uses kernel boot identity and elapsed boot time, not a serialized wall-clock timer. Receipt deadlines are checked again after HTTP delivery, so NTP adjustments, suspend/resume or reboot do not grant an extra confirmation window. Clock-evidence loss after arming requests conservative restoration rather than treating it as confirmation.

If a retained recovery error requires intervention, stop the daemon and invoke the installed binary locally as root with `-state-dir /var/lib/wearden-agent -recover-task TASK_ID`. This only restores the selected authorized task's approved snapshots under exclusive daemon/task locks. It cannot fetch paths/commands from core or forge core acknowledgements. An already published failed revision remains immutable history; normal subsequent scans describe current state. Recovery errors are cleared only after restoration succeeds. No manual recovery command was executed here.

## Redirect and source-route controls

NET002..008 now use the same typed sysctl write/backup/recheck/restore path as NET009..012. Core treats these seven network changes as risky even though the imported YAML marks them false. Planning, run creation and persisted changes use that effective risk value, so the browser requires explicit operator confirmation. The YAML content is preserved unchanged. No host setting was changed during implementation.

NET001 remains excluded: changing ip_forward can reset other IPv4 settings, so restoring only its original value would not restore the complete previous state. A future implementation needs a reviewed multi-setting snapshot and restore plan. See the [Linux kernel IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html), inspected on 2026-11-15.

Password-policy parser semantics were inspected in [shadow getdef.c](https://raw.githubusercontent.com/shadow-maint/shadow/master/lib/getdef.c) and [libpwquality settings.c](https://raw.githubusercontent.com/libpwquality/libpwquality/master/src/settings.c). These controls describe configuration values, not active PAM-stack enforcement. Password-quality drop-ins remain subject to the existing explicit merged-policy observation guard. No native policy operation or test was executed.

The fixed faillock deny value5 uses the same per-control policy backup/recovery path. Its last-value assignment was inspected in [Linux-PAM faillock_config.c](https://raw.githubusercontent.com/linux-pam/linux-pam/master/modules/pam_faillock/faillock_config.c). It does not activate PAM modules or modify/reset account lockout records.
