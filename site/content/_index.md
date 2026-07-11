---
title: "GhostLock — rtmutex/futex stack use-after-free tracking"
description: "Linux kernel rtmutex/futex requeue-PI stack use-after-free (CVE-2026-43499, GhostLock) — local privilege escalation & container escape — distro patch status tracker"
layout: "single"
date: 2026-07-09
lastmod: 2026-07-11
cover:
  image: "ghostlock-tracker.png"
  alt: "GhostLock — Linux kernel rtmutex/futex stack use-after-free tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-43499 |
| Alias | `GhostLock` (the name its [PoC][poc] uses) |
| Component | Kernel: rtmutex priority-inheritance code — `remove_waiter()` in `kernel/locking/rtmutex.c`, reached through the futex requeue-PI path |
| Type | Stack use-after-free — `remove_waiter()` clears `pi_blocked_on` on the wrong task, leaving a dangling pointer into freed kernel-stack memory |
| Impact | An unprivileged **local** user can escalate to **root**, and an unprivileged process inside a **container** can **escape to the host**. Architecture-independent |
| Upstream fix | [`3bfdc63936dd`][fix] (*rtmutex: Use waiter::task instead of current in remove_waiter()*); first in **v7.1** |
| Introduced | [`8161239a8bcc`][intro] in **v2.6.39** (2011) — reachable for ~15 years |
| Affected window | Kernels **2.6.39 through 7.0** (every maintained tree without the backport); ≥ 7.1 fixed |
| Discoverer | Nebula Security — found by their [VEGA][vega] tool |
| Public disclosure | 2026-07-07 |
| Public PoC | [NebuSec/CyberMeowfia][poc] (drives the three-futex requeue-PI deadlock unprivileged) |
| KEV / EPSS / CVSS | NVD **CVSS 7.8 HIGH** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`); Red Hat rates it **Important**; Google kernelCTF awarded the submission $92,337 |
| Related | Part **II** of Nebula Security's *IonStack* series |

## How the exploitation chain works

GhostLock is a use-after-free of **on-stack** kernel memory in the
real-time mutex (rtmutex) priority-inheritance implementation. rtmutex
backs the kernel side of PI futexes: when a thread blocks on a PI futex it
allocates an `rt_mutex_waiter` on its **kernel stack**, links it into the
lock's waiter tree, and records the blocking relationship in the task's
`pi_blocked_on` field.

`remove_waiter()` unwinds that state. It was written for the ordinary case
— a task that blocked on its own behalf and now cleans up after itself — so
it operates on `current`: it clears `current->pi_blocked_on` and walks the
PI chain starting from `current`.

The futex **requeue-PI** path breaks that assumption.
`futex_requeue()` (with `FUTEX_CMP_REQUEUE_PI`) moves a waiter from one
futex to another and, in doing so, can take the rtmutex **on behalf of a
different task** than the one running. When that operation must be rolled
back — the requeue forms a PI **deadlock** and returns `-EDEADLK` — the
cleanup calls `remove_waiter()` from the requeuing thread's context, but the
waiter it must unlink belongs to the *other* task. `remove_waiter()`
dutifully clears `pi_blocked_on` on `current` (the requeuer) instead of on
`waiter->task` (the real waiter), and walks the wrong PI chain.

The real waiter's `pi_blocked_on` is left pointing at an `rt_mutex_waiter`
that lived in a kernel stack frame which has since unwound and been reused —
a **dangling stack pointer**. A later PI operation dereferences it; because
the attacker controls what now occupies that stack slot, the primitive
becomes a write of a controlled pointer to a near-arbitrary address —
enough to corrupt kernel structures and gain root, or, from inside an
unprivileged container, to escape to the host.

Triggering it requires arranging a specific PI **deadlock cycle** across
**three** futexes so the requeue returns `-EDEADLK` and takes the buggy
rollback path; the PoC does this from an entirely unprivileged process.

The fix, [`3bfdc63936dd`][fix], makes `remove_waiter()` operate on
`waiter->task` — the task that actually owns the waiter — instead of
`current`, so the requeue-PI rollback clears `pi_blocked_on` on the right
task and walks the right chain.

> :information_source: Any unprivileged local task can issue the requeue-PI
> futex operations — the bug needs no special device, capability, or
> unprivileged user namespace, and it is not architecture-specific. There is
> therefore **no configuration knob that closes it short of the kernel
> patch** (see [Mitigation](#mitigation)). **Only the kernel backport flips a
> verdict here.**

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`8161239a8bcc`][intro] | Introduced | *rtmutex: Simplify PI algorithm and make highest prio task get lock* (v2.6.39) — reworked the PI algorithm so `remove_waiter()` operates on `current`, which is wrong when the futex requeue-PI path unwinds a waiter owned by another task. |
| [`3bfdc63936dd`][fix] | Fixed | *rtmutex: Use waiter::task instead of current in remove_waiter()* — clears `pi_blocked_on` on the waiter's own task rather than `current`; first released in **v7.1**. |

The reachable lifetime is therefore **v2.6.39 (2011) through v7.0**; ≥ 7.1
carries the fix. The flaw is in generic locking code, so **every CPU
architecture is affected** — there is no architecture exemption.

## Upstream fixed versions

The fix reached Linus as **v7.1** and the stable maintainers backported it
across the maintained lines: **6.1.175**, **6.6.140**, **6.12.86**,
**6.18.27**, and **7.0.4**. 7.0.y took the backport in 7.0.4, well before
that line reached end of life at 7.0.14. The pre-6.1 longterm lines
(5.15.y, 5.10.y) carry the bug — but have **not** received a backport as of
this writing.

| Branch | Status | Current | Notes |
|---|---|---|---|
| Linus mainline | :white_check_mark: Carries `3bfdc63936dd` | v7.2-rc2 | first fixed release v7.1 |
| 7.1.x | :white_check_mark: Carries the fix | 7.1.3 | fixed as of the v7.1 release |
| 7.0.x | :white_check_mark: Carries the backport | 7.0.14 (EOL) | backported in 7.0.4 before end of life |
| 6.18.x | :white_check_mark: Carries the backport | 6.18.38 | LTS; first fixed point release 6.18.27 |
| 6.12.x | :white_check_mark: Carries the backport | 6.12.95 | LTS; first fixed point release 6.12.86 |
| 6.6.x | :white_check_mark: Carries the backport | 6.6.144 | LTS; first fixed point release 6.6.140 |
| 6.1.x | :white_check_mark: Carries the backport | 6.1.177 | LTS; first fixed point release 6.1.175 |
| 5.15.x | :x: Not backported | 5.15.211 | in window; no backport yet |
| 5.10.x | :x: Not backported | 5.10.260 | in window; no backport yet |

When verifying a tree directly, the fixed function is `remove_waiter()` in
`kernel/locking/rtmutex.c`; the fix replaces the use of `current` /
`current->pi_lock` with the waiter's own `waiter->task`.

## Distribution status

The deciding fact per release is whether the **kernel** carries the
[`3bfdc63936dd`][fix] backport. Because the bug dates to v2.6.39, **every**
current distro kernel is inside the affected window — there are no "predates
the bug" rows here — so a release is `:x:` until it ships the fix. The
trigger needs no privilege or special configuration, so exposure does not
vary by host posture; the kernel version is the whole story. *Fixed since*
records the date the kernel fix first lands in that release.

The rows below track a focused set of general-purpose and container-host
distributions. Other systems named in the disclosure appear only in prose
where relevant.

| Distribution | Release | Kernel | Fixed since | Status |
|---|---|---|---|---|
| Debian | sid (unstable) | 7.0.4-1 | 2026-05-08 | :white_check_mark: Fixed — first fixed upload 7.0.4-1 (now ships 7.1.3-1) |
| Debian | forky (testing) | 7.0.4-1 | 2026-05-10 | :white_check_mark: Fixed — 7.0.4-1 migrated to testing (now ships 7.0.13-1) |
| Debian | 13 (trixie) | 6.12.86-1 | 2026-05-08 | :white_check_mark: Fixed — trixie base (6.12.86-1) |
| Debian | 12 (bookworm) | 6.1.176-1 | 2026-07-03 | :white_check_mark: Fixed — via `bookworm-security` (6.1.176-1, DLA-4665-1) |
| Debian | 11 (bullseye, LTS) | 5.10.259-1 | — | :x: Vulnerable — default 5.10.y kernel has no fix; opt-in `linux-6.1` is fixed (DLA-4671-1) |
| Proxmox VE | 9 | 7.0.14-1-pve | 2026-07-01 | :white_check_mark: Fixed — proxmox-kernel-7.0.14 in pve-no-subscription |
| Proxmox VE | 8 | 6.8.12-pve | — | :x: Vulnerable — 6.8.y EOL, no backport |
| NixOS | Unstable | 6.18.36 | 2026-06-28 | :white_check_mark: Fixed — default moved to `linux_6_18` (≥ 6.18.36) |
| NixOS | 26.05 | 6.18.36 | 2026-07-03 | :white_check_mark: Fixed — default moved to `linux_6_18` (≥ 6.18.36) |
| Rocky Linux | 10 | 6.12.0-211.28.1.el10_2 | — | :x: Vulnerable — RHEL 10 kernel "Affected", no RHSA/RLSA yet |
| Rocky Linux | 9 | 5.14.0-687.17.1.el9_8 | — | :x: Vulnerable — RHEL 9 kernel "Affected", no RHSA/RLSA yet |
| Rocky Linux | 8 | 4.18.0-553.el8_10 | — | :x: Vulnerable — RHEL 8 kernel "Affected", no RHSA/RLSA yet |
| Amazon Linux | 2023 (kernel 6.1) | 6.1.176-220.360 | 2026-06-22 | :white_check_mark: Fixed — ALAS2023-2026-1882 (≥ 6.1.175-219.357) |
| Amazon Linux | 2023 (kernel6.12) | 6.12.94-123.176 | 2026-05-25 | :white_check_mark: Fixed — ALAS2023-2026-1753 (≥ 6.12.88-119.157) |
| Amazon Linux | 2023 (kernel6.18) | 6.18.36-69.136 | 2026-05-25 | :white_check_mark: Fixed — ALAS2023-2026-1754 (≥ 6.18.30-61.116) |
| Amazon Linux | 2 (kernel 4.14) | 4.14.355-284.737 | — | :x: Vulnerable — no fix expected (AL2 EOL 2026-06-30) |
| Amazon Linux | 2 (kernel-5.10) | 5.10.259-258.1043 | — | :x: Vulnerable — no fix expected (AL2 EOL 2026-06-30) |
| Amazon Linux | 2 (kernel-5.15) | 5.15.210-148.245 | — | :x: Vulnerable — no fix expected (AL2 EOL 2026-06-30) |
{.distros}

### Debian

Debian's `linux` is affected in every suite (the bug predates all of them).
**sid** first shipped a fixed kernel with `linux 7.0.4-1` on 2026-05-08 and
now rides 7.1.3-1; **forky** (testing) received the fix when `7.0.4-1`
migrated on 2026-05-10 and now ships 7.0.13-1. **trixie** (stable) was fixed
at `linux 6.12.86-1` in the base suite on 2026-05-08; `trixie-security` also
carries it at 6.12.95-1. **bookworm** (oldstable) was fixed via
`bookworm-security 6.1.176-1` (DLA-4665-1, 2026-07-03); `6.1.176` is above
the upstream first-fixed `6.1.175`, so this is not a backport below upstream.
**bullseye** (LTS) remains vulnerable on its default kernel: the `linux`
5.10.y package has no upstream backport and the security tracker keeps it
open. A fixed kernel *is* available as the separate opt-in `linux-6.1`
source package — the bookworm 6.1 kernel rebuilt for bullseye — via
`bullseye-security` (`6.1.176-1~deb11u1`, DLA-4671-1, 2026-07-04); it is not
installed by an ordinary upgrade, so a stock bullseye system stays exposed
until the admin switches to it. Debian's security tracker carries
CVE-2026-43499 and drove these assessments.

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels (`proxmox-kernel-*`), so
Debian's fix status does not carry over — and as a common VM/container host,
the container-escape vector makes it worth tracking. PVE 9's default kernel
(pinned by `proxmox-default-kernel` 2.1.0) is base **7.0.14**, at or above
the 7.0.4 backport, so a default PVE 9 host is fixed. PVE 8's default
remains on the end-of-life **6.8** line (`6.8.12-pve`), which has no
backport, so it stays vulnerable. PVE 9 hosts still running the opt-in
**6.17** kernel series are also vulnerable unless Proxmox cherry-picks the
fix into that series; watch the `pve-kernel` changelog.

### Rocky Linux / RHEL family

Rocky 10 (`6.12.0-211.28.1.el10_2`), Rocky 9 (`5.14.0-687.17.1.el9_8`), and
Rocky 8 (`4.18.0-553.el8_10`) are all inside the window (the bug predates
every EL kernel). RHEL-family kernels carry security backports without
moving their upstream base version, so the version string alone cannot
confirm a fix — the signal is an erratum. Red Hat's security data lists the
RHEL 8/9/10 `kernel` as **Affected** (severity Important) with **no** RHSA
issued, and neither AlmaLinux nor Rocky has an erratum referencing
CVE-2026-43499, so all three remain vulnerable. Because Red Hat's state is
"Affected" (not "Will not fix"), a fix is expected: Red Hat's advisory is
the leading indicator, AlmaLinux the fastest rebuild, and Rocky follows.
RHEL, Oracle Linux, and CloudLinux OS are in the same state until an
advisory lands.

### Amazon Linux

Each Amazon kernel stream is tracked as its own row above. **AL2023** is
fixed on all three streams (default `kernel` 6.1, opt-in `kernel6.12` /
`kernel6.18`). **AL2** (amzn2) reached end of support on **2026-06-30**
with no ALAS ever issued for this CVE: all three of its streams — 4.14,
plus 5.10 / 5.15 via `amazon-linux-extras` — are in-window, and AWS no
longer provides security updates or bug fixes for AL2 core packages, so
no fix is expected. An AL2 host stays permanently exploitable; the exit
is migrating to AL2023 (or another patched distribution). Status is
verified from the repodata `updateinfo.xml` (the per-CVE ALAS pages are
JS-rendered and don't fetch headlessly).

## Detection

GhostLock is architecture-independent and needs no special configuration,
so the only question is whether the running kernel is inside the affected
window and missing the fix. Compare the running kernel against the *Upstream
fixed versions* table and your distro row above:

```bash
uname -r
```

A kernel at or above its branch's first-fixed release (6.1.175 / 6.6.140 /
6.12.86 / 6.18.27 / 7.0.4), or any mainline **≥ 7.1**, carries the fix;
anything else in the 2.6.39–7.0 window without a distro backport is
vulnerable. On RHEL-family and Amazon kernels the base version does not map
to an upstream point release — rely on the distribution's advisory state
(see the rows above) rather than the number alone.

## Public PoC

The upstream PoC is in [NebuSec/CyberMeowfia][poc] (under
`IonStack/CVE-2026-43499`); it constructs the three-futex requeue-PI
deadlock and triggers the buggy `remove_waiter()` rollback from an
unprivileged process. Do **not** run it on a system you are not authorised
to test.

## Mitigation

There is **no effective mitigation short of installing a patched kernel.**
The trigger is ordinary `futex(2)` requeue-PI (`FUTEX_LOCK_PI`,
`FUTEX_WAIT_REQUEUE_PI`, `FUTEX_CMP_REQUEUE_PI`), available to every
process; it cannot be disabled, and the bug needs neither elevated privilege
nor unprivileged user namespaces — so namespace-hardening knobs such as
`kernel.unprivileged_userns_clone=0` do **not** block it.

Install a kernel that carries the [`3bfdc63936dd`][fix] backport: **6.1.175**,
**6.6.140**, **6.12.86**, **6.18.27**, **7.0.4**, or mainline **≥ 7.1**.
Until you can reboot into a fixed kernel, the only risk reduction on
multi-tenant and container hosts is ordinary defence-in-depth that does not
touch the hole itself — limit untrusted local logins and untrusted container
workloads until the host kernel is patched.

## Risk notes

- **Unprivileged local users:** on an unpatched in-window kernel, any local
  user can escalate to root — shared multi-user hosts, CI runners, and login
  servers are directly in scope.
- **Container escape:** the bug is reachable from inside an unprivileged
  container, so a hostile or compromised container can break out to the
  host. Multi-tenant container platforms are the headline risk.
- **Architecture-independent:** rtmutex and futex requeue-PI are generic
  kernel code — there is no "this architecture is safe" caveat.
- **No mitigation short of patching:** unlike bugs gated by a device node or
  a namespace toggle, there is no knob to turn; only the kernel backport
  removes the hole.
- **Long exposure window:** the flaw dates to v2.6.39 (2011), so essentially
  every unpatched production kernel is affected. Backports exist for
  6.1.175, 6.6.140, 6.12.86, 6.18.27, 7.0.4, and mainline 7.1 — check your
  distribution row.

## Verification log

*Last verified 2026-07-11.*

### Upstream

- The fix is `3bfdc63936dd` (*rtmutex: Use waiter::task instead of current
  in remove_waiter()*), first released in **v7.1** (confirmed with
  `git describe --contains` against `~/src/linux/stable`). It makes
  `remove_waiter()` operate on `waiter->task` rather than `current`.
- The bug was introduced by `8161239a8bcc` in **v2.6.39**.
- **`vulns.git` record now published** (appeared after seed; inspected via
  `origin/master`). The `.dyad` gives authoritative per-branch first-fixed
  commits, which are earlier than the seed had recorded — the seed grep
  (`--grep=3bfdc63936dd --grep='waiter::task'`) matched a follow-up fix
  (`4afda3a1da02` et al., upstream `40a25d59e85b`) that cites the original fix
  in its commit body, not the backport of the original fix itself. Corrected
  first-fixed commits (confirmed via `git describe --contains`): 6.1.175
  (`d8cce4773c2b`), 6.6.140 (`8a1fc8d698ac`), 6.12.86 (`6d52dfcb2a5d`),
  6.18.27 (`3fb7394a8377`), 7.0.4 (`88614876370a`). Mainline carries it since
  v7.1. 5.15.y and 5.10.y are in-window and not yet backported (subject/ref
  grep against `~/src/linux/stable` — empty output).
- **NVD CVSS score published**: CVSS 7.8 HIGH
  (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), confirming Red Hat's
  Important severity rating (via NVD REST API).
- Current point releases (`https://www.kernel.org/finger_banner`): mainline
  7.2-rc2; 7.1.3; 7.0.14 (EOL, fixed since 7.0.4); 6.18.38; 6.12.95;
  6.6.144; 6.1.177; 5.15.211; 5.10.260. Unchanged from prior run.

### Distributions

- **Debian** (via the security-tracker JSON, tracker.debian.org migration
  news, and snapshot.debian.org `first_seen`): sid — first fixed upload
  `7.0.4-1` on 2026-05-08 (now 7.1.3-1); testing/forky — `7.0.4-1` migrated
  2026-05-10 (now 7.0.13-1); stable/trixie — base suite `6.12.86-1` on
  2026-05-08 (trixie-security also carries 6.12.95-1); oldstable/bookworm —
  `bookworm-security 6.1.176-1` (DLA-4665-1) on 2026-07-03, with 6.1.176
  above upstream first-fixed 6.1.175. LTS/bullseye stays `:x:`: the tracker
  keeps `src:linux` (5.10.y) **open** — only the opt-in `linux-6.1` package
  (bookworm's 6.1 kernel rebuilt for bullseye) is resolved, at
  `6.1.176-1~deb11u1` (DLA-4671-1, 2026-07-04); the row tracks the default
  kernel. The seed had trixie's first-fixed wrong (recorded 6.12.95-1 /
  2026-07-05; actual 6.12.86-1 / 2026-05-08) because the upstream first-fixed
  series was also wrong at seed.
- **NixOS** (via the local nixpkgs clone): `packageAliases.linux_default` is
  `linux_6_18` on both nixos-unstable and nixos-26.05; now ships 6.18.38
  (up from 6.18.36 at seed). `linuxPackages_latest` (`linux_7_1`) is 7.1.3.
  Both channels fixed; no verdict change.
- **Proxmox VE** (via pve-no-subscription `Packages` index): PVE 9 default
  (`proxmox-default-kernel 2.1.0`) depends on `proxmox-kernel-7.0`; highest
  available is `7.0.14-4-pve` (was 7.0.14-1-pve at seed) — still fixed. PVE
  8 default is still `proxmox-default-kernel 1.1.0` → `proxmox-kernel-6.8`;
  no newer series added — still vulnerable.
- **Rocky / RHEL family** (via the Red Hat security data API and OSV): RHEL
  8/9/10 `kernel` still **Affected** with empty `affected_release` (no RHSA),
  severity Important; OSV carries only the upstream Linux ecosystem entry
  (no AlmaLinux or Rocky advisory). Rocky rows unchanged.
- **Amazon Linux** (via the repodata `updateinfo.xml`): **AL2023 fixed** on
  all three streams — ALAS2023-2026-1882 (default `kernel` 6.1, current
  `6.1.176-220.360`), ALAS2023-2026-1753 (`kernel6.12`), ALAS2023-2026-1754
  (`kernel6.18`). **AL2** never received an ALAS for CVE-2026-43499 and
  reached end of support on 2026-06-30 (per the AWS AL2 FAQ; confirmed
  against endoflife.date) — AWS no longer ships security updates for AL2
  core packages, so the 4.14 / 5.10 / 5.15 streams remain vulnerable with
  no fix expected. No verdict changes this run.

## References

| Source | URL |
|---|---|
| Disclosure writeup (Nebula Security — *IonStack* part II) | <https://nebusec.ai/research/ionstack-part-2/> |
| Public PoC (NebuSec/CyberMeowfia) | <https://github.com/NebuSec/CyberMeowfia> |
| VEGA — the discovery tool | <https://nebusec.ai/vega> |
| Kernel fix | <https://github.com/torvalds/linux/commit/3bfdc63936dd4773109b7b8c280c0f3b5ae7d349> |
| Introducing commit | <https://github.com/torvalds/linux/commit/8161239a8bcce9ad6b537c04a1fa3b5c68bae693> |
| CVE-2026-43499 | <https://www.cve.org/CVERecord?id=CVE-2026-43499> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-43499> |
| Debian package madison (dak-backed) | <https://api.ftp-master.debian.org/madison?package=linux&s=sid,forky,trixie,bookworm,bullseye&text=on> |
| AlmaLinux errata | <https://errata.almalinux.org/> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
{.references}

[poc]: https://github.com/NebuSec/CyberMeowfia
[vega]: https://nebusec.ai/vega
[fix]: https://github.com/torvalds/linux/commit/3bfdc63936dd4773109b7b8c280c0f3b5ae7d349
[intro]: https://github.com/torvalds/linux/commit/8161239a8bcce9ad6b537c04a1fa3b5c68bae693
