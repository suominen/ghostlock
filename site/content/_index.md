---
title: "GhostLock — rtmutex/futex stack use-after-free tracking"
description: "Linux kernel rtmutex/futex requeue-PI stack use-after-free (CVE-2026-43499, GhostLock) — local privilege escalation & container escape — distro patch status tracker"
layout: "single"
date: 2026-07-09
lastmod: 2026-07-09
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
| KEV / EPSS / CVSS | Not yet scored (no NVD / `vulns.git` record at seed); Red Hat rates it **Important**; Google kernelCTF awarded the submission $92,337 |
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
across the maintained lines: **6.1.177**, **6.6.144**, **6.12.95**,
**6.18.36**, and **7.0.13**. 7.0.y took the backport in 7.0.13, just before
that line reached end of life at 7.0.14. The pre-6.1 longterm lines
(5.15.y, 5.10.y) carry the bug — but have **not** received a backport as of
this writing.

| Branch | Status | Current | Notes |
|---|---|---|---|
| Linus mainline | :white_check_mark: Carries `3bfdc63936dd` | v7.2-rc2 | first fixed release v7.1 |
| 7.1.x | :white_check_mark: Carries the fix | 7.1.3 | fixed as of the v7.1 release |
| 7.0.x | :white_check_mark: Carries the backport | 7.0.14 (EOL) | backported in 7.0.13 before end of life |
| 6.18.x | :white_check_mark: Carries the backport | 6.18.38 | LTS; first fixed point release 6.18.36 |
| 6.12.x | :white_check_mark: Carries the backport | 6.12.95 | LTS; first fixed point release 6.12.95 |
| 6.6.x | :white_check_mark: Carries the backport | 6.6.144 | LTS; first fixed point release 6.6.144 |
| 6.1.x | :white_check_mark: Carries the backport | 6.1.177 | LTS; first fixed point release 6.1.177 |
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
| Debian | sid (unstable) | 7.0.13-1 | 2026-06-19 | :white_check_mark: Fixed — first fixed upload 7.0.13-1 (now ships 7.1.3-1) |
| Debian | forky (testing) | 7.0.13-1 | 2026-06-28 | :white_check_mark: Fixed — 7.0.13-1 migrated to testing |
| Debian | 13 (trixie) | 6.12.95-1 | 2026-07-05 | :white_check_mark: Fixed — via `trixie-security` (6.12.95-1) |
| Debian | 12 (bookworm) | 6.1.176-1 | 2026-07-03 | :white_check_mark: Fixed — via `bookworm-security` (6.1.176-1, Debian backport) |
| Debian | 11 (bullseye, LTS) | 5.10.223-1 | — | :x: Vulnerable — 5.10.y not backported (tracker: open) |
| Proxmox VE | 9 | 7.0.14-1-pve | 2026-07-01 | :white_check_mark: Fixed — proxmox-kernel-7.0.14 in pve-no-subscription |
| Proxmox VE | 8 | 6.8.12-pve | — | :x: Vulnerable — 6.8.y EOL, no backport |
| NixOS | Unstable | 6.18.36 | 2026-06-28 | :white_check_mark: Fixed — default moved to `linux_6_18` (≥ 6.18.36) |
| NixOS | 26.05 | 6.18.36 | 2026-07-03 | :white_check_mark: Fixed — default moved to `linux_6_18` (≥ 6.18.36) |
| Rocky Linux | 10 | 6.12.0-211.28.1.el10_2 | — | :x: Vulnerable — RHEL 10 kernel "Affected", no RHSA/RLSA yet |
| Rocky Linux | 9 | 5.14.0-687.17.1.el9_8 | — | :x: Vulnerable — RHEL 9 kernel "Affected", no RHSA/RLSA yet |
| Rocky Linux | 8 | 4.18.0-553.el8_10 | — | :x: Vulnerable — RHEL 8 kernel "Affected", no RHSA/RLSA yet |
| Amazon Linux | 2023 | 6.12.x (amzn2023) | — | :x: Vulnerable — ALAS has no advisory / kernel fix for this CVE yet |
| Amazon Linux | 2 | 5.10.x (amzn2) | — | :x: Vulnerable — ALAS has no advisory / kernel fix for this CVE yet |
{.distros}

### Debian

Debian's `linux` is affected in every suite (the bug predates all of them),
but the security team has now resolved it everywhere except bullseye.
**sid** first shipped a fixed kernel with `linux 7.0.13-1` on 2026-06-19 and
now rides 7.1.3-1; **forky** (testing) took the same 7.0.13-1 on 2026-06-28.
The stable suites were fixed through the **security archive**: **trixie** via
`trixie-security 6.12.95-1` (2026-07-05, matching the upstream 6.12.95
backport) and **bookworm** via `bookworm-security 6.1.176-1` (2026-07-03) —
a Debian **backport** of the fix, since upstream 6.1 did not carry it until
6.1.177. Only **bullseye** remains open: its 5.10.y kernel has no upstream
backport and Debian-LTS had not shipped one at the time of writing. Debian's
security tracker now carries CVE-2026-43499 and drove these assessments;
note that the base-suite `madison` version (e.g. trixie's 6.12.86-1) lags
the `-security` upload that actually ships the fix.

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels (`proxmox-kernel-*`), so
Debian's fix status does not carry over — and as a common VM/container host,
the container-escape vector makes it worth tracking. PVE 9's default kernel
(pinned by `proxmox-default-kernel` 2.1.0) is base **7.0.14**, at or above
the 7.0.13 backport, so a default PVE 9 host is fixed. PVE 8's default
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

AL2023 (6.12 and 6.1 streams) and AL2 (5.10 / 4.14) all carry the bug.
Amazon backports selectively without always moving the base version, but as
of seed no ALAS advisory references CVE-2026-43499, so all streams are
treated as vulnerable until Amazon ships a patched kernel or advisory.

## Detection

GhostLock is architecture-independent and needs no special configuration,
so the only question is whether the running kernel is inside the affected
window and missing the fix. Compare the running kernel against the *Upstream
fixed versions* table and your distro row above:

```bash
uname -r
```

A kernel at or above its branch's first-fixed release (6.1.177 / 6.6.144 /
6.12.95 / 6.18.36 / 7.0.13), or any mainline **≥ 7.1**, carries the fix;
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

Install a kernel that carries the [`3bfdc63936dd`][fix] backport: **6.1.177**,
**6.6.144**, **6.12.95**, **6.18.36**, **7.0.13**, or mainline **≥ 7.1**.
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
  6.1.177, 6.6.144, 6.12.95, 6.18.36, 7.0.13, and mainline 7.1 — check your
  distribution row.

## Verification log

*Last verified 2026-07-09.*

### Upstream

- The fix is `3bfdc63936dd` (*rtmutex: Use waiter::task instead of current
  in remove_waiter()*), first released in **v7.1** (confirmed with
  `git describe --contains` against `~/src/linux/stable`). It makes
  `remove_waiter()` operate on `waiter->task` rather than `current`.
- The bug was introduced by `8161239a8bcc` in **v2.6.39**.
- **Stable backports landed** (confirmed by upstream-reference / subject
  grep against `~/src/linux/stable`): 6.1.177 (`4afda3a1da02`), 6.6.144
  (`6707d7e0b717`), 6.12.95 (`5799f9bd7fee`), 6.18.36 (`a388e3dfaf95`), and
  7.0.13 (`55363fa0a045`). Mainline carries it since v7.1. 5.15.y and 5.10.y
  are in-window and not yet backported.
- **CVE-2026-43499** is assigned but had **no** `vulns.git` record at seed
  (2026-07-09); the *Upstream fixed versions* table is seeded from the
  stable tree and the disclosure, to be reconciled against the `.dyad` once
  the CNA publishes it.
- Current point releases (`https://www.kernel.org/finger_banner`): mainline
  7.2-rc2; 7.1.3; 7.0.14 (EOL, fixed since 7.0.13); 6.18.38; 6.12.95;
  6.6.144; 6.1.177; 5.15.211; 5.10.260.

### Distributions

- **Debian** (via the security-tracker JSON and snapshot.debian.org
  `first_seen`): the security tracker now lists CVE-2026-43499 and resolves
  it in every suite but bullseye. sid — first fixed upload `7.0.13-1` on
  2026-06-19 (now 7.1.3-1); testing/forky — `7.0.13-1` migrated 2026-06-28;
  stable/trixie — `trixie-security 6.12.95-1` on 2026-07-05; oldstable/
  bookworm — `bookworm-security 6.1.176-1` on 2026-07-03, a backport since
  6.1.176 < upstream 6.1.177; oldoldstable/bullseye — open (5.10.y
  unbackported). The base-suite `madison` versions lag the `-security`
  uploads that ship the fix.
- **NixOS** (via the local nixpkgs clone git history): the default
  `linuxPackages` became fixed when `packageAliases.linux_default` moved to
  `linux_6_18` — 2026-06-28 on nixos-unstable, 2026-07-03 on nixos-26.05 —
  with the 6.18 series already ≥ 6.18.36 (first-fixed) from 2026-06-27. The
  prior `linux_6_12` default never reached 6.12.95 before the switch
  (6.12.95 landed 2026-07-05). Now ships 6.18.38; `linuxPackages_latest`
  (`linux_7_1`) is 7.1.3.
- **Proxmox VE** (via the `pve-kernel` `debian/changelog` and the
  `pve-no-subscription` `Packages` index): PVE 9's default kernel became
  fixed with `proxmox-kernel-7.0.14-1` (changelog 2026-07-01); the prior
  default was 7.0.12 (vulnerable) and Proxmox shipped no 7.0.13 build. The
  PVE 8 default `6.8.12` is on the EOL 6.8 line without a backport →
  vulnerable; the 6.14/6.17 opt-in series are non-LTS and unbackported.
- **Rocky / RHEL family** (via the Red Hat security data API, OSV, and
  Rocky BaseOS repodata): Red Hat lists RHEL 6/7/8/9/10 `kernel` as
  **Affected** with an empty `affected_release` (no RHSA), severity
  Important; OSV carries only the upstream kernel record (no AlmaLinux or
  Rocky advisory); and Rocky BaseOS ships `kernel-4.18.0-553.el8_10` (el8),
  `kernel-5.14.0-687.17.1.el9_8` (el9), and `kernel-6.12.0-211.28.1.el10_2`
  (el10), none carrying a fix → all vulnerable. The leading signal is the
  Red Hat CVE record gaining an `affected_release` (RHSA + fixed kernel
  NVR); Rocky then rebuilds it as an RLSA.
- **Amazon Linux**: no ALAS advisory references CVE-2026-43499 at seed.
  AL2023 (6.12 / 6.1 streams) and AL2 (5.10 / 4.14) are all in-window →
  vulnerable.

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
