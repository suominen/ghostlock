---
title: "GhostLock — rtmutex/futex stack use-after-free"
description: "Linux kernel rtmutex/futex requeue-PI stack use-after-free (CVE-2026-43499, GhostLock) — local privilege escalation & container escape — distro patch status tracker"
layout: "single"
date: 2026-07-09
lastmod: 2026-07-31
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
{.summary}

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

## Patch status

The deciding fact per row is whether the **kernel** carries the
[`3bfdc63936dd`][fix] backport. Because the bug dates to v2.6.39,
**every** kernel below is inside the affected window — there are no
"predates the bug" rows here — and the trigger needs no privilege or
special configuration, so the kernel version is the whole story: a row
is `:x:` until its kernel ships the fix.

The first group tracks the upstream kernel itself; the rest are a
focused set of general-purpose and container-host distributions.
*Current kernel* is the latest version observed in the row's
user-facing channel; *First fixed* is the first release or build
carrying the fix, and *Fixed since* the date it first held (both stay
`—` while a row is vulnerable).

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.2-rc5 | 7.1 | 2026-06-14 | :white_check_mark: Fixed — carries `3bfdc63936dd` |
| Linux kernel | 7.1.x | 7.1.5 | 7.1 | 2026-06-14 | :white_check_mark: Fixed — at the initial release |
| Linux kernel | 7.0.x | 7.0.14 | 7.0.4 | 2026-05-07 | :white_check_mark: Fixed — EOL |
| Linux kernel | 6.18.x | 6.18.41 | 6.18.27 | 2026-05-07 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.100 | 6.12.86 | 2026-05-07 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.147 | 6.6.140 | 2026-05-17 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.180 | 6.1.175 | 2026-06-01 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.212 | 5.15.212 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.261 | 5.10.261 | 2026-07-24 | :white_check_mark: Fixed — LTS |
| Debian | sid (unstable) | 7.1.5-1 | 7.0.4-1 | 2026-05-08 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.3-1 | 7.0.4-1 | 2026-05-10 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.96-1 | 6.12.86-1 | 2026-05-08 | :white_check_mark: Fixed |
| Debian | 12 (bookworm) | 6.1.177-1 | 6.1.176-1 | 2026-07-03 | :white_check_mark: Fixed — DLA-4665-1 |
| Debian | 11 (bullseye, LTS) | 5.10.259-1 | — | — | :x: Vulnerable |
| Debian | 11 (linux-6.1 opt-in) | 6.1.177-1~deb11u1 | 6.1.176-1~deb11u1 | 2026-07-04 | :white_check_mark: Fixed — DLA-4671-1 |
| Proxmox VE | 9 (default) | 7.0.14-8-pve | 7.0.14-1-pve | 2026-07-01 | :white_check_mark: Fixed — base ≥ the 7.0.4 backport |
| Proxmox VE | 9 (6.17 old) | 6.17.13-21-pve | 6.17.13-16-pve | 2026-07-09 | :white_check_mark: Fixed — cherry-picked from `linux-6.18.y` |
| Proxmox VE | 9 (6.14 old) | 6.14.11-9-pve | — | — | :x: Vulnerable — no cherry-pick |
| Proxmox VE | 8 (default) | 6.8.12-39-pve | — | — | :x: Vulnerable — 6.8.y EOL, no backport |
| Proxmox VE | 8 (6.14 opt-in) | 6.14.11-9-bpo12-pve | — | — | :x: Vulnerable — no cherry-pick |
| Proxmox VE | 8 (6.11 old) | 6.11.11-2-pve | — | — | :x: Vulnerable — no cherry-pick |
| NixOS | Unstable | 6.18.40 | 6.18.36 | 2026-06-28 | :white_check_mark: Fixed — default moved to `linux_6_18` |
| NixOS | 26.05 | 6.18.40 | 6.18.36 | 2026-07-03 | :white_check_mark: Fixed — default moved to `linux_6_18` |
| Rocky Linux | 10 | 6.12.0-211.40.1.el10_2 | 6.12.0-211.33.1.el10_2 | 2026-07-15 | :white_check_mark: Fixed — RLSA-2026:38492 |
| Rocky Linux | 9 | 5.14.0-687.31.1.el9_8 | 5.14.0-687.25.1.el9_8 | 2026-07-15 | :white_check_mark: Fixed — RLSA-2026:38491 |
| Rocky Linux | 8 | 4.18.0-553.148.1.el8_10 | 4.18.0-553.144.1.el8_10 | 2026-07-15 | :white_check_mark: Fixed — RLSA-2026:39179 |
| Amazon Linux | 2023 (default) | 6.1.176-223.369 | 6.1.175-219.357 | 2026-06-22 | :white_check_mark: Fixed — ALAS2023-2026-1882 |
| Amazon Linux | 2023 (kernel6.12) | 6.12.94-123.192 | 6.12.88-119.157 | 2026-05-25 | :white_check_mark: Fixed — ALAS2023-2026-1753 |
| Amazon Linux | 2023 (kernel6.18) | 6.18.38-76.139 | 6.18.30-61.116 | 2026-05-25 | :white_check_mark: Fixed — ALAS2023-2026-1754 |
{.distros}

### Linux kernel

The fix reached Linus as **v7.1** and the stable maintainers backported
it across every maintained line. 7.0.y took the backport in 7.0.4, well
before that line reached end of life at 7.0.14. The pre-6.1 longterm
lines (5.15.y, 5.10.y) received the backport on 2026-07-24.

When verifying a tree directly, the fixed function is `remove_waiter()`
in `kernel/locking/rtmutex.c`; the fix replaces the use of `current` /
`current->pi_lock` with the waiter's own `waiter->task`.

### Debian

Debian's `linux` is affected in every suite (the bug predates all of
them); the security tracker's CVE-2026-43499 record drove these
assessments, and it keeps bullseye's default `src:linux` open. A stock
**bullseye** (LTS) system stays exposed: the fixed `linux-6.1` package
— the bookworm 6.1 kernel rebuilt for bullseye, shipped via
`bullseye-security` — is a separate opt-in source package that an
ordinary upgrade does not install, so the admin must switch to it
explicitly.

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels (`proxmox-kernel-*`), so
Debian's fix status does not carry over — and as a common VM/container
host, the container-escape vector makes it worth tracking. Each PVE
release's default kernel series (pinned by `proxmox-default-kernel`)
and its opt-in series get their own rows above; the current defaults
are the 7.0 series on PVE 9 and 6.8 on PVE 8. Whether a series
carries the fix tracks Proxmox's kernel changelog, not Debian's: the
6.17 fix is Proxmox's own cherry-pick of the three patches from
`linux-6.18.y`, made on 2026-07-09.

An *opt-in* series is Proxmox's preview of a likely next default,
aimed at setups that need newer hardware support; an *old* series is
one the release has moved past — a superseded default (PVE 9's 6.17
and 6.14) or an opt-in overtaken by a newer one (PVE 8's 6.11).
Proxmox discontinues updates for superseded series once a short
transition tail ends (the 6.17 cherry-pick above landed inside that
tail), and every such PVE kernel series is long end-of-life on
kernel.org, so a fix can only ever arrive as a Proxmox cherry-pick. A
vulnerable *old* row is therefore unlikely ever to flip — the exit is
rebooting into the release's current default kernel.

### Rocky Linux / RHEL family

RHEL-family kernels carry security backports without moving their
upstream base version, so the version string alone cannot confirm a
fix — the signal is an erratum. The table rows track the standard
`kernel`; the niche real-time `kernel-rt` variant is covered only
here. RHEL is upstream of the rebuilds, and the fix flowed RHEL →
AlmaLinux → Rocky:

- **Standard `kernel`, EL10 / EL9** — Red Hat shipped
  **RHSA-2026:38492** (RHEL 10.2, kernel `6.12.0-211.33.1.el10_2`) and
  **RHSA-2026:38491** (RHEL 9, kernel `5.14.0-687.25.1.el9_8`) on
  2026-07-13; AlmaLinux rebuilt both as **ALSA-2026:38492** /
  **ALSA-2026:38491**, and Rocky shipped the matching RLSAs in the
  table above.
- **Standard `kernel`, EL8** — Red Hat shipped **RHSA-2026:39083**
  (kernel `4.18.0-553.143.1.el8_10`); AlmaLinux rebuilt it as
  **ALSA-2026:39083**. Rocky 8 skipped that NVR — rather than
  publishing a standalone rebuild of `553.143.1`, it shipped the
  cumulative `4.18.0-553.144.1.el8_10` as **RLSA-2026:39179**.
- **`kernel-rt`, EL9 GA — still vulnerable** — Red Hat shipped
  **RHSA-2026:39983** (`kernel-rt 5.14.0-284.181.1.rt14.466.el9_2`)
  for the RHEL 9.2 E4S path only; there is no advisory for the GA
  stream and no RLSA rebuild in Rocky's NFV repo, and Red Hat's
  `kernel-rt` package state remains **Affected** for RHEL 9 GA.
- **`kernel-rt`, EL8** — Red Hat shipped **RHSA-2026:39082**
  (`kernel-rt 4.18.0-553.143.1.rt7.484.el8_10`) on 2026-07-14; Rocky
  8's RT repo carries the cumulative
  `4.18.0-553.144.1.rt7.485.el8_10`, which supersedes the RHEL fixed
  NVR.

The standard `kernel` is thus fixed for RHEL 10, RHEL 9, Oracle Linux,
CloudLinux OS, and Rocky 8; the EL9 GA `kernel-rt` stream is the one
still waiting.

### Amazon Linux

Each **AL2023** kernel stream is its own row above; status is verified
from the repodata `updateinfo.xml` (the per-CVE ALAS pages are
JS-rendered and don't fetch headlessly). The *default* row is the plain
`kernel` package (a 6.1-series stream); `kernel6.12` and `kernel6.18`
are the opt-in streams.

**AL2** (amzn2) is not tracked here: it reached end of support on
**2026-06-30** — before this tracker existed — with no ALAS ever issued
for this CVE, and AWS no longer provides security updates or bug fixes
for AL2 core packages. All three of its kernel streams (4.14, plus
5.10 / 5.15 via `amazon-linux-extras`) are in-window and permanently
vulnerable, and no fix is expected. The exit is migrating to AL2023 (or
another patched distribution).

## Detection

GhostLock is architecture-independent and needs no special configuration,
so the only question is whether the running kernel is inside the affected
window and missing the fix. Compare the running kernel against the *Patch
status* table above — the *Linux kernel* rows for the upstream point
releases, and your distribution's row:

```bash
uname -r
```

Any mainline kernel **≥ 7.1**, or one at or above its branch's first-fixed
release (7.0.4 / 6.18.27 / 6.12.86 / 6.6.140 / 6.1.175 / 5.15.212 /
5.10.261), carries the fix; anything else in the 2.6.39–7.0 window
without a distro backport is vulnerable. On RHEL-family and Amazon kernels the base version does not map
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

Install a kernel that carries the [`3bfdc63936dd`][fix] backport: mainline
**≥ 7.1**, or **7.0.4**, **6.18.27**, **6.12.86**, **6.6.140**, **6.1.175**,
**5.15.212**, **5.10.261**.

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
  every unpatched production kernel is affected. The fix is in mainline
  7.1 and backported to 7.0.4, 6.18.27, 6.12.86, 6.6.140, 6.1.175,
  5.15.212, and 5.10.261 — check your distribution row.

## Verification log

Every verdict in the table above is backed by a checkable source. This
log records the provenance — the advisory, repository index, or git
reference that established each fact — so any row can be audited or
reproduced. Most readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- The fix is `3bfdc63936dd` (*rtmutex: Use waiter::task instead of current
  in remove_waiter()*), first released in **v7.1** (confirmed with
  `git describe --contains` against `~/src/linux/stable`). It makes
  `remove_waiter()` operate on `waiter->task` rather than `current`.
- The bug was introduced by `8161239a8bcc` in **v2.6.39**.
- **`vulns.git` record** (appeared after seed; inspected via
  `origin/master`; confirmed via subject/ref grep and
  `git describe --contains`):
  - The `.dyad` gives authoritative per-branch first-fixed commits,
    earlier than the seed had recorded — the seed grep
    (`--grep=3bfdc63936dd --grep='waiter::task'`) matched a follow-up
    fix (`4afda3a1da02` et al., upstream `40a25d59e85b`) that cites the
    original fix in its commit body, not the backport of the original
    fix itself.
  - Corrected first-fixed commits: 7.0.4 (`88614876370a`), 6.18.27
    (`3fb7394a8377`), 6.12.86 (`6d52dfcb2a5d`), 6.6.140
    (`8a1fc8d698ac`), 6.1.175 (`d8cce4773c2b`). Mainline carries the
    fix since v7.1.
  - **5.15.y first fixed in 5.15.212** (backport `838ce5cb5d93`) and
    **5.10.y in 5.10.261** (`f3fa3424bceb`), both tagged 2026-07-24;
    the CNA record now covers them alongside 6.1–7.1.
- **NVD CVSS score published**: CVSS 7.8 HIGH
  (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), confirming Red Hat's
  Important severity rating (via NVD REST API).
- Current point releases (`https://www.kernel.org/finger_banner`): mainline
  7.2-rc5; 7.1.5; 7.0.14 (EOL, fixed since 7.0.4); 6.18.41; 6.12.100;
  6.6.147; 6.1.180; 5.15.212; 5.10.261.

#### Distributions

- **Debian** (via the security-tracker JSON, tracker.debian.org migration
  news, and snapshot.debian.org `first_seen`):
  - sid — first fixed upload `7.0.4-1` on 2026-05-08; now 7.1.5-1.
  - testing/forky — `7.0.4-1` migrated 2026-05-10; now 7.1.3-1.
  - stable/trixie — base suite `6.12.86-1` on 2026-05-08; now 6.12.94-1
    in trixie, 6.12.96-1 in trixie-security.
  - oldstable/bookworm — `bookworm-security 6.1.176-1` (DLA-4665-1) on
    2026-07-03; now 6.1.177-1 in bookworm-security; 6.1.176 is above
    upstream first-fixed 6.1.175.
  - LTS/bullseye — the tracker keeps `src:linux` (5.10.y) **open**, so
    the default row stays `:x:`; the opt-in `linux-6.1` package
    (bookworm's 6.1 kernel rebuilt for bullseye) first resolved at
    `6.1.176-1~deb11u1` (DLA-4671-1, 2026-07-04); now
    `6.1.177-1~deb11u1` — its own row.
  - Seed correction — trixie's first-fixed was recorded wrong at seed
    (6.12.95-1 / 2026-07-05; actual 6.12.86-1 / 2026-05-08) because the
    upstream first-fixed series was also wrong at seed.
- **NixOS** (via the local nixpkgs clone):
  - `packageAliases.linux_default` is `linux_6_18` on both
    nixos-unstable and nixos-26.05; nixos-unstable ships 6.18.40,
    nixos-26.05 ships 6.18.40 — both fixed.
  - `linuxPackages_latest` (`linux_7_1`) is 7.1.5.
- **Proxmox VE** (via pve-no-subscription `Packages` index and pve-kernel
  `debian/changelog`):
  - PVE 9 default — `proxmox-default-kernel 2.1.0` depends on
    `proxmox-kernel-7.0`; highest available `7.0.14-8-pve` — fixed.
  - PVE 9 old 6.17 — cherry-pick confirmed; highest
    `6.17.13-21-pve` — fixed.
  - PVE 9 old 6.14 — highest `6.14.11-9-pve`, no cherry-pick —
    vulnerable.
  - PVE 8 default — `proxmox-default-kernel 1.1.0` →
    `proxmox-kernel-6.8`; highest available `6.8.12-39-pve` — vulnerable.
  - PVE 8 opt-in 6.14 — highest `6.14.11-9-bpo12-pve`, no
    cherry-pick — vulnerable.
  - PVE 8 old 6.11 — highest `6.11.11-2-pve`, no cherry-pick —
    vulnerable.
  - Series lifecycle (via the Proxmox forum opt-in kernel
    announcements): an opt-in kernel previews the next default, a
    superseded series stops receiving updates barring serious issues,
    and every such series is EOL on kernel.org — the basis of the
    *old* labels and the "unlikely ever to flip" caveat.
- **Rocky / RHEL family** (via the Red Hat security data API, AlmaLinux
  errata, and Rocky BaseOS repodata):
  - EL10 / EL9 standard `kernel` — **RHSA-2026:38492** (RHEL 10.2,
    `6.12.0-211.33.1.el10_2`) and **RHSA-2026:38491** (RHEL 9,
    `5.14.0-687.25.1.el9_8`) shipped 2026-07-13; AlmaLinux rebuilt both
    (ALSA-2026:38492 / ALSA-2026:38491); Rocky 10 and Rocky 9 carry the
    fixed NVRs in BaseOS, RLSA-2026:38492 / RLSA-2026:38491 confirmed
    in updateinfo; current Rocky 10 kernel `6.12.0-211.40.1.el10_2`
    (in primary.xml); current Rocky 9 kernel `5.14.0-687.31.1.el9_8`
    (in primary.xml; post-38491 updates via RLSA-2026:43307 and subsequent
    builds).
  - EL8 standard `kernel` — **RHSA-2026:39083**
    (`4.18.0-553.143.1.el8_10`); AlmaLinux rebuilt it as
    **ALSA-2026:39083**. Rocky 8 skipped `.143.1` and shipped
    `4.18.0-553.144.1.el8_10` as RLSA-2026:39179 (2026-07-15) — above
    the RHEL fixed NVR, carrying the fix cumulatively; current Rocky 8
    kernel `4.18.0-553.148.1.el8_10` (confirmed via BaseOS repodata).
  - `kernel-rt`, EL9 GA — **RHSA-2026:39983**
    (`kernel-rt 5.14.0-284.181.1.rt14.466.el9_2`) shipped for the RHEL
    9.2 E4S path only; Rocky's NFV repo carries `5.14.0-687.12.1.el9_8`
    for the GA stream with no RLSA for this advisory. RHEL 9 GA
    `kernel-rt` still shows `fix_state: Affected`; `kernel-rt` on
    RHEL 9 / Rocky 9 GA remains vulnerable.
  - `kernel-rt`, EL8 — **RHSA-2026:39082**
    (`kernel-rt 4.18.0-553.143.1.rt7.484.el8_10`) shipped 2026-07-14;
    Rocky 8's RT repo carries `4.18.0-553.144.1.rt7.485.el8_10`, which
    supersedes the fixed NVR and carries the fix cumulatively (no RLSA
    listing the CVE — same pattern as the standard kernel).
  - Additional RHEL advisories not tracked in the table (Rocky has no
    EUS, ELS, or NV rows): **RHSA-2026:37728** (RHEL 10 NV,
    `kernel 6.12.0-231.16.el10nv`), **RHSA-2026:41062** (RHEL 10.0
    EUS, `kernel 6.12.0-55.89.1.el10_0`), **RHSA-2026:40425** (RHEL
    9.6 EUS, `kernel 5.14.0-570.128.1.el9_6`), **RHSA-2026:41063**
    (RHEL 9.4 E4S, `kernel 5.14.0-427.138.1.el9_4`),
    **RHSA-2026:40082** (RHEL 9.2 E4S, `kernel 5.14.0-284.181.1.el9_2`),
    **RHSA-2026:40760** (RHEL 8.8 TUS/E4S,
    `kernel 4.18.0-477.152.1.el8_8`), **RHSA-2026:40068** (RHEL 8.6
    AUS/EUS, `kernel 4.18.0-372.201.1.el8_6`), **RHSA-2026:39984**
    (RHEL 8.4 AUS/EUS, `kernel 4.18.0-305.198.1.el8_4`),
    **RHSA-2026:41235** (RHEL 7 ELS, `kernel 3.10.0-1160.156.1.el7`),
    **RHSA-2026:41234** (RHEL 7 ELS,
    `kernel-rt 3.10.0-1160.156.1.rt56.1308.el7`), **RHSA-2026:41920**
    (RHEL 6 ELS, `kernel 2.6.32-754.62.1.el6`).
- **Amazon Linux** (via the repodata `updateinfo.xml`):
  - AL2023 default `kernel` (6.1) — ALAS2023-2026-1882; current
    `6.1.176-223.369` — fixed.
  - AL2023 `kernel6.12` — ALAS2023-2026-1753; current
    `6.12.94-123.192` — fixed.
  - AL2023 `kernel6.18` — ALAS2023-2026-1754; current
    `6.18.38-76.139` — fixed.
  - AL2 — never received an ALAS for CVE-2026-43499 and reached end of
    support on 2026-06-30 (per the AWS AL2 FAQ; confirmed against
    endoflife.date) — AWS no longer ships security updates for AL2
    core packages, so the 4.14 / 5.10 / 5.15 streams remain vulnerable
    with no fix expected.
{{< /details >}}

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
