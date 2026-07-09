# GhostLock — Linux kernel rtmutex/futex stack-UAF tracking site

Patch-status tracker for **GhostLock** (**CVE-2026-43499**), a stack
use-after-free in the Linux kernel's real-time mutex (rtmutex)
priority-inheritance code, reached through the futex requeue-PI path.
`remove_waiter()` in `kernel/locking/rtmutex.c` clears `pi_blocked_on` on
`current` instead of on the waiter's own task; when the requeue-PI rollback
runs it on behalf of a *different* task, it leaves a dangling pointer into
freed kernel-stack memory — a use-after-free the PoC turns into a
near-arbitrary write, local root, and container escape.  The trigger is
ordinary `futex(2)`, so any unprivileged local user (or unprivileged
container process) can reach it.  Discovered by **Nebula Security** with
their VEGA tool and [disclosed on 2026-07-07](https://nebusec.ai/research/ionstack-part-2/).
Public PoC: <https://github.com/NebuSec/CyberMeowfia>.

The bug was introduced by `8161239a8bcc` in **v2.6.39** (2011) and fixed in
**v7.1** by
[`3bfdc63936dd`](https://github.com/torvalds/linux/commit/3bfdc63936dd4773109b7b8c280c0f3b5ae7d349)
(*rtmutex: Use waiter::task instead of current in remove_waiter()*).
Because it dates to 2.6.39, the practical exploitable window is **every
kernel from 2.6.39 through 7.0**; distro adoption of the backport is tracked
below.

**CVE-2026-43499** is assigned; the stable maintainers backported the fix to
6.1.177, 6.6.144, 6.12.95, 6.18.36, and 7.0.13, but each distribution has to
pick it up.  GhostLock is **architecture-independent** (generic locking
code) and has **no companion tracker**.

The rendered site is published at **<https://kimmo.cloud/ghostlock/>**.
Deployment plan and current setup state live in
[`WEBSITE.md`](WEBSITE.md).

## Source of truth

The tracker is a single Hugo page: [`site/content/_index.md`](site/content/_index.md).
Edit that file; everything else is build infrastructure.

## Local development

Requires Hugo extended (≥ 0.146.0) and Go (for Hugo Modules to fetch the
PaperMod theme).

### With Nix (recommended)

```sh
nix develop          # dev shell: hugo, go, git, resvg
cd site
hugo server          # local preview at http://localhost:1313/ghostlock/
```

If you use [direnv](https://direnv.net/), `direnv allow` once and the dev
shell auto-activates whenever you `cd` into the repo.

### Without Nix

Install Hugo extended ≥ 0.146.0 and Go ≥ 1.24 yourself, then:

```sh
cd site
hugo server          # http://localhost:1313/ghostlock/
```

## Build and publish

```sh
make build       # local build into site/public/
make dist        # build, then rsync to haig:/ghostlock/
make banner      # re-rasterise the social banner SVG → PNG (needs resvg + Roboto)
```

`make dist` runs `make build` first.  `make banner` is only needed after
editing `site/assets/ghostlock-tracker.svg`; the rendered PNG is committed.

## Repo layout

```
.
├── flake.nix              # Nix dev environment (hugo, go, git, resvg + RPM tools)
├── .envrc                 # direnv hook → `use flake`
├── .gitignore
├── Makefile               # `make build`, `make dist`, `make banner`
├── LICENSE                # CC BY 4.0
├── README.md              # this file
├── CLAUDE.md              # project instructions for Claude Code
├── WEBSITE.md             # publication plan / decisions log
├── scripts/               # auto-update agent: prompt + driver
├── systemd/               # user-level timer + service units
└── site/                  # Hugo project
    ├── hugo.toml
    ├── content/
    │   └── _index.md      # the tracker (single page)
    ├── assets/css/extended/custom.css   # PaperMod CSS overrides
    ├── assets/ghostlock-tracker.svg     # social-banner source (→ make banner)
    ├── static/ghostlock-tracker.png     # rendered OpenGraph banner (committed)
    ├── layouts/partials/  # PaperMod overrides (post_meta, extend_footer)
    ├── go.mod, go.sum     # Hugo Modules — pulls PaperMod theme
    └── …                  # standard Hugo skeleton
```

## License

[CC BY 4.0](LICENSE) — share and adapt with attribution.
