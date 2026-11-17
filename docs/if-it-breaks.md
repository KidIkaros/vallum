# If the tunnel takes your internet away

Read this before turning a full tunnel on, and keep it somewhere you can reach
when you have no internet.

## The one command

```sh
sudo vallum-panic
```

It removes the egress block, withdraws the tunnel's default route, stops the
Vallum units, and asks the network manager for a route if none is left. It ends
by saying whether the internet is back. In the console it is the **PANIC** button
in the header, and it needs no password once the installer's sudoers rule is in
place.

If that command is not on the machine (an older install):

```sh
sudo nft delete table inet vallum_policy
sudo ip route del default dev vallum0
sudo systemctl stop 'vallum-quick@*' 'vallum-guard@*' 'vallum@*'
```

That is the whole of it. Nothing Vallum installs is irreversible.

## Why it can happen

A full tunnel (`allowed_ips = ["0.0.0.0/0"]`) moves the host's default route
into the tunnel. The egress guard (`vallum-guard@`) blocks everything that is
not the tunnel, by design, so that a dead tunnel cannot leak. If the routes
never go in — because the peer never handshook, because the server is down —
the block is still on and the host has nothing.

The product now refuses that combination three ways:

1. **`vallum-quick` will not route into a tunnel that has not handshaked.**
   It waits 45 s, then refuses and leaves the host alone.
2. **A dead-man timer** (`vallum-deadman@<iface>.timer`, every 10 s) removes the
   block when the tunnel cannot pass a packet three checks running.
3. **`scripts/trial.sh`** applies the change with a deadline armed *before* the
   change: if the host is not healthy when the clock runs out, everything is
   reverted automatically.

## Trying a full tunnel safely

```sh
sudo scripts/trial.sh --config /etc/vallum/vallum0.toml --trial 60
```

It records the current route and resolver, arms a 60-second revert, brings the
guard and routes up, then proves the host still has internet (default route,
ping, DNS). Pass it and the timer stands down; fail it and the script reverts
and tells you which check failed. `--dry-run` prints the plan and changes
nothing, and does not need root.

## Undo an install

```sh
sudo scripts/install.sh --uninstall           # keeps /etc/vallum (configs and keys)
sudo scripts/install.sh --uninstall --purge   # removes those too
```

The uninstaller stops and disables the units, removes the policy table, deletes
the files it installed (including `/usr/local/sbin/vallum-panic` and the
dead-man units), and leaves the host's routing alone.

## What to look at when it is broken

```sh
ip route show default          # is the default route still yours?
nft list table inet vallum_policy   # is the block still installed?
systemctl status 'vallum*'     # which unit is unhappy?
journalctl -u vallum@vallum0 -n 50
```

If the console cannot reach a daemon it says so; it does not pretend a tunnel is
up. The EGRESS panel states where traffic is actually leaving from, which is the
question that matters when the answer is "somewhere you did not intend".

## When you need to ask someone

```sh
sudo vallum support-bundle
```

That writes `vallum-support-<host>-<stamp>.tar.gz` in the current directory and
tells you what it put in it. It collects the four commands above (`status`,
`doctor`, `show`, `metrics`, each as JSON where it has one), the config, the
host's kernel and distribution, and the last 500 lines of the unit's journal.

It is built to be sent to someone else, so it is built not to carry secrets:

* **Private keys are never read.** `private_key = "…"` in a config is a *path*;
  the path is included, the file is not opened.
* **Preshared keys are redacted** as `preshared_key = "<redacted>"`.
* **Enrolment tickets, account numbers, and join URIs are not collected.**

`README.txt` inside the bundle lists what is in it and what was withheld, so you
can check before sending. If a check failed, its file starts with a `#` line
saying which command and how it exited — a failed check is a finding, not a
missing file.

Add `--no-journal` if you would rather not send log text at all; the rest of the
bundle is still enough to tell a platform fault from a config fault.

