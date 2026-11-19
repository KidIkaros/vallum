#!/usr/bin/env bash
#
# Pull the desk's backup copies OFF the VPS onto this laptop (off-host DR).
#
# The host timer `vallum-desk-backup` writes /var/backups/vallum on the VPS;
# a copy on the same disk survives a bad migration, not a lost host. This
# script copies those backups here so a lost VPS does not lose the accounts
# (the premortem's most-likely failure). Run by a systemd user timer.
#
# Install on the operator's laptop:
#   install -m755 scripts/backup-pull.sh ~/.local/bin/vallum-backup-pull
#   # unit files: contrib/ops/vallum-backup-pull.{service,timer}
#   systemctl --user daemon-reload
#   systemctl --user enable --now vallum-backup-pull.timer
#   loginctl enable-linger "$USER"   # run even when logged out
#
# No new credentials: it rides the existing ssh alias and passwordless sudo.
set -euo pipefail

HOST="${VALLUM_BACKUP_HOST:-wingman-vps}"
DEST="${VALLUM_BACKUP_DEST:-$HOME/vallum-backups}"
KEEP="${VALLUM_BACKUP_KEEP:-30}"
SRC="${VALLUM_BACKUP_SRC:-/var/backups/vallum}"

mkdir -p "$DEST"
# tar over ssh with sudo on the far side: the backups are root-owned 0600.
# No rsync dependency; tar + ssh are universal.
ssh -o ConnectTimeout=15 "$HOST" "sudo tar -C '$SRC' -cf - ." | tar -C "$DEST" -xf -

# Retain the newest $KEEP copies (the host keeps its own rotation too).
find "$DEST" -name 'desk-*.sqlite' -printf '%T@ %p\n' \
    | sort -rn | tail -n +"$((KEEP + 1))" | cut -d' ' -f2- | xargs -r rm -f

count=$(find "$DEST" -name 'desk-*.sqlite' | wc -l)
echo "vallum-backup-pull: $count desk backup copy/copies in $DEST (off-host $HOST)"
