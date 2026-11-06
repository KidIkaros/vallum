#!/usr/bin/env bash
# Stages the static site into site/dist: the pages, plus the one image they
# reference, which lives in assets/ because the README and the release media use
# it too. A host has to serve this directory as its root; deploying site/ on its
# own leaves the screenshot 404, which is why the link check runs before the
# script reports success.
#
# Not in dist/: scripts/release.sh owns that path and removes it wholesale.
set -euo pipefail
cd "$(dirname "$0")/.."

out=site/dist
rm -rf "$out"
mkdir -p "$out/assets"
cp -R site/index.html site/docs site/style.css "$out"/
cp assets/vallum-cockpit.png "$out/assets/"

# Every relative href/src must resolve inside the staged tree. Absolute URLs are
# left alone: they point at the repository, not at the site.
missing=0
while IFS= read -r -d '' page; do
    while IFS= read -r ref; do
        case "$ref" in
            http://* | https://* | \#* | mailto:*) continue ;;
        esac
        ref=${ref%%#*}
        if [ ! -e "$(dirname "$page")/$ref" ]; then
            printf 'missing reference: %s -> %s\n' "$page" "$ref" >&2
            missing=1
        fi
    done < <(grep -oE '(href|src)="[^"]+"' "$page" | sed -E 's/^[a-z]+="//; s/"$//')
done < <(find "$out" -name '*.html' -print0)

if [ "$missing" -ne 0 ]; then
    printf 'stage-site: broken references, refusing to stage\n' >&2
    exit 1
fi

printf 'staged %s files into %s\n' "$(find "$out" -type f | wc -l)" "$out"
(cd "$out" && find . -type f | sort)
