#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
profile=${1:-debug}
case "$profile" in
  debug) cargo_profile=dev ;;
  release) cargo_profile=release ;;
  *) printf 'usage: %s [debug|release]\n' "$0" >&2; exit 2 ;;
esac
bundle="$repo_root/target/$profile/Devclean.app"
contents="$bundle/Contents"

cargo build --manifest-path "$repo_root/Cargo.toml" --profile "$cargo_profile" \
  -p devclean -p devclean-gui --bin devclean --bin devclean-app

mkdir -p "$contents/MacOS" "$contents/Resources"
cp "$repo_root/target/$profile/devclean" "$contents/MacOS/devclean"
cp "$repo_root/target/$profile/devclean-app" "$contents/MacOS/devclean-app"
cp "$repo_root/crates/devclean-gui/macos/Info.plist" "$contents/Info.plist"
chmod 755 "$contents/MacOS/devclean" "$contents/MacOS/devclean-app"

printf '%s\n' "$bundle"
