#!/bin/sh
# Install the sketchy post-checkout hook into a global git template directory,
# so every future `git clone` auto-scans the new repo.
#
# Only affects future clones. Existing repos are not modified.
set -e

TEMPLATE="${SKETCHY_TEMPLATE_DIR:-$HOME/.git-template-sketchy}"
SRC="$(cd "$(dirname "$0")" && pwd)/git-template/hooks/post-checkout"

if [ ! -f "$SRC" ]; then
  echo "error: hook source not found at $SRC" >&2
  exit 1
fi

existing="$(git config --global init.templateDir || true)"
if [ -n "$existing" ] && [ "$existing" != "$TEMPLATE" ]; then
  echo "warning: init.templateDir is already set to: $existing" >&2
  echo "         refusing to overwrite. To proceed, either:" >&2
  echo "           1. copy $SRC into $existing/hooks/, or" >&2
  echo "           2. re-run with SKETCHY_TEMPLATE_DIR=$existing" >&2
  exit 1
fi

mkdir -p "$TEMPLATE/hooks"
cp "$SRC" "$TEMPLATE/hooks/post-checkout"
chmod +x "$TEMPLATE/hooks/post-checkout"
git config --global init.templateDir "$TEMPLATE"

echo "Installed. New 'git clone' invocations will auto-scan at HIGH severity."
echo "Uninstall: git config --global --unset init.templateDir"

if ! command -v sketchy >/dev/null 2>&1; then
  echo ""
  echo "⚠️  Heads up: 'sketchy' is not on your PATH. The hook will install but" >&2
  echo "   skip scanning until you put the binary somewhere on PATH, e.g.:" >&2
  echo "     sudo mv sketchy /usr/local/bin/" >&2
fi
