#!/usr/bin/env bash
#
# Reproducible, fully offline demo for `scan --staged` / `detect-secrets-hook --staged`.
#
# It builds throwaway Git repositories under a temp directory and uses hand-crafted
# fake secrets.  All plugins used here perform offline checks; no network access is
# required once detect-secrets and its Python dependencies are installed.
#
# Usage:
#   ./scripts/demo_staged.sh [python-interpreter]
#
# Example:
#   ./scripts/demo_staged.sh /workspace/.venv/bin/python
set -u

PYTHON="${1:-python3}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/detect-secrets-staged-demo.XXXXXX")"
GIBBERISH='detect_secrets.filters.gibberish.should_exclude_secret'

# Hand-crafted, high-entropy fake secrets (not real credentials).
SECRET_ONE='c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'
SECRET_TWO='ZjZDR1Y0YU1MOVplZG9oM09VTmJTYWtCeW1vN3lwbEI='

trap 'rm -rf "$WORK"' EXIT

banner() {
    printf '\n\033[1;36m== %s ==\033[0m\n' "$1"
}

new_repo() {
    local dir="$WORK/$1"
    mkdir -p "$dir"
    git -C "$dir" init -q
    git -C "$dir" config user.email demo@example.com
    git -C "$dir" config user.name 'Staged Demo'
    printf '%s' "$dir"
}

scan() { ( cd "$1" && "$PYTHON" -m detect_secrets scan --no-verify --disable-filter "$GIBBERISH" "${@:2}"; ) }
hook() { ( cd "$1" && "$PYTHON" -m detect_secrets.pre_commit_hook --no-verify --disable-filter "$GIBBERISH" "${@:2}"; ) }

# ---------------------------------------------------------------------------
banner '1. Secret only in the index (working-tree copy deleted) is still found'
repo="$(new_repo 01-index-only)"
printf 'CONFIG_VALUE = "%s"\n' "$SECRET_ONE" > "$repo/app.py"
git -C "$repo" add app.py
rm "$repo/app.py"
scan "$repo" --staged | python3 -c 'import json,sys; print("found:", list(json.load(sys.stdin)["results"]))'

# ---------------------------------------------------------------------------
banner '2. Secret only in the working tree is never reported'
repo="$(new_repo 02-worktree-only)"
printf 'safe = "ordinary code"\n' > "$repo/clean.py"
git -C "$repo" add clean.py
printf 'CONFIG_VALUE = "%s"\n' "$SECRET_TWO" > "$repo/dirty.py"   # never staged
scan "$repo" --staged | python3 -c 'import json,sys; print("found:", list(json.load(sys.stdin)["results"]))'
hook "$repo" --staged; echo "hook exit (expect 0): $?"

# ---------------------------------------------------------------------------
banner '3. git add during the check cannot mix old and new content'
repo="$(new_repo 03-mid-run-add)"
printf 'CONFIG_VALUE = "%s"\n' "$SECRET_ONE" > "$repo/app.py"
git -C "$repo" add app.py
# Start the hook, then re-stage clean content while it is running.
hook "$repo" --staged --json > "$WORK/3.json" 2>/dev/null &
hook_pid=$!
sleep 0.5
printf 'CONFIG_VALUE = "ordinary replacement value"\n' > "$repo/app.py"
git -C "$repo" add app.py
wait "$hook_pid"; echo "hook exit while re-adding (expect 1): $?"
python3 -c 'import json; print("frozen result saw:", list(json.load(open("'$WORK'/3.json"))["results"]))'
hook "$repo" --staged; echo "fresh hook exit against new index (expect 0): $?"

# ---------------------------------------------------------------------------
banner '4. File name containing a newline and spaces'
repo="$(new_repo 04-newline-name)"
printf 'CONFIG_VALUE = "%s"\n' "$SECRET_ONE" > "$(printf '%s/weird\nname with spaces.py' "$repo")"
git -C "$repo" add -- "$(printf 'weird\nname with spaces.py')"
scan "$repo" --staged | python3 -c 'import json,sys; print("found:", {repr(k): v[0]["line_number"] for k,v in json.load(sys.stdin)["results"].items()})'

# Symlinks and submodules are not treated as regular files.
printf 'TARGET_VALUE = "%s"\n' "$SECRET_ONE" > "$repo/target.py"
ln -s target.py "$repo/link.py"
git -C "$repo" add target.py link.py
scan "$repo" --staged | python3 -c 'import json,sys; r=json.load(sys.stdin)["results"]; assert "link.py" not in r; print("symlink excluded; files:", sorted(r))'

# ---------------------------------------------------------------------------
banner '5. Two files with different contents; baseline generated and consumed'
repo="$(new_repo 05-two-files)"
printf 'A = "%s"\n' "$SECRET_ONE" > "$repo/a.py"
printf 'B = "%s"\n' "$SECRET_TWO" > "$repo/b.py"
git -C "$repo" add a.py b.py
scan "$repo" --staged > "$repo/baseline.json"
git -C "$repo" add baseline.json
hook "$repo" --staged --baseline baseline.json; echo "hook exit with matching baseline (expect 0): $?"

# Tamper with the on-disk baseline after staging: the hook reads the staged blob.
printf '{"tampered": true}\n' > "$repo/baseline.json"
hook "$repo" --staged --baseline baseline.json; echo "hook exit using staged baseline (expect 0): $?"

# ---------------------------------------------------------------------------
banner '6. Occurrence evidence: tracked baseline matches on identical content'
repo="$(new_repo 06-occurrence-evidence)"
cat > "$repo/config.py" <<EOF
# header
CONFIG_VALUE = "$SECRET_ONE"
BACKUP_VALUE = "$SECRET_ONE"
# footer
EOF
git -C "$repo" add config.py
scan "$repo" --staged --track-occurrences > "$repo/tracked.json"
python3 -c '
import json
d = json.load(open("'$repo'/tracked.json"))
assert "$SECRET_ONE" not in open("'$repo'/tracked.json").read()
assert "detect-secrets-staged" not in open("'$repo'/tracked.json").read()
entries = d["results"]["config.py"]
print("marker:", d["occurrence_tracking"]["scheme"])
print("lines:", sorted({e["line_number"] for e in entries}))
print("evidence available:", all(e["occurrence"]["evidence"]["available"] for e in entries))
'
git -C "$repo" add tracked.json
hook "$repo" --staged --baseline tracked.json; echo "tracked hook exit on identical snapshot (expect 0): $?"

# A new, separately located copy must be flagged even though type/hash match.
cat >> "$repo/config.py" <<EOF
# separate context alpha
IMPORTED_VALUE = "$SECRET_ONE"
# separate context omega
EOF
git -C "$repo" add config.py
hook "$repo" --staged --json --baseline tracked.json > "$WORK/6.json"
echo "tracked hook exit with new occurrence (expect 1): $?"
python3 -c 'import json; print("new occurrences:", [(e["line_number"], e["occurrence"]["continuity"]) for e in json.load(open("'$WORK'/6.json"))["results"]["config.py"]])'

# ---------------------------------------------------------------------------
banner '7. Unmerged conflicts error out with a non-zero status (never "clean")'
repo="$(new_repo 07-conflict)"
printf 'one\n' > "$repo/f.txt"
git -C "$repo" add f.txt
git -C "$repo" commit -qm base
git -C "$repo" checkout -qb side
printf 'side\n' > "$repo/f.txt"
git -C "$repo" add f.txt
git -C "$repo" commit -qm side
git -C "$repo" checkout -q master
printf 'main\n' > "$repo/f.txt"
git -C "$repo" add f.txt
git -C "$repo" commit -qm main2
git -C "$repo" merge side -q --no-edit || true
scan "$repo" --staged; echo "scan exit on conflict (expect non-zero): $?"
hook "$repo" --staged; echo "hook exit on conflict (expect non-zero): $?"

printf '\nDemo repositories were kept under: %s (removed on exit)\n' "$WORK"
