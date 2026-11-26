# Scanning a fixed staging-area snapshot (`--staged`)

`detect-secrets scan --staged` and `detect-secrets-hook --staged` operate on a **fixed snapshot of
the Git index** taken when the command starts, rather than on the working tree.

This matters because the files staged for the next commit are not necessarily the files currently
on disk:

```bash
printf 'TOKEN = "%s"\n' "$FAKE_SECRET" > app.py
git add app.py
rm app.py                     # the secret is still staged and will be committed
detect-secrets-hook --staged  # blocks: the indexed blob still contains the secret
```

## What is included

Only **stage-0 regular files** (`git ls-files --stage` modes `100644` and `100755`) are scanned,
using the blob content recorded in the index:

* staged deletions disappear from the scan because the path leaves the index;
* symbolic links (`120000`) and submodule gitlinks (`160000`) are not regular files and are skipped;
* file names containing spaces or newlines are handled via NUL-separated Git output.

Unresolved merge entries (stages 1/2/3) and unreadable staged blobs are hard errors: the command
prints a message and exits non-zero instead of reporting a clean check.

## Isolation from concurrent `git add`

At launch, every staged blob is materialized once into a private temporary directory with
`git cat-file blob <sha>`. The existing scanning kernel, filters, transformers and occurrence
evidence then read ordinary files in that directory for the whole invocation. Re-running
`git add` mid-check therefore cannot splice old and new content into one result, and working-tree
edits or deletions cannot influence findings. The temporary directory is removed when the command
finishes, and neither the index nor any working-tree file is modified.

Reported paths stay repository-relative; the temporary directory never appears in output or in
baselines.

### Cost as the index grows

* **Isolation** — the total size of staged bytes is copied once, which is what guarantees the
  frozen view.
* **File count** — one temporary file (and parent directories) per staged path; the Git listing
  calls are linear in the number of index entries.
* **Total bytes** — disk and memory use grow linearly with the sum of staged blob sizes.

## `scan --staged`

```bash
# Print a fresh baseline of the staged contents to stdout (never writes a file).
detect-secrets scan --staged --no-verify > staged.baseline.json

# Occurrence-tracked baseline; evidence fingerprints the staged bytes only.
detect-secrets scan --staged --track-occurrences --no-verify > tracked.baseline.json
git add tracked.baseline.json
```

`--staged` cannot be combined with `--string`, `--only-allowlisted`, or an in-place
`--baseline` update. Positional paths and `--all-files` are ignored: the index itself defines the
file set.

## `detect-secrets-hook --staged`

The hook scans the same frozen set and keeps the usual exit codes: `1` when a new secret is found,
`0` when clean.

With `--baseline`, the baseline file is **also read from the staged snapshot**, so it must itself
be `git add`-ed. An unstaged edit to the baseline after staging cannot affect the check. In this
mode the hook only inspects: it never rewrites the baseline and never asks you to re-stage it, and
an occurrence-tracked baseline still matches because both the findings and the continuation
evidence are computed from the identical staged bytes.

```bash
git add tracked.baseline.json
detect-secrets-hook --staged --baseline tracked.baseline.json
```

Calls without `--staged` keep their original working-tree semantics unchanged.

A scripted, offline walkthrough of every scenario (index-only secret, worktree-only secret,
mid-run `git add`, newline file names, two-file baselines, occurrence evidence, and conflicts)
lives at [`scripts/demo_staged.sh`](../scripts/demo_staged.sh).
