# Occurrence-tracked baselines

Occurrence tracking is an opt-in baseline format for keeping separate audit state for separate
copies of the same secret in the same file.

It does **not** migrate legacy baselines, track file renames, or correlate occurrences across
different files. Baselines without the `occurrence_tracking` marker keep the historical
filename/type/hash identity and behavior.

## Create, audit, update, and hook

The following walkthrough uses a temporary Git repository and deliberately fake secrets.
`--no-verify` disables provider verification/network calls. The gibberish filter is disabled only
because the example value is readable; omit that option when using a high-entropy fake token or in
a normal installation where the optional gibberish package is absent.

```bash
tmpdir="$(mktemp -d)"
cd "$tmpdir"
git init -q
git config user.email test@example.com
git config user.name Test User

cat > settings.py <<'PY'
# demo service
SERVICE_NAME = "billing"
PASSWORD = "fake-occurrence-demo-secret-0001"
PASSWORD_BACKUP = "fake-occurrence-demo-secret-0001"
# trailing context one
# trailing context two
PY

# 1. Create the occurrence-tracked baseline.
detect-secrets scan \
  --track-occurrences \
  --no-verify \
  --disable-filter detect_secrets.filters.gibberish.should_exclude_secret \
  --all-files settings.py \
  > .occurrence-baseline.json

# The two equal-valued hits are two result entries with different occurrence ids.
python -m json.tool .occurrence-baseline.json | less

# 2. Audit interactively. Press "y" for a false positive, "n" for a real secret,
#    then "q" to save and quit. Only the selected occurrence is changed.
detect-secrets audit .occurrence-baseline.json

# 3. Re-scan and merge judgements into the same baseline file.
detect-secrets scan \
  --baseline .occurrence-baseline.json \
  --no-verify \
  --disable-filter detect_secrets.filters.gibberish.should_exclude_secret \
  --all-files settings.py

# 4. The hook uses the same occurrence matcher.
detect-secrets-hook \
  --baseline .occurrence-baseline.json \
  --no-verify \
  --disable-filter detect_secrets.filters.gibberish.should_exclude_secret \
  settings.py
```

If an unrelated block is inserted above the findings, the local content fingerprints still match
and the existing occurrence ids and judgements move to the new line numbers.

If another copy of the same value is added, run the hook **before** updating the baseline. It exits
non-zero and reports only the unmatched copy, even though its filename, type, and secret hash match
an older baseline entry. After review, explicitly catalog it with the same
`detect-secrets scan --baseline .occurrence-baseline.json ...` command.

The hook can exit with status `3` after automatically refreshing line numbers in the baseline.
That is the existing hook convention; `git add` the baseline and run the hook again.

## Identity and continuation evidence

Every result gets a random stable label:

```json
{
  "occurrence": {
    "id": "occ_...",
    "scheme": "position-v1",
    "continuity": "tracked",
    "evidence": {
      "file_fingerprint": "...",
      "line_fingerprint": "...",
      "anchors": [
        {"offset": -1, "fingerprint": "..."},
        {"offset": 1, "fingerprint": "..."}
      ]
    }
  }
}
```

The random `id` is only a label for the reviewed baseline row. It is not treated as proof that a
new scan hit is the same physical occurrence.

Within one filename and `(secret type, hashed secret)` group, the shared matcher in
`detect_secrets.core.occurrences` compares fresh candidates with baseline entries using:

1. **Unchanged-file coordinates:** an exact whole-file fingerprint, line number, and redacted line
   fingerprint is a high-confidence match.
2. **Local anchor continuity:** otherwise the redacted target line and HMAC fingerprints of up to
   five lines on each side must agree. A shifted match is accepted only when it is the sole
   plausible neighborhood candidate for both the old and current occurrence.
3. **Ambiguity cutoff:** a second plausible candidate, a tie, a move into unrelated context, or
   insufficient anchors stops judgement transfer. Current findings receive new ids and no prior
   `is_secret` or `is_verified` judgement is copied to them. Tied candidates are marked
   `"continuity": "ambiguous"` so `audit` presents them for re-review. Exact unchanged-file
   coordinates remain authoritative even when repeated lines create weak cross-candidates.

This keeps re-review volume low for normal edits such as inserting imports or comments at the top of
a file: the local neighborhood is unchanged and usually gives a unique match. Repeated identical
blocks and copy/paste edits are deliberately more conservative because snapshots alone cannot
always distinguish a moved line from a deleted original plus a newly pasted copy.

## Baseline privacy

The occurrence baseline does not store plaintext secrets or source-code snippets. It contains:

- the existing `hashed_secret` value;
- random occurrence ids;
- integer line numbers/offsets;
- HMAC-SHA256 fingerprints of the whole file and redacted local lines.

A random baseline-local HMAC key is stored under `occurrence_tracking.fingerprint_key`. Secret
values discovered during the scan are redacted from lines before their line/anchor fingerprints are
computed. The HMAC key is a per-baseline salt/domain separator, not encryption; anyone with the
baseline can verify guesses against its digests. The format nevertheless avoids adding raw secret
text or raw source fragments.

## Regression tests

The main regression suite creates real temporary Git repositories and exercises the command line:

```bash
pytest -q tests/core/occurrence_tracking_test.py
```

It covers:

- duplicate same-type/same-hash hits are stored separately;
- interactive `audit` changes only the selected occurrence;
- `audit --report --only-false` keeps the occurrence id;
- unchanged rescans preserve ids and judgements;
- inserting unrelated lines above an occurrence preserves continuity;
- a new same-value copy is reported by the hook and cannot inherit the old judgement;
- an indistinguishable duplicated neighborhood is marked ambiguous and requires re-audit;
- a move into unrelated context gets a new unreviewed id;
- the baseline JSON contains neither the fake secret nor a distinctive source identifier.

`--track-occurrences` cannot be combined with `--slim`, because auditing and continuation matching
require line coordinates. It also refuses to update a legacy baseline; create a new
occurrence-tracked file instead.
