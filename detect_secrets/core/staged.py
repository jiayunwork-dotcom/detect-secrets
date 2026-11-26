"""
A fixed, read-only snapshot of the Git index (staging area).

Why this module exists
----------------------
Both ``detect-secrets scan --staged`` and ``detect-secrets-hook --staged`` must
report on exactly the bytes that were staged when the command started, even if:

* the user runs ``git add`` again while the check is in progress,
* the working-tree copy of a staged file is modified or deleted,
* file names contain spaces or newlines.

The snapshot is taken once, up front.  Every stage-0 regular file in the index
is materialized into a private temporary directory, using the blob content
recorded in the index rather than anything read from the working tree.  The
existing scanning kernel, filters, transformers and occurrence-evidence code
then operate on that directory unchanged: they see ordinary files whose
contents are frozen for the whole invocation.  Deleted index entries, symbolic
links and gitlinks (submodules) are deliberately not materialized, because they
are not regular files.

Costs
-----
* Isolation: O(total staged bytes) are copied into a temp directory, so scans
  are immune to concurrent ``git add``/working-tree edits and never observe a
  half-written mixture of old and new content.
* File count: one temp file plus one directory entry per staged path; the
  ``git`` invocations themselves are O(number of index entries).
* Bytes: disk and memory use grow linearly with the total size of staged blobs;
  the temp directory is removed when the context exits.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .secrets_collection import SecretsCollection


# Index entry status codes emitted by ``git ls-files --stage`` /
# ``git diff --cached --raw``.  Non-zero stages (1,2,3) mark an unresolved
# merge and must never be silently treated as a clean, scannable index.
UNMERGED_STAGES = {'1', '2', '3'}


class StagedSnapshotError(ValueError):
    """Raised when the staging area cannot be turned into a fixed snapshot."""


class StagedSnapshot:
    """
    An on-disk materialization of the Git index at one point in time.

    :ivar root: repository root (as reported by ``git rev-parse``)
    :ivar workdir: directory the command was launched from; used to resolve
        repository-relative paths given on the command line
    :ivar tempdir: private directory holding the frozen blob contents
    :ivar files: repository-relative paths of every materialized stage-0
        regular file, in index order
    """

    def __init__(
        self,
        root: str,
        workdir: str,
        tempdir: str,
        files: List[str],
    ) -> None:
        self.root = root
        self.workdir = workdir
        self.tempdir = tempdir
        self.files = files

    # ------------------------------------------------------------------ paths
    def materialized_path(self, repo_relative_path: str) -> str:
        """Absolute path of a staged file's frozen copy inside the temp dir."""
        return os.path.join(self.tempdir, repo_relative_path)

    def to_repo_relative_path(self, materialized_filename: str) -> str:
        """
        Convert an absolute temp-dir path produced by the scanning kernel back
        into the file's repository-relative name.
        """
        normalized = os.path.normpath(materialized_filename)
        prefix = os.path.normpath(self.tempdir) + os.sep
        if normalized.startswith(prefix):
            return normalized[len(prefix):].replace(os.sep, '/')

        # Fallback for names that were already relative to the temp dir.
        return normalized.replace(os.sep, '/')

    def resolve_repo_relative_path(self, path: str) -> Optional[str]:
        candidate = self._normalize(path)
        if candidate is None:
            return None

        staged = set(self.files)
        if candidate in staged:
            return candidate

        # Tolerate callers that already pass a repository-relative path.
        if not os.path.isabs(path) and path.replace(os.sep, '/') in staged:
            return path.replace(os.sep, '/')

        return None

    def read_bytes(self, repo_relative_path: str) -> bytes:
        """Read frozen content for a staged path; raises if it is unavailable."""
        with open(self.materialized_path(repo_relative_path), 'rb') as f:
            return f.read()

    def _normalize(self, path: str) -> Optional[str]:
        if os.path.isabs(path):
            absolute = os.path.normpath(path)
        else:
            absolute = os.path.normpath(os.path.join(self.workdir, path))

        root_with_sep = os.path.normpath(self.root) + os.sep
        if absolute != os.path.normpath(self.root) and not absolute.startswith(root_with_sep):
            return None

        return os.path.relpath(absolute, self.root).replace(os.sep, '/')

    # ------------------------------------------------------------- lifecycle
    def cleanup(self) -> None:
        shutil.rmtree(self.tempdir, ignore_errors=True)


def _run_git(*args: str, cwd: Optional[str] = None) -> str:
    """
    :raises StagedSnapshotError: when git is missing or exits non-zero.
    """
    try:
        completed = subprocess.run(
            ['git', *args],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except FileNotFoundError as e:
        raise StagedSnapshotError('`git` is required for --staged scans.') from e
    except subprocess.CalledProcessError as e:
        message = e.stderr.decode('utf-8', errors='replace').strip()
        raise StagedSnapshotError(
            f'Unable to read the Git index: {message or e}',
        ) from e

    return completed.stdout.decode('utf-8', errors='surrogateescape')


def _get_repo_root(workdir: str) -> str:
    output = _run_git('rev-parse', '--show-toplevel', cwd=workdir)
    return output.strip()


def _get_raw_index_entries(root: str) -> List[Tuple[str, str, str, str]]:
    """
    Return ``(mode, sha, stage, path)`` tuples for every index entry.

    ``git ls-files --stage`` emits NUL-terminated records of the form
    ``<mode> <sha> <stage>\\t<path>\\0``, which keeps file names containing
    newlines and spaces parseable.
    """
    output = _run_git('ls-files', '--stage', '-z', cwd=root)
    entries: List[Tuple[str, str, str, str]] = []
    for record in output.split('\0'):
        if not record:
            continue

        metadata, path = record.split('\t', 1)
        mode, sha, stage = metadata.split(' ')
        entries.append((mode, sha, stage, path))

    return entries


def _assert_no_unmerged_entries(
    entries: List[Tuple[str, str, str, str]],
) -> None:
    unmerged: List[str] = [
        path
        for _mode, _sha, stage, path in entries
        if stage in UNMERGED_STAGES
    ]

    if unmerged:
        displayed = ', '.join(repr(path) for path in unmerged[:5])
        raise StagedSnapshotError(
            'Cannot scan --staged while the index has unmerged entries. '
            f'Resolve the conflicts first (examples: {displayed}).',
        )


def _create_snapshot(root: str, workdir: str) -> StagedSnapshot:
    entries = _get_raw_index_entries(root)
    _assert_no_unmerged_entries(entries)

    tempdir = tempfile.mkdtemp(prefix='detect-secrets-staged-')
    materialized: List[str] = []

    try:
        for mode, sha, stage, path in entries:
            # Defensive: unmerged stages were rejected above; only materialize
            # regular files at stage 0.
            #   100644 / 100755 -> regular file
            #   120000          -> symbolic link
            #   160000          -> submodule gitlink
            if stage != '0' or not mode.startswith('100'):
                continue

            destination = os.path.join(tempdir, path)
            parent = os.path.dirname(destination)
            if parent:
                os.makedirs(parent, exist_ok=True)

            # ``git cat-file blob <sha>`` reads the frozen blob object named by
            # the index, never the working tree.  A later ``git add`` cannot
            # change this object's content.
            try:
                completed = subprocess.run(
                    ['git', 'cat-file', 'blob', sha],
                    cwd=root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                message = ''
                if isinstance(e, subprocess.CalledProcessError):
                    message = e.stderr.decode('utf-8', errors='replace').strip()
                raise StagedSnapshotError(
                    f'Unable to read staged content for {path!r}: '
                    f'{message or str(e)}',
                ) from e

            with open(destination, 'wb') as f:
                f.write(completed.stdout)

            materialized.append(path)
    except BaseException:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise

    return StagedSnapshot(
        root=root,
        workdir=os.path.abspath(workdir),
        tempdir=tempdir,
        files=materialized,
    )


@contextmanager
def staged_snapshot(workdir: Optional[str] = None) -> Iterator[StagedSnapshot]:
    """
    Build a fixed snapshot of the current index and clean it up afterwards.

    :raises StagedSnapshotError: outside a work tree, with unmerged index
        entries, or when any staged blob cannot be read.
    """
    workdir = os.path.abspath(workdir or os.getcwd())
    root = _get_repo_root(workdir)
    snapshot = _create_snapshot(root, workdir)
    try:
        yield snapshot
    finally:
        snapshot.cleanup()


# ---------------------------------------------------------------------------
# Process-wide registration
#
# Argument parsing (baseline path validation, ...) happens before the scan/hook
# handlers run, so the active snapshot is published here instead of being
# threaded through every function signature.
_active_snapshot: Optional[StagedSnapshot] = None


def set_active_snapshot(snapshot: Optional[StagedSnapshot]) -> None:
    global _active_snapshot
    _active_snapshot = snapshot


def get_active_snapshot() -> Optional[StagedSnapshot]:
    return _active_snapshot


def wants_staged(argv: Optional[List[str]]) -> bool:
    """Cheap pre-parse check so the snapshot exists before argument validation."""
    if not argv:
        return False

    # Options after `--` are positional values, never our switch.
    for argument in argv:
        if argument == '--':
            return False
        if argument == '--staged':
            return True

    return False


def get_workdir_override(argv: Optional[List[str]]) -> Optional[str]:
    """
    Extract the global ``-C <path>`` option during the pre-parse, so the
    snapshot is rooted in the same repository even before argparse runs.
    """
    if not argv:
        return None

    for index, argument in enumerate(argv):
        if argument == '-C' and index + 1 < len(argv):
            return argv[index + 1]
        if argument.startswith('-C') and len(argument) > 2:
            return argument[2:]
        if argument == '--':
            return None

    return None


def create_collection_from_snapshot(
    snapshot: StagedSnapshot,
    track_occurrences: bool = False,
    fingerprint_key: Optional[str] = None,
    num_processors: Optional[int] = None,
) -> 'SecretsCollection':
    """
    Scan every materialized staged file through the unmodified scanning kernel.

    The collection's ``root`` is the private temp directory, so all file reads
    (including parallel workers and occurrence evidence) hit frozen bytes.  The
    secrets' reported filenames are rewritten back to repository-relative names
    before insertion, so neither output nor baselines ever mention the temp
    directory.
    """
    from .secrets_collection import SecretsCollection

    secrets = SecretsCollection(
        root=snapshot.tempdir,
        occurrence_tracking=track_occurrences,
        fingerprint_key=fingerprint_key,
    )
    secrets.scan_files(
        *snapshot.files,
        num_processors=num_processors,
        remap_filename=snapshot.to_repo_relative_path,
    )
    return secrets
