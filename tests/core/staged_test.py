"""
Tests for ``detect-secrets scan --staged`` and ``detect-secrets-hook --staged``.

Every test builds a throwaway Git repository with hand-crafted fake secrets and
drives the real CLI entry points.  The plugins perform offline checks only, so
the whole suite runs without network access once dependencies are installed.
"""
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict
from typing import List
from typing import Optional

import pytest

from detect_secrets.core import staged
from detect_secrets.main import main as scan_main
from detect_secrets.pre_commit_hook import main as hook_main


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Hand-crafted, high-entropy fake secrets. They are not real credentials.
SECRET_ONE = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'
SECRET_TWO = 'ZjZDR1Y0YU1MOVplZG9oM09VTmJTYWtCeW1vN3lwbEI='
SECRET_THREE = 'bmV3LWhpZ2gtZW50cm9weS1zZWNyZXQtdmFsdWUtMTIzNA=='

GIBBERISH_FILTER = 'detect_secrets.filters.gibberish.should_exclude_secret'


# --------------------------------------------------------------------------- #
# Repository / process helpers
# --------------------------------------------------------------------------- #
def _env() -> Dict[str, str]:
    env = os.environ.copy()
    pythonpath = str(PROJECT_ROOT)
    if env.get('PYTHONPATH'):
        pythonpath += os.pathsep + env['PYTHONPATH']
    env['PYTHONPATH'] = pythonpath
    # Belt and braces: these checks must work fully offline.
    env['NO_PROXY'] = '*'
    env['HTTP_PROXY'] = 'http://127.0.0.1:9'
    env['HTTPS_PROXY'] = 'http://127.0.0.1:9'
    return env


def git(repo: Path, *args: str, input_text: Optional[str] = None) -> str:
    completed = subprocess.run(
        ['git', *args],
        cwd=str(repo),
        input=input_text,
        text=True,
        capture_output=True,
        env=_env(),
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / 'repo'
    repo.mkdir()
    git(repo, 'init', '-q')
    git(repo, 'config', 'user.email', 'tests@example.com')
    git(repo, 'config', 'user.name', 'Staged Tests')
    return repo


def write(repo: Path, name: str, content: str) -> Path:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def stage(repo: Path, *names: str) -> None:
    if names and names[0] == '--':
        git(repo, 'add', *names)
    else:
        git(repo, 'add', '--', *names)


def _common_args(*extra: str) -> List[str]:
    return [
        '--no-verify',
        '--disable-filter',
        GIBBERISH_FILTER,
        *extra,
    ]


def run_scan(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, '-m', 'detect_secrets', 'scan', *_common_args(*args)],
        cwd=str(repo),
        text=True,
        capture_output=True,
        env=_env(),
        timeout=60,
    )


def run_hook(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            '-m',
            'detect_secrets.pre_commit_hook',
            *_common_args(*args),
        ],
        cwd=str(repo),
        text=True,
        capture_output=True,
        env=_env(),
        timeout=60,
    )


def results_of(completed: subprocess.CompletedProcess) -> Dict:
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)['results']


# --------------------------------------------------------------------------- #
# Snapshot unit behavior
# --------------------------------------------------------------------------- #
class TestStagedSnapshot:
    def test_lists_only_stage_zero_regular_files(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'regular.py', f'PASSWORD = "{SECRET_ONE}"\n')
        write(repo, 'target.py', f'PASSWORD = "{SECRET_ONE}"\n')
        (repo / 'link.py').symlink_to('target.py')
        stage(repo, 'regular.py', 'target.py', 'link.py')

        with staged.staged_snapshot(str(repo)) as snapshot:
            assert sorted(snapshot.files) == ['regular.py', 'target.py']
            assert snapshot.resolve_repo_relative_path('regular.py') == 'regular.py'
            assert snapshot.resolve_repo_relative_path('link.py') is None
            assert snapshot.read_bytes('regular.py').decode() == (
                f'PASSWORD = "{SECRET_ONE}"\n'
            )

    def test_handles_spaces_and_newlines_in_filenames(self, tmp_path):
        repo = make_repo(tmp_path)
        weird_name = 'weird\nname with spaces.py'
        write(repo, weird_name, f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, '--', weird_name)

        with staged.staged_snapshot(str(repo)) as snapshot:
            assert snapshot.files == [weird_name]
            assert snapshot.materialized_path(weird_name).endswith(weird_name)
            assert os.path.isfile(snapshot.materialized_path(weird_name))

    def test_survives_worktree_deletion_and_edits(self, tmp_path):
        repo = make_repo(tmp_path)
        path = write(repo, 'frozen.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'frozen.py')

        with staged.staged_snapshot(str(repo)) as snapshot:
            path.unlink()
            write(repo, 'other.py', f'PASSWORD = "{SECRET_TWO}"\n')
            # Snapshot content is fixed at entry time.
            assert SECRET_ONE in snapshot.read_bytes('frozen.py').decode()
            assert 'other.py' not in snapshot.files

    def test_unmerged_index_is_an_error_not_a_clean_scan(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'f.txt', 'a = 1\n')
        stage(repo, 'f.txt')
        git(repo, 'commit', '-qm', 'base')
        git(repo, 'checkout', '-qb', 'side')
        write(repo, 'f.txt', 'side\n')
        stage(repo, 'f.txt')
        git(repo, 'commit', '-qm', 'side')
        git(repo, 'checkout', '-q', 'master')
        write(repo, 'f.txt', 'main\n')
        stage(repo, 'f.txt')
        git(repo, 'commit', '-qm', 'main2')

        merge = subprocess.run(
            ['git', 'merge', 'side', '-q', '--no-edit'],
            cwd=str(repo),
            capture_output=True,
            env=_env(),
        )
        assert merge.returncode != 0  # conflict expected

        with pytest.raises(staged.StagedSnapshotError):
            with staged.staged_snapshot(str(repo)):
                pass

    def test_cleanup_removes_temp_directory(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'a.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'a.py')

        with staged.staged_snapshot(str(repo)) as snapshot:
            tempdir = snapshot.tempdir
            assert os.path.isdir(tempdir)

        assert not os.path.exists(tempdir)

    def test_blob_read_failure_is_reported(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'a.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'a.py')

        original_run = staged.subprocess.run

        def flaky_run(argv, *args, **kwargs):
            if argv[:2] == ['git', 'cat-file']:
                raise subprocess.CalledProcessError(1, argv, stderr=b'missing object')
            return original_run(argv, *args, **kwargs)

        with pytest.raises(staged.StagedSnapshotError):
            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(staged.subprocess, 'run', flaky_run)
                with staged.staged_snapshot(str(repo)):
                    pass

    def test_missing_git_binary_is_reported(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'a.py', 'safe = 1\n')
        stage(repo, 'a.py')

        def no_git(argv, *args, **kwargs):
            raise FileNotFoundError(2, 'No such file or directory')

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(staged.subprocess, 'run', no_git)
            with pytest.raises(staged.StagedSnapshotError):
                with staged.staged_snapshot(str(repo)):
                    pass

    def test_preparse_helpers(self, tmp_path):
        assert staged.wants_staged(['scan', '--staged'])
        assert staged.wants_staged(['--staged', 'x'])
        assert not staged.wants_staged(['scan'])
        # Everything after `--` is positional, so the switch is not recognized.
        assert not staged.wants_staged(['scan', '--', '--staged'])

        assert staged.get_workdir_override(['-C', '/some/repo', 'scan']) == '/some/repo'
        assert staged.get_workdir_override(['-C/some/repo', 'scan']) == '/some/repo'
        assert staged.get_workdir_override(['scan']) is None
        assert staged.get_workdir_override(['scan', '--', '-C', 'x']) is None

    def test_path_resolution_inside_and_outside_repo(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'dir/a.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'dir/a.py')

        with staged.staged_snapshot(str(repo)) as snapshot:
            assert snapshot.resolve_repo_relative_path('dir/a.py') == 'dir/a.py'
            assert snapshot.resolve_repo_relative_path(
                str(repo / 'dir/a.py'),
            ) == 'dir/a.py'
            assert snapshot.resolve_repo_relative_path(
                str(tmp_path / 'outside.py'),
            ) is None
            assert (
                snapshot.to_repo_relative_path(
                    snapshot.materialized_path('dir/a.py'),
                )
                == 'dir/a.py'
            )


# --------------------------------------------------------------------------- #
# scan --staged
# --------------------------------------------------------------------------- #
class TestScanStaged:
    def test_secret_only_in_index_is_reported(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'staged_only.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'staged_only.py')
        # Delete the working-tree copy: the indexed blob must still be scanned.
        (repo / 'staged_only.py').unlink()

        results = results_of(run_scan(repo, '--staged'))
        assert 'staged_only.py' in results
        assert {entry['line_number'] for entry in results['staged_only.py']} == {1}

    def test_secret_only_in_working_tree_is_not_reported(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'clean.py', 'safe = "nothing interesting here"\n')
        stage(repo, 'clean.py')
        write(repo, 'work_only.py', f'PASSWORD = "{SECRET_TWO}"\n')

        results = results_of(run_scan(repo, '--staged'))
        assert list(results) == []

    def test_reports_repo_relative_paths_without_temp_leakage(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'pkg/app.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'pkg/app.py')

        completed = run_scan(repo, '--staged')
        assert 'pkg/app.py' in json.loads(completed.stdout)['results']
        assert 'detect-secrets-staged' not in completed.stdout
        assert str(repo) not in completed.stdout

    def test_deleted_symlink_and_submodule_are_not_regular_files(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'target.py', f'PASSWORD = "{SECRET_ONE}"\n')
        (repo / 'link.py').symlink_to('target.py')
        stage(repo, 'target.py', 'link.py')

        results = results_of(run_scan(repo, '--staged'))
        assert 'target.py' in results
        assert 'link.py' not in results

    def test_submodule_gitlink_is_not_treated_as_a_regular_file(self, tmp_path):
        repo = make_repo(tmp_path)
        embedded = tmp_path / 'embedded'
        embedded.mkdir()
        git(embedded, 'init', '-q')
        git(embedded, 'config', 'user.email', 'tests@example.com')
        git(embedded, 'config', 'user.name', 'Staged Tests')
        write(embedded, 'inner.py', f'PASSWORD = "{SECRET_ONE}"\n')
        git(embedded, 'add', '--', 'inner.py')
        git(embedded, 'commit', '-qm', 'inner')

        git(repo, '-c', 'protocol.file.allow=always', 'submodule', 'add', str(embedded), 'vendor')
        git(repo, 'add', '--', '.gitmodules', 'vendor')

        # The gitlink is staged at mode 160000 and must be skipped entirely.
        modes = {
            line.split(' ')[0]
            for line in git(repo, 'ls-files', '--stage').splitlines()
            if '\tvendor' in line
        }
        assert modes == {'160000'}

        results = results_of(run_scan(repo, '--staged'))
        assert 'vendor' not in results
        assert not any(name.startswith('vendor/') for name in results)

    def test_newline_filename_is_scanned_with_correct_line_number(self, tmp_path):
        repo = make_repo(tmp_path)
        weird = 'weird\nname with spaces.py'
        write(repo, weird, f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, '--', weird)

        results = results_of(run_scan(repo, '--staged'))
        assert weird in results
        assert results[weird][0]['line_number'] == 1

    def test_mid_run_git_add_cannot_change_scanned_version(self, tmp_path):
        from detect_secrets.settings import transient_settings

        repo = make_repo(tmp_path)
        app = write(repo, 'app.py', f'CONFIG_VALUE = "{SECRET_ONE}"\n')
        stage(repo, 'app.py')

        with transient_settings({
            'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 4.5}],
        }):
            with staged.staged_snapshot(str(repo)) as snapshot:
                # Re-stage completely different content while the snapshot is alive.
                app.write_text('CONFIG_VALUE = "plain replacement, no secret"\n')
                stage(repo, 'app.py')

                collection = staged.create_collection_from_snapshot(snapshot)
                assert 'app.py' in collection.files
                assert {
                    secret.line_number
                    for secret in collection['app.py']
                } == {1}

                # A fresh snapshot observes the new index version.
                with staged.staged_snapshot(str(repo)) as refreshed:
                    assert SECRET_ONE not in refreshed.read_bytes('app.py').decode()

    def test_staged_rejects_baseline_file_and_special_modes(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'a.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'a.py')

        for bad_args in (
            ['--staged', '--string', SECRET_ONE],
            ['--staged', '--only-allowlisted'],
        ):
            completed = run_scan(repo, *bad_args)
            assert completed.returncode != 0

        baseline = write(repo, 'baseline.json', '{}')
        stage(repo, 'baseline.json')
        completed = run_scan(repo, '--staged', '--baseline', str(baseline))
        assert completed.returncode != 0

    def test_staged_scan_does_not_modify_index_or_worktree(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'a.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'a.py')
        index_before = git(repo, 'ls-files', '--stage')
        worktree_before = (repo / 'a.py').read_text()

        run_scan(repo, '--staged')

        assert git(repo, 'ls-files', '--stage') == index_before
        assert (repo / 'a.py').read_text() == worktree_before

    def test_track_occurrences_baseline_carries_redacted_evidence(self, tmp_path):
        repo = make_repo(tmp_path)
        write(
            repo,
            'config.py',
            '\n'.join([
                '# header',
                f'CONFIG_VALUE = "{SECRET_ONE}"',
                f'BACKUP_VALUE = "{SECRET_ONE}"',
                '# footer',
                '',
            ]),
        )
        stage(repo, 'config.py')

        completed = run_scan(repo, '--staged', '--track-occurrences')
        data = json.loads(completed.stdout)
        assert data['occurrence_tracking']['scheme'] == 'position-v1'

        # Several plugins may flag each line; group findings by line number.
        entries = sorted(
            data['results']['config.py'],
            key=lambda item: item['line_number'],
        )
        assert sorted({entry['line_number'] for entry in entries}) == [2, 3]
        occurrence_ids = {
            entry['occurrence']['id']
            for entry in entries
        }
        assert len(occurrence_ids) == len(entries)
        assert all(entry['occurrence']['evidence']['available'] for entry in entries)

        # Raw secrets and temp paths must never appear in the baseline.
        assert SECRET_ONE not in completed.stdout
        assert 'detect-secrets-staged' not in completed.stdout


# --------------------------------------------------------------------------- #
# hook --staged
# --------------------------------------------------------------------------- #
class TestHookStaged:
    def test_blocks_on_staged_secret_and_succeeds_when_clean(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'secret.py', f'CONFIG_VALUE = "{SECRET_ONE}"\n')
        write(repo, 'clean.py', 'safe = "ordinary code"\n')
        stage(repo, 'secret.py', 'clean.py')

        blocked = run_hook(repo, '--staged')
        assert blocked.returncode == 1
        assert 'secret.py:1' in blocked.stdout

        write(repo, 'secret.py', 'CONFIG_VALUE = "ordinary code"\n')
        stage(repo, 'secret.py')
        assert run_hook(repo, '--staged').returncode == 0

    def test_working_tree_only_secret_is_ignored(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'clean.py', 'safe = "ordinary code"\n')
        stage(repo, 'clean.py')
        write(repo, 'dirty.py', f'PASSWORD = "{SECRET_TWO}"\n')

        assert run_hook(repo, '--staged').returncode == 0

    def test_staged_deletion_does_not_revive_the_removed_file(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'kept.py', 'safe = "ordinary code"\n')
        write(repo, 'removed.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'kept.py', 'removed.py')
        git(repo, 'commit', '-qm', 'base')

        # Stage a deletion: removed.py leaves the index entirely.
        git(repo, 'rm', '-q', 'removed.py')

        results = results_of(run_scan(repo, '--staged'))
        assert 'removed.py' not in results
        assert run_hook(repo, '--staged').returncode == 0

    def test_mid_run_git_add_keeps_the_launch_time_snapshot(self, tmp_path, monkeypatch):
        """
        Drive the real hook entry point in-process, but hold the snapshot open
        across a concurrent ``git add`` by monkeypatching the blob materializer
        to pause after the index entry list was frozen.  This is deterministic
        and does not depend on process-startup timing.
        """
        from detect_secrets import pre_commit_hook
        from detect_secrets.core import staged as staged_module

        repo = make_repo(tmp_path)
        app = write(repo, 'app.py', f'CONFIG_VALUE = "{SECRET_ONE}"\n')
        stage(repo, 'app.py')

        original_run = staged_module.subprocess.run
        release = tmp_path / 'release'

        def blocking_run(argv, *args, **kwargs):
            if argv[:2] == ['git', 'cat-file']:
                # Simulate a slow check: the user re-stages clean content while
                # the snapshot is being built.
                app.write_text('CONFIG_VALUE = "clean replacement"\n')
                stage(repo, 'app.py')
                release.write_text('re-staged')
            return original_run(argv, *args, **kwargs)

        monkeypatch.setattr(staged_module.subprocess, 'run', blocking_run)

        cwd = os.getcwd()
        try:
            os.chdir(repo)
            # The indexed blob at launch still holds the secret, so the hook
            # must block even though the index changed mid-snapshot.
            assert pre_commit_hook.main([
                '--staged',
                '--no-verify',
                '--disable-filter',
                GIBBERISH_FILTER,
            ]) == 1
        finally:
            os.chdir(cwd)

        # A fresh invocation observes the new, clean index.
        assert run_hook(repo, '--staged').returncode == 0

    def test_unmerged_index_exits_nonzero_without_clean_verdict(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'f.txt', 'one\n')
        stage(repo, 'f.txt')
        git(repo, 'commit', '-qm', 'base')
        git(repo, 'checkout', '-qb', 'side')
        write(repo, 'f.txt', 'side\n')
        stage(repo, 'f.txt')
        git(repo, 'commit', '-qm', 'side')
        git(repo, 'checkout', '-q', 'master')
        write(repo, 'f.txt', 'main\n')
        stage(repo, 'f.txt')
        git(repo, 'commit', '-qm', 'main2')
        subprocess.run(
            ['git', 'merge', 'side', '-q', '--no-edit'],
            cwd=str(repo),
            capture_output=True,
            env=_env(),
        )

        completed = run_hook(repo, '--staged')
        assert completed.returncode == 1
        assert 'unmerged' in completed.stderr

    def test_baseline_is_read_from_snapshot_and_never_rewritten(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'app.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'app.py')

        scan = run_scan(repo, '--staged')
        baseline_path = write(repo, '.secrets.baseline', scan.stdout)
        stage(repo, '.secrets.baseline')

        # Tamper with the working-tree baseline after staging: the hook must use
        # the staged blob, which still contains a valid, matching baseline.
        baseline_path.write_text('{"tampered": true}\n')
        clean = run_hook(repo, '--staged', '--baseline', '.secrets.baseline')
        assert clean.returncode == 0, clean.stdout + clean.stderr
        assert baseline_path.read_text() == '{"tampered": true}\n'

    def test_unstaged_baseline_path_is_rejected(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'app.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'app.py')
        write(repo, 'local.json', '{}')

        rejected = run_hook(repo, '--staged', '--baseline', 'local.json')
        assert rejected.returncode != 0
        assert 'staged snapshot' in rejected.stderr

    def test_tracked_baseline_matches_but_new_occurrence_is_flagged(self, tmp_path):
        repo = make_repo(tmp_path)
        write(
            repo,
            'config.py',
            '\n'.join([
                '# header',
                f'CONFIG_VALUE = "{SECRET_ONE}"',
                f'BACKUP_VALUE = "{SECRET_ONE}"',
                '# footer',
                '',
            ]),
        )
        stage(repo, 'config.py')

        write(
            repo,
            'tracked.json',
            run_scan(repo, '--staged', '--track-occurrences').stdout,
        )
        stage(repo, 'tracked.json')
        assert run_hook(
            repo, '--staged', '--baseline', 'tracked.json',
        ).returncode == 0

        # Add a third, separately-located copy and stage it.
        with (repo / 'config.py').open('a') as f:
            f.write(
                '# separate context alpha\n'
                f'IMPORTED_VALUE = "{SECRET_ONE}"\n'
                '# separate context omega\n',
            )
        stage(repo, 'config.py')

        blocked = run_hook(
            repo, '--staged', '--json', '--baseline', 'tracked.json',
        )
        assert blocked.returncode == 1
        new_entries = json.loads(blocked.stdout)['results']['config.py']
        # Verify the reported coordinate against the actual staged fixture.
        expected_line = (repo / 'config.py').read_text().splitlines().index(
            f'IMPORTED_VALUE = "{SECRET_ONE}"',
        ) + 1
        assert {entry['line_number'] for entry in new_entries} == {expected_line}

        # Inspect-only: the staged index and working tree are untouched.
        assert git(repo, 'status', '--porcelain') != ''
        index_before = git(repo, 'ls-files', '--stage')
        run_hook(repo, '--staged', '--baseline', 'tracked.json')
        assert git(repo, 'ls-files', '--stage') == index_before

    def test_two_files_with_different_contents_are_distinct(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'a.py', f'A = "{SECRET_ONE}"\n')
        write(repo, 'b.py', f'B = "{SECRET_TWO}"\n')
        stage(repo, 'a.py', 'b.py')

        results = results_of(run_scan(repo, '--staged'))
        assert set(results) == {'a.py', 'b.py'}

        # Baseline covering both files yields a clean hook.
        write(
            repo,
            'both.json',
            run_scan(repo, '--staged').stdout,
        )
        stage(repo, 'both.json')
        assert run_hook(
            repo, '--staged', '--baseline', 'both.json',
        ).returncode == 0

    def test_hook_does_not_modify_worktree_or_index(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'app.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'app.py')
        index_before = git(repo, 'ls-files', '--stage')
        worktree_before = (repo / 'app.py').read_text()

        run_hook(repo, '--staged')

        assert git(repo, 'ls-files', '--stage') == index_before
        assert (repo / 'app.py').read_text() == worktree_before


# --------------------------------------------------------------------------- #
# Non-staged semantics remain unchanged
# --------------------------------------------------------------------------- #
class TestNonStagedSemanticsUnchanged:
    def test_plain_scan_still_reads_working_tree(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'app.py', 'safe = "ordinary code"\n')
        stage(repo, 'app.py')
        # An unstaged secret must be visible to a normal (non-staged) scan.
        write(repo, 'app.py', f'PASSWORD = "{SECRET_ONE}"\n')

        completed = run_scan(repo)
        assert 'app.py' in json.loads(completed.stdout)['results']

    def test_plain_hook_uses_positional_filenames(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'app.py', f'PASSWORD = "{SECRET_ONE}"\n')

        blocked = run_hook(repo, 'app.py')
        assert blocked.returncode == 1

    def test_in_process_entry_points_accept_explicit_argv(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'app.py', f'PASSWORD = "{SECRET_ONE}"\n')
        stage(repo, 'app.py')

        cwd = os.getcwd()
        try:
            os.chdir(repo)
            assert hook_main(['--staged', '--no-verify']) == 1
            assert scan_main(['scan', '--staged', '--no-verify']) == 0
        finally:
            os.chdir(cwd)

    def test_entry_points_fail_nonzero_outside_a_work_tree(self, tmp_path):
        not_a_repo = tmp_path / 'plain-dir'
        not_a_repo.mkdir()

        cwd = os.getcwd()
        try:
            os.chdir(not_a_repo)
            assert scan_main(['scan', '--staged', '--no-verify']) == 1
            assert hook_main(['--staged', '--no-verify']) == 1
        finally:
            os.chdir(cwd)

    def test_custom_root_option_resolves_repository(self, tmp_path):
        repo = make_repo(tmp_path)
        write(repo, 'app.py', f'CONFIG_VALUE = "{SECRET_ONE}"\n')
        stage(repo, 'app.py')

        scan = subprocess.run(
            [
                sys.executable,
                '-m',
                'detect_secrets',
                '-C',
                str(repo),
                'scan',
                '--staged',
                '--no-verify',
            ],
            cwd=str(tmp_path),
            text=True,
            capture_output=True,
            env=_env(),
            timeout=60,
        )
        assert scan.returncode == 0, scan.stderr
        assert 'app.py' in json.loads(scan.stdout)['results']

        hook = subprocess.run(
            [
                sys.executable,
                '-m',
                'detect_secrets.pre_commit_hook',
                '-C',
                str(repo),
                '--staged',
                '--no-verify',
            ],
            cwd=str(tmp_path),
            text=True,
            capture_output=True,
            env=_env(),
            timeout=60,
        )
        assert hook.returncode == 1, hook.stderr
