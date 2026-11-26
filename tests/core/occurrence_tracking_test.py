import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import pytest

from detect_secrets.core import occurrences


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FAKE_SECRET = 'fake-occurrence-regression-secret-0001'
GIBBERISH_FILTER = 'detect_secrets.filters.gibberish.should_exclude_secret'


def _subprocess_env() -> Dict[str, str]:
    env = os.environ.copy()
    pythonpath = str(PROJECT_ROOT)
    if env.get('PYTHONPATH'):
        pythonpath += os.pathsep + env['PYTHONPATH']
    env['PYTHONPATH'] = pythonpath
    env['NO_PROXY'] = '*'
    env['HTTP_PROXY'] = 'http://127.0.0.1:9'
    env['HTTPS_PROXY'] = 'http://127.0.0.1:9'
    return env


def _run_command(
    argv: List[str],
    cwd: Path,
    stdin: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd),
        input=stdin,
        text=True,
        capture_output=True,
        env=_subprocess_env(),
        timeout=30,
    )


def _detect_secrets(
    *arguments: str,
    cwd: Path,
    stdin: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    return _run_command(
        [sys.executable, '-m', 'detect_secrets', *arguments],
        cwd=cwd,
        stdin=stdin,
    )


def _scan(
    *arguments: str,
    cwd: Path,
    stdin: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    return _detect_secrets(
        'scan',
        '--disable-filter',
        GIBBERISH_FILTER,
        *arguments,
        cwd=cwd,
        stdin=stdin,
    )


def _hook(
    *arguments: str,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return _run_command(
        [
            sys.executable,
            '-m',
            'detect_secrets.pre_commit_hook',
            '--disable-filter',
            GIBBERISH_FILTER,
            *arguments,
        ],
        cwd=cwd,
    )


def _git_repo(tmp_path: Path) -> Path:
    _run_command(['git', 'init', '-q'], tmp_path)
    _run_command(['git', 'config', 'user.email', 'tests@example.com'], tmp_path)
    _run_command(['git', 'config', 'user.name', 'Occurrence Tests'], tmp_path)
    return tmp_path


def _write_main_file(path: Path) -> None:
    path.write_text(
        '\n'.join(
            [
                '# demo service',
                'SERVICE_NAME = "billing"',
                f'PASSWORD = "{FAKE_SECRET}"',
                f'PASSWORD_BACKUP = "{FAKE_SECRET}"',
                '# end context one',
                '# end context two',
                '',
            ],
        ),
    )


def _load_baseline(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _entries(baseline: Dict[str, Any], filename: str = 'config.py') -> List[Dict[str, Any]]:
    return sorted(
        baseline['results'][filename],
        key=lambda entry: entry['line_number'],
    )


def test_tracked_scan_audit_rescan_copy_and_hook(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    source = tmp_path / 'config.py'
    baseline_path = tmp_path / '.occurrence-baseline.json'
    _write_main_file(source)
    _run_command(['git', 'add', 'config.py'], tmp_path)
    _run_command(['git', 'commit', '-qm', 'fixture'], tmp_path)

    scan = _scan(
        '--track-occurrences',
        '--no-verify',
        '--all-files',
        'config.py',
        cwd=tmp_path,
    )
    assert scan.returncode == 0, scan.stderr
    baseline_path.write_text(scan.stdout)

    baseline = _load_baseline(baseline_path)
    assert baseline['occurrence_tracking']['scheme'] == 'position-v1'
    initial_entries = _entries(baseline)
    assert [entry['line_number'] for entry in initial_entries] == [3, 4]
    initial_ids = [entry['occurrence']['id'] for entry in initial_entries]
    assert len(set(initial_ids)) == 2

    serialized_baseline = baseline_path.read_text()
    assert FAKE_SECRET not in serialized_baseline
    assert 'PASSWORD_BACKUP' not in serialized_baseline

    # Label only the first occurrence as a false positive, then quit.
    audit = _detect_secrets(
        'audit',
        str(baseline_path),
        cwd=tmp_path,
        stdin='y\nq\n',
    )
    assert audit.returncode == 0, audit.stderr

    audited = _entries(_load_baseline(baseline_path))
    assert audited[0]['occurrence']['id'] == initial_ids[0]
    assert audited[0]['is_secret'] is False
    assert audited[1]['occurrence']['id'] == initial_ids[1]
    assert audited[1].get('is_secret') is None

    report = _detect_secrets(
        'audit',
        str(baseline_path),
        '--report',
        '--only-false',
        cwd=tmp_path,
    )
    assert report.returncode == 0, report.stderr
    report_results = json.loads(report.stdout)['results']
    assert len(report_results) == 1
    assert report_results[0]['occurrence_id'] == initial_ids[0]

    # An unchanged rescan must preserve both identity and the single judgement.
    rescan = _scan(
        '--no-verify',
        '--all-files',
        'config.py',
        '--baseline',
        str(baseline_path),
        cwd=tmp_path,
    )
    assert rescan.returncode == 0, rescan.stderr
    unchanged = _entries(_load_baseline(baseline_path))
    assert [entry['occurrence']['id'] for entry in unchanged] == initial_ids
    assert unchanged[0]['is_secret'] is False
    assert unchanged[1].get('is_secret') is None

    hook = _hook(
        '--no-verify',
        '--baseline',
        str(baseline_path),
        'config.py',
        cwd=tmp_path,
    )
    assert hook.returncode == 0, hook.stdout + hook.stderr
    baseline_before_hook = baseline_path.read_text()
    stable_hook = _hook(
        '--no-verify',
        '--baseline',
        str(baseline_path),
        'config.py',
        cwd=tmp_path,
    )
    assert stable_hook.returncode == 0, stable_hook.stdout + stable_hook.stderr
    assert baseline_path.read_text() == baseline_before_hook

    # Insert unrelated lines above both occurrences. Local anchor evidence must
    # move both identities with their lines without asking for re-audit.
    source.write_text(
        '# unrelated header one\n'
        '# unrelated header two\n'
        '# unrelated header three\n'
        + source.read_text(),
    )
    prepend = _scan(
        '--no-verify',
        '--all-files',
        'config.py',
        '--baseline',
        str(baseline_path),
        cwd=tmp_path,
    )
    assert prepend.returncode == 0, prepend.stderr

    shifted = _entries(_load_baseline(baseline_path))
    assert [entry['line_number'] for entry in shifted] == [6, 7]
    assert [entry['occurrence']['id'] for entry in shifted] == initial_ids
    assert shifted[0]['is_secret'] is False
    assert shifted[1].get('is_secret') is None

    shifted_hook = _hook(
        '--no-verify',
        '--baseline',
        str(baseline_path),
        'config.py',
        cwd=tmp_path,
    )
    assert shifted_hook.returncode == 0, shifted_hook.stdout + shifted_hook.stderr

    # Add a third copy with distinct surrounding context. Before updating the
    # baseline, hook must report it even though type and hash match old entries.
    with source.open('a') as f:
        f.write(
            '# separate copy context alpha\n'
            f'IMPORTED_PASSWORD = "{FAKE_SECRET}"\n'
            '# separate copy context omega\n',
        )

    copy_hook = _hook(
        '--json',
        '--no-verify',
        '--baseline',
        str(baseline_path),
        'config.py',
        cwd=tmp_path,
    )
    assert copy_hook.returncode == 1
    copy_results = json.loads(copy_hook.stdout)['results']['config.py']
    assert len(copy_results) == 1
    assert copy_results[0]['line_number'] == 11
    assert copy_results[0]['occurrence']['id'] not in initial_ids

    # Explicit scan --baseline catalogs it as its own unreviewed occurrence and
    # must not transfer the first occurrence's false-positive judgement.
    update_copy = _scan(
        '--no-verify',
        '--all-files',
        'config.py',
        '--baseline',
        str(baseline_path),
        cwd=tmp_path,
    )
    assert update_copy.returncode == 0, update_copy.stderr

    with_copy = _entries(_load_baseline(baseline_path))
    assert len(with_copy) == 3
    assert [entry['occurrence']['id'] for entry in with_copy[:2]] == initial_ids
    assert with_copy[0]['is_secret'] is False
    assert with_copy[1].get('is_secret') is None
    assert with_copy[2].get('is_secret') is None
    assert with_copy[2]['occurrence']['id'] not in initial_ids

    final_hook = _hook(
        '--no-verify',
        '--baseline',
        str(baseline_path),
        'config.py',
        cwd=tmp_path,
    )
    assert final_hook.returncode == 0, final_hook.stdout + final_hook.stderr


def test_ambiguous_copy_requires_separate_reaudit(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    source = tmp_path / 'dup.py'
    baseline_path = tmp_path / 'dup-baseline.json'
    secret = 'fake-ambiguous-regression-secret-123'

    source.write_text(
        'BEFORE = "same-before"\n'
        f'PASSWORD = "{secret}"\n'
        'AFTER = "same-after"\n',
    )

    scan = _scan(
        '--track-occurrences',
        '--no-verify',
        '--all-files',
        'dup.py',
        cwd=tmp_path,
    )
    assert scan.returncode == 0, scan.stderr
    baseline_path.write_text(scan.stdout)
    old_entry = _entries(_load_baseline(baseline_path), 'dup.py')[0]
    old_id = old_entry['occurrence']['id']

    audit = _detect_secrets(
        'audit',
        str(baseline_path),
        cwd=tmp_path,
        stdin='n\nq\n',
    )
    assert audit.returncode == 0, audit.stderr
    assert _entries(_load_baseline(baseline_path), 'dup.py')[0]['is_secret'] is True

    # Duplicate the complete indistinguishable neighborhood. Hook sees two
    # unbaselined candidates because neither can safely inherit the old id.
    source.write_text(
        'BEFORE = "same-before"\n'
        f'PASSWORD = "{secret}"\n'
        'AFTER = "same-after"\n'
        'BEFORE = "same-before"\n'
        f'PASSWORD = "{secret}"\n'
        'AFTER = "same-after"\n',
    )
    ambiguous_hook = _hook(
        '--json',
        '--no-verify',
        '--baseline',
        str(baseline_path),
        'dup.py',
        cwd=tmp_path,
    )
    assert ambiguous_hook.returncode == 1
    assert len(json.loads(ambiguous_hook.stdout)['results']['dup.py']) == 2

    update = _scan(
        '--no-verify',
        '--all-files',
        'dup.py',
        '--baseline',
        str(baseline_path),
        cwd=tmp_path,
    )
    assert update.returncode == 0, update.stderr

    ambiguous_entries = _entries(_load_baseline(baseline_path), 'dup.py')
    assert [entry['line_number'] for entry in ambiguous_entries] == [2, 5]
    assert all(entry['occurrence']['id'] != old_id for entry in ambiguous_entries)
    assert all(entry.get('is_secret') is None for entry in ambiguous_entries)
    assert all(
        entry['occurrence']['continuity'] == 'ambiguous'
        for entry in ambiguous_entries
    )

    # Re-audit only the first replacement identity.
    reaudit = _detect_secrets(
        'audit',
        str(baseline_path),
        cwd=tmp_path,
        stdin='y\nq\n',
    )
    assert reaudit.returncode == 0, reaudit.stderr
    reaudited = _entries(_load_baseline(baseline_path), 'dup.py')
    assert reaudited[0]['is_secret'] is False
    assert reaudited[1].get('is_secret') is None
    reaudited_ids = [entry['occurrence']['id'] for entry in reaudited]

    rescan = _scan(
        '--no-verify',
        '--all-files',
        'dup.py',
        '--baseline',
        str(baseline_path),
        cwd=tmp_path,
    )
    assert rescan.returncode == 0, rescan.stderr
    preserved = _entries(_load_baseline(baseline_path), 'dup.py')
    assert [entry['occurrence']['id'] for entry in preserved] == reaudited_ids
    assert preserved[0]['is_secret'] is False
    assert preserved[1].get('is_secret') is None

    serialized = baseline_path.read_text()
    assert secret not in serialized
    assert 'same-before' not in serialized


def test_move_to_unrelated_context_does_not_inherit_judgement(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    source = tmp_path / 'moved.py'
    baseline_path = tmp_path / 'moved-baseline.json'
    secret = 'fake-moved-regression-secret-456'

    source.write_text(
        'OLD_BEFORE_TWO = "old-before-2"\n'
        'OLD_BEFORE_ONE = "old-before-1"\n'
        f'PASSWORD = "{secret}"\n'
        'OLD_AFTER_ONE = "old-after-1"\n'
        'OLD_AFTER_TWO = "old-after-2"\n',
    )
    scan = _scan(
        '--track-occurrences',
        '--no-verify',
        '--all-files',
        'moved.py',
        cwd=tmp_path,
    )
    assert scan.returncode == 0, scan.stderr
    baseline_path.write_text(scan.stdout)
    old_id = _entries(_load_baseline(baseline_path), 'moved.py')[0]['occurrence']['id']

    audit = _detect_secrets(
        'audit',
        str(baseline_path),
        cwd=tmp_path,
        stdin='y\nq\n',
    )
    assert audit.returncode == 0, audit.stderr

    # Cut the secret from its old neighborhood and paste it into an unrelated one.
    source.write_text(
        'OLD_BEFORE_TWO = "old-before-2"\n'
        'OLD_BEFORE_ONE = "old-before-1"\n'
        'OLD_AFTER_ONE = "old-after-1"\n'
        'OLD_AFTER_TWO = "old-after-2"\n'
        'NEW_BEFORE_TWO = "new-before-2"\n'
        'NEW_BEFORE_ONE = "new-before-1"\n'
        f'LEGACY_PASSWORD = "{secret}"\n'
        'NEW_AFTER_ONE = "new-after-1"\n'
        'NEW_AFTER_TWO = "new-after-2"\n',
    )

    hook = _hook(
        '--json',
        '--no-verify',
        '--baseline',
        str(baseline_path),
        'moved.py',
        cwd=tmp_path,
    )
    assert hook.returncode == 1
    assert len(json.loads(hook.stdout)['results']['moved.py']) == 1

    update = _scan(
        '--no-verify',
        '--all-files',
        'moved.py',
        '--baseline',
        str(baseline_path),
        cwd=tmp_path,
    )
    assert update.returncode == 0, update.stderr
    moved_entry = _entries(_load_baseline(baseline_path), 'moved.py')[0]
    assert moved_entry['line_number'] == 7
    assert moved_entry['occurrence']['id'] != old_id
    assert moved_entry.get('is_secret') is None
    assert moved_entry['occurrence']['continuity'] == 'tracked'


def test_any_competing_context_candidate_blocks_inheritance() -> None:
    def edge(
        old_id: str,
        current_id: str,
        score: int = 12,
        confidence: str = 'local-anchor-continuity',
    ) -> occurrences.OccurrenceMatch:
        return occurrences.OccurrenceMatch(
            old=None,
            current=None,
            updated=None,
            old_id=old_id,
            current_id=current_id,
            score=score,
            confidence=confidence,
        )

    # A higher score must not outvote a second plausible copy/move candidate.
    accepted = occurrences._select_unique_edges([
        edge('old-1', 'current-1', score=15),
        edge('old-1', 'current-copy', score=12),
    ])
    assert accepted == []

    # Unchanged-file coordinates remain authoritative, and their cross-edges do
    # not make another exact coordinate ambiguous.
    exact = edge('old-2', 'current-2', score=1000, confidence='unchanged-file-position')
    accepted = occurrences._select_unique_edges([
        exact,
        edge('old-2', 'current-other', score=12),
    ])
    assert accepted == [exact]


@pytest.mark.parametrize('flag', ['--slim', '--baseline'])
def test_track_flag_rejects_unsupported_legacy_or_slim(
    tmp_path: Path,
    flag: str,
) -> None:
    if flag == '--baseline':
        legacy = tmp_path / 'legacy.json'
        legacy.write_text(
            json.dumps({
                'version': '1.5.0',
                'results': {},
            }),
        )
        command = [
            'scan',
            '--track-occurrences',
            '--baseline',
            str(legacy),
        ]
    else:
        command = ['scan', '--track-occurrences', '--slim']

    result = _detect_secrets(*command, cwd=tmp_path)
    assert result.returncode != 0
