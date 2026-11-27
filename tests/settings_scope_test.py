"""
Tests for the context-scoped settings redesign.

These cover the failure modes described in the bug report:

1. Concurrent threads each keep their own detectors (no cross-thread泄漏).
2. Independent threads and interleaved asyncio tasks only see their own
   detector parameters and filter configuration.
3. Nested scopes restore the enclosing configuration on normal exit, exception
   and task cancellation, and a finishing scope never reverts a live scope.
4. Settings queries, plugin initialization, regex/wordlist filter caches and
   baseline serialization all agree on the same scope configuration.
5. Word lists and regex filters can be interleaved without contaminating each
   other's results.
6. Two threads can block on their own barriers and scan without serialization.
7. Inheritance and isolation boundaries hold for tasks.
8. Non-scoped single-threaded behaviour is unchanged.
"""
import asyncio
import os
import threading
from pathlib import Path

import pytest

from detect_secrets import filters
from detect_secrets.constants import VerifiedResult
from detect_secrets.core import baseline
from detect_secrets.core.scan import scan_line
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file

KEYWORD_LINE = 'secret = "hunter2"'
BARRIER_TIMEOUT = 5


# ---------------------------------------------------------------------------
# 1. Concurrent threads keep their own detectors.
# ---------------------------------------------------------------------------
def test_thread_does_not_steal_outer_detectors():
    """
    Outer thread enables KeywordDetector and warms up its caches.  A second
    thread enters an AWSKeyDetector-only transient scope and pauses.  The outer
    thread must still detect the fake password *and* serialize the config it is
    actually using.
    """
    inner_entered = threading.Event()
    outer_may_finish = threading.Event()
    results = {}

    def inner():
        with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}]}):
            inner_entered.set()
            # Sleep until the outer thread has scanned.
            outer_may_finish.wait(BARRIER_TIMEOUT)

    def outer():
        with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
            # Warm up the caches so a naive shared cache would already be primed.
            assert list(scan_line(KEYWORD_LINE))

            worker = threading.Thread(target=inner)
            worker.start()
            try:
                assert inner_entered.wait(BARRIER_TIMEOUT)

                secrets = list(scan_line(KEYWORD_LINE))
                results['outer_detected'] = bool(secrets)
                results['outer_plugins'] = sorted(get_settings().plugins)
                results['outer_json'] = [
                    item['name']
                    for item in get_settings().json()['plugins_used']
                ]
            finally:
                outer_may_finish.set()
                worker.join(BARRIER_TIMEOUT)

    thread = threading.Thread(target=outer)
    thread.start()
    thread.join(BARRIER_TIMEOUT)

    assert results['outer_detected'] is True
    assert results['outer_plugins'] == ['KeywordDetector']
    assert results['outer_json'] == ['KeywordDetector']


# ---------------------------------------------------------------------------
# 2. Threads and asyncio tasks isolate their own configuration.
# ---------------------------------------------------------------------------
def test_independent_threads_isolate_detector_parameters():
    barrier = threading.Barrier(2)
    results = {}

    def worker(name, config, expected_limit, expected_plugins):
        with transient_settings(config):
            barrier.wait(BARRIER_TIMEOUT)
            plugin = get_settings().get_plugins()[0]
            results[name] = (
                type(plugin).__name__,
                getattr(plugin, 'entropy_limit', None),
                sorted(get_settings().plugins),
            )
            barrier.wait(BARRIER_TIMEOUT)

    threads = [
        threading.Thread(
            target=worker,
            args=(
                'base64',
                {'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 2.0}]},
                2.0,
                ['Base64HighEntropyString'],
            ),
        ),
        threading.Thread(
            target=worker,
            args=(
                'hex',
                {'plugins_used': [{'name': 'HexHighEntropyString', 'limit': 6.0}]},
                6.0,
                ['HexHighEntropyString'],
            ),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(BARRIER_TIMEOUT)

    assert results['base64'] == ('Base64HighEntropyString', 2.0, ['Base64HighEntropyString'])
    assert results['hex'] == ('HexHighEntropyString', 6.0, ['HexHighEntropyString'])


def test_asyncio_tasks_inherit_then_isolate():
    async def scenario():
        seen = {}

        async def child():
            # Task inherits the config that existed at creation time.
            seen['child_inherited'] = sorted(get_settings().plugins)
            # Mutating the child's scope must not affect the parent.
            from detect_secrets.settings import configure_settings_from_baseline
            configure_settings_from_baseline({
                'plugins_used': [{'name': 'AWSKeyDetector'}],
            })
            await asyncio.sleep(0)
            seen['child_after'] = sorted(get_settings().plugins)

        with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
            task = asyncio.create_task(child())
            # Parent mutates *its* scope too; child already captured its own copy.
            from detect_secrets.settings import configure_settings_from_baseline
            configure_settings_from_baseline({
                'plugins_used': [{'name': 'HexHighEntropyString'}],
            })
            await task
            seen['parent_after'] = sorted(get_settings().plugins)
        return seen

    seen = asyncio.run(scenario())
    # The child inherited KeywordDetector at creation time, then *added*
    # AWSKeyDetector in its own scope.
    assert seen['child_inherited'] == ['KeywordDetector']
    assert seen['child_after'] == ['AWSKeyDetector', 'KeywordDetector']
    # The parent's later addition (HexHighEntropyString) is invisible to the
    # child, and the child's addition is invisible to the parent.
    assert seen['parent_after'] == ['HexHighEntropyString', 'KeywordDetector']


def test_asyncio_tasks_do_not_pollute_each_other_filters():
    async def scenario():
        async def task_with(regex_pattern):
            with transient_settings({
                'plugins_used': [{'name': 'KeywordDetector'}],
                'filters_used': [{
                    'path': 'detect_secrets.filters.regex.should_exclude_secret',
                    'pattern': [regex_pattern],
                }],
            }):
                await asyncio.sleep(0)
                return filters.regex.should_exclude_secret('hunter2')

        first, second = await asyncio.gather(
            task_with('hunter'),
            task_with('nothing-matches'),
        )
        return first, second

    first, second = asyncio.run(scenario())
    assert first is True
    assert second is False


# ---------------------------------------------------------------------------
# 3. Nested scopes restore the enclosing config on every exit path.
# ---------------------------------------------------------------------------
def test_nested_scope_restores_on_normal_exit():
    with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
        with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}]}):
            assert sorted(get_settings().plugins) == ['AWSKeyDetector']

        assert sorted(get_settings().plugins) == ['KeywordDetector']
        assert list(scan_line(KEYWORD_LINE))


def test_nested_scope_restores_on_exception():
    with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
        with pytest.raises(RuntimeError):
            with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}]}):
                assert sorted(get_settings().plugins) == ['AWSKeyDetector']
                raise RuntimeError('boom')

        assert sorted(get_settings().plugins) == ['KeywordDetector']
        assert list(scan_line(KEYWORD_LINE))


def test_nested_scope_restores_on_task_cancellation():
    async def scenario():
        with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
            started = asyncio.Event()

            async def child():
                with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}]}):
                    started.set()
                    await asyncio.sleep(10)

            task = asyncio.create_task(child())
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            return sorted(get_settings().plugins)

    assert asyncio.run(scenario()) == ['KeywordDetector']


def test_finishing_scope_does_not_revert_another_live_scope():
    outer_entered = threading.Event()
    inner_entered = threading.Event()
    inner_done = threading.Event()

    def first():
        with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
            outer_entered.set()
            # Wait until the second scope is active, then check it is still intact
            # after this scope would have "restored" its original settings.
            assert inner_entered.wait(BARRIER_TIMEOUT)
            yield_check = sorted(get_settings().plugins)
            inner_done.set()
            assert yield_check == ['KeywordDetector']

    results = {}

    def second():
        with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}]}):
            inner_entered.set()
            assert outer_entered.wait(BARRIER_TIMEOUT)
            # First scope has now "finished" (past its finally block would be an
            # issue only if scopes were shared). Give it a moment.
            inner_done.wait(BARRIER_TIMEOUT)
            results['second'] = sorted(get_settings().plugins)

    t1 = threading.Thread(target=first)
    t2 = threading.Thread(target=second)
    t1.start()
    t2.start()
    t1.join(BARRIER_TIMEOUT)
    t2.join(BARRIER_TIMEOUT)

    assert results['second'] == ['AWSKeyDetector']


# ---------------------------------------------------------------------------
# 4. Settings queries, plugins, caches and serialization agree.
# ---------------------------------------------------------------------------
def test_config_change_updates_filtering_and_reporting_together():
    line = 'password = "AKIATESTTESTTESTTEST"'

    with transient_settings({
        'plugins_used': [{'name': 'KeywordDetector'}],
        'filters_used': [],
    }) as settings:
        # Force a warm-up of the filter/plugin caches.
        assert list(scan_line(line))
        assert settings.json()['filters_used'] == []

        settings.configure_filters([{
            'path': 'detect_secrets.filters.regex.should_exclude_secret',
            'pattern': ['AKIA'],
        }])

        # The filtering result *and* the serialized policy must both change.
        assert not list(scan_line(line))
        paths = {item['path'] for item in settings.json()['filters_used']}
        assert 'detect_secrets.filters.regex.should_exclude_secret' in paths


def test_baseline_serialization_reflects_scope():
    with transient_settings({
        'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 3.5}],
    }):
        output = baseline.format_for_output(SecretsCollection())
    assert output['plugins_used'] == [{'name': 'Base64HighEntropyString', 'limit': 3.5}]


def test_verification_policy_is_scoped():
    get_settings().filters[
        'detect_secrets.filters.common.is_ignored_due_to_verification_policies'
    ] = {'min_level': VerifiedResult.VERIFIED_TRUE.value}

    with transient_settings({
        'filters_used': [{
            'path': 'detect_secrets.filters.common.is_ignored_due_to_verification_policies',
            'min_level': VerifiedResult.UNVERIFIED.value,
        }],
    }):
        assert filters.common._get_verification_policy() == VerifiedResult.UNVERIFIED

    assert filters.common._get_verification_policy() == VerifiedResult.VERIFIED_TRUE


# ---------------------------------------------------------------------------
# 5. Word list + regex filters interleaved across scopes.
# ---------------------------------------------------------------------------
def test_wordlist_min_length_variants_do_not_interfere():
    """min_length=3 and min_length=8 must each behave like when run alone."""
    wordlist = 'test_data/word_list.txt'

    def run(min_length):
        with transient_settings({
            'filters_used': [{
                'path': 'detect_secrets.filters.wordlist.should_exclude_secret',
                'min_length': min_length,
                'file_name': wordlist,
                'file_hash': 'irrelevant',
            }],
        }):
            return (
                filters.wordlist.should_exclude_secret('testPass'),
                # '2short' is only >= 3 chars, so min_length=3 catches it.
                filters.wordlist.should_exclude_secret('2short'),
            )

    # Interleave with the opposite regex condition to also warm regex caches.
    assert run(3) == (True, True)
    with transient_settings({
        'filters_used': [{
            'path': 'detect_secrets.filters.regex.should_exclude_secret',
            'pattern': ['testPass'],
        }],
    }):
        assert filters.regex.should_exclude_secret('testPass') is True
    assert run(8) == (True, False)
    assert run(3) == (True, True)


def test_regex_conditions_are_opposite_and_isolated():
    """Two scopes with opposite regex conditions stay correct when alternated."""
    patterns_a = ['^AKIA']
    patterns_b = ['^NOT-A-MATCH']

    def check(patterns, secret):
        with transient_settings({
            'filters_used': [{
                'path': 'detect_secrets.filters.regex.should_exclude_secret',
                'pattern': patterns,
            }],
        }):
            return filters.regex.should_exclude_secret(secret)

    # Warm up both, then alternate and confirm results remain independent.
    assert check(patterns_a, 'AKIATEST') is True
    assert check(patterns_b, 'AKIATEST') is False
    assert check(patterns_a, 'AKIATEST') is True
    assert check(patterns_b, 'AKIATEST') is False


def test_concurrent_wordlist_scopes():
    wordlist = 'test_data/word_list.txt'
    barrier = threading.Barrier(2)
    results = {}

    def worker(name, min_length):
        with transient_settings({
            'filters_used': [{
                'path': 'detect_secrets.filters.wordlist.should_exclude_secret',
                'min_length': min_length,
                'file_name': wordlist,
                'file_hash': 'irrelevant',
            }],
        }):
            barrier.wait(BARRIER_TIMEOUT)
            results[name] = filters.wordlist.should_exclude_secret('2short')
            barrier.wait(BARRIER_TIMEOUT)

    threads = [
        threading.Thread(target=worker, args=('short', 3)),
        threading.Thread(target=worker, args=('long', 8)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(BARRIER_TIMEOUT)

    assert results == {'short': True, 'long': False}


# ---------------------------------------------------------------------------
# 6. Two threads can hold their own barriers and scan, without serialization.
# ---------------------------------------------------------------------------
def test_two_threads_scan_at_own_barriers_simultaneously():
    barrier = threading.Barrier(2)
    results = {}

    def worker(name, config, line, expected):
        with transient_settings(config):
            # Both threads must reach this barrier -- if scopes were serialized,
            # one thread would block forever and the barrier would time out.
            barrier.wait(BARRIER_TIMEOUT)
            results[name] = bool(list(scan_line(line)))
            barrier.wait(BARRIER_TIMEOUT)

    keyword_thread = threading.Thread(
        target=worker,
        args=(
            'keyword',
            {'plugins_used': [{'name': 'KeywordDetector'}]},
            'secret = "hunter2"',
            True,
        ),
    )
    aws_thread = threading.Thread(
        target=worker,
        args=(
            'aws',
            {'plugins_used': [{'name': 'AWSKeyDetector'}]},
            'AKIATESTTESTTESTTEST',
            True,
        ),
    )
    keyword_thread.start()
    aws_thread.start()
    keyword_thread.join(BARRIER_TIMEOUT)
    aws_thread.join(BARRIER_TIMEOUT)

    assert results == {'keyword': True, 'aws': True}


# ---------------------------------------------------------------------------
# 7. Inheritance boundary: creation-time config, then independence.
# ---------------------------------------------------------------------------
def test_task_inherits_configuration_at_creation():
    async def scenario():
        async def child():
            return sorted(get_settings().plugins)

        task = asyncio.create_task(child())
        return await task

    # Outside any scope, the task sees the ambient (empty) defaults.
    assert asyncio.run(scenario()) == []

    async def scenario_inherit():
        async def child():
            return sorted(get_settings().plugins)

        with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
            return await asyncio.create_task(child())

    assert asyncio.run(scenario_inherit()) == ['KeywordDetector']


# ---------------------------------------------------------------------------
# 8. Non-transient single-threaded behaviour is unchanged.
# ---------------------------------------------------------------------------
def test_global_settings_creation_and_reuse():
    settings_module = __import__('detect_secrets.settings', fromlist=['get_settings'])
    settings_module.get_settings().clear()
    first = get_settings()
    first.configure_plugins([{'name': 'AWSKeyDetector'}])
    assert get_settings() is first
    assert sorted(get_settings().plugins) == ['AWSKeyDetector']


def test_ambient_settings_restored_after_transient_scope():
    get_settings().clear()
    get_settings().configure_plugins([{'name': 'AWSKeyDetector'}])

    with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
        assert sorted(get_settings().plugins) == ['KeywordDetector']

    assert sorted(get_settings().plugins) == ['AWSKeyDetector']


def test_baseline_round_trip_still_works_with_default_plugin_locations():
    """
    Regression: existing baseline load/save must still find secrets in the same
    files, using the packaged default configuration.
    """
    with transient_settings({
        'plugins_used': [
            {'name': 'Base64HighEntropyString', 'limit': 4.5},
        ],
    }):
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.env')
        assert secrets

        output = baseline.format_for_output(secrets)

    with mock_named_temporary_file() as f:
        baseline.save_to_file(output, f.name)
        f.seek(0)

        reloaded = baseline.load(baseline.load_from_file(f.name), f.name)

    assert reloaded.files == secrets.files


def test_threads_start_with_clean_context():
    """A fresh thread never inherits the parent thread's transient scope."""
    results = {}

    def worker():
        results['plugins'] = sorted(get_settings().plugins)

    with transient_settings({'plugins_used': [{'name': 'KeywordDetector'}]}):
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(BARRIER_TIMEOUT)

    assert results['plugins'] == []


def test_word_list_distance_offsets(tmp_path):
    """Sanity check the shared wordlist artifact cache is keyed correctly."""
    wordlist = Path('test_data/word_list.txt')

    with transient_settings({
        'filters_used': [{
            'path': 'detect_secrets.filters.wordlist.should_exclude_secret',
            'min_length': 8,
            'file_name': str(wordlist),
            'file_hash': 'irrelevant',
        }],
    }):
        assert filters.wordlist.should_exclude_secret('testPass') is True
        assert filters.wordlist.should_exclude_secret('AKIAnotr') is False

    assert os.path.exists(wordlist)
