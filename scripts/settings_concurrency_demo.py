#!/usr/bin/env python3
"""
Terminal demonstration for context-scoped settings.

Run from the repository root:

    python scripts/settings_concurrency_demo.py

Each section prints a short PASS/FAIL line, mirroring the bug report's
requirements:

    1. Two threads: the outer KeywordDetector scan keeps detecting while another
       thread parks inside an AWSKeyDetector-only scope; the baseline policy
       follows the outer scan too.
    2. Independent threads and interleaved asyncio tasks keep their own detector
       parameters and filter configuration.
    3. Nested scopes restore the enclosing configuration on normal exit,
       exceptions and task cancellation; a finishing scan cannot undo a live one.
    4. Settings, plugin init, regex/wordlist caches and baseline serialization
       agree on one configuration.
    5. Repo word list (min_length 3 vs 8) and opposite regex conditions stay
       correct when interleaved.
    6. Two threads block on their own barriers (5s cap) and each scan a line --
       the scope is not serialized.
    7. Inheritance/isolation boundaries for asyncio tasks.
    8. Single-threaded, non-transient calls keep the old behaviour.
"""
import asyncio
import os
import sys
import threading

if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())

from detect_secrets import filters                              # noqa: E402
from detect_secrets.core import baseline                        # noqa: E402
from detect_secrets.core.scan import scan_line                  # noqa: E402
from detect_secrets.core.secrets_collection import SecretsCollection  # noqa: E402
from detect_secrets.settings import get_settings                # noqa: E402
from detect_secrets.settings import transient_settings          # noqa: E402
from testing.mocks import mock_named_temporary_file             # noqa: E402


BARRIER_TIMEOUT = 5
KEYWORD_LINE = 'secret = "hunter2"'
KEYWORD_NAME = 'KeywordDetector'
AWS_NAME = 'AWSKeyDetector'


def report(name, ok, detail=''):
    status = 'PASS' if ok else 'FAIL'
    print(f'[{status}] {name}' + (f'  ({detail})' if detail else ''))
    return ok


def requirement_1():
    results = {}
    inner_entered = threading.Event()
    release_inner = threading.Event()

    def inner():
        with transient_settings({'plugins_used': [{'name': AWS_NAME}]}):
            inner_entered.set()
            release_inner.wait(BARRIER_TIMEOUT)

    def outer():
        with transient_settings({'plugins_used': [{'name': KEYWORD_NAME}]}):
            assert list(scan_line(KEYWORD_LINE))   # warm the caches
            worker = threading.Thread(target=inner)
            worker.start()
            try:
                inner_entered.wait(BARRIER_TIMEOUT)
                results['detected'] = bool(list(scan_line(KEYWORD_LINE)))
                results['policy'] = [
                    item['name'] for item in get_settings().json()['plugins_used']
                ]
            finally:
                release_inner.set()
                worker.join(BARRIER_TIMEOUT)

    thread = threading.Thread(target=outer)
    thread.start()
    thread.join(BARRIER_TIMEOUT)

    ok = results.get('detected') is True and results.get('policy') == [KEYWORD_NAME]
    return report(
        '1. outer scan keeps its detector + baseline policy',
        ok,
        f'detected={results.get("detected")}, policy={results.get("policy")}',
    )


def requirement_2():
    barrier = threading.Barrier(2)
    results = {}

    def worker(name, config):
        with transient_settings(config):
            barrier.wait(BARRIER_TIMEOUT)
            plugin = get_settings().get_plugins()[0]
            results[name] = (type(plugin).__name__, getattr(plugin, 'entropy_limit', None))
            barrier.wait(BARRIER_TIMEOUT)

    threads = [
        threading.Thread(
            target=worker,
            args=('b64', {'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 2.0}]}),
        ),
        threading.Thread(
            target=worker,
            args=('hex', {'plugins_used': [{'name': 'HexHighEntropyString', 'limit': 6.0}]}),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(BARRIER_TIMEOUT)

    async def scenario():
        async def task_with(pattern):
            with transient_settings({
                'plugins_used': [{'name': KEYWORD_NAME}],
                'filters_used': [{
                    'path': 'detect_secrets.filters.regex.should_exclude_secret',
                    'pattern': [pattern],
                }],
            }):
                await asyncio.sleep(0)
                return filters.regex.should_exclude_secret('hunter2')

        return await asyncio.gather(task_with('hunter'), task_with('no-match'))

    first, second = asyncio.run(scenario())
    ok = (
        results.get('b64') == ('Base64HighEntropyString', 2.0)
        and results.get('hex') == ('HexHighEntropyString', 6.0)
        and first is True and second is False
    )
    return report(
        '2. threads + interleaved asyncio tasks isolate detector/filter config',
        ok,
        f'threads={results}, regex_tasks={(first, second)}',
    )


def requirement_3():
    # Normal exit.
    with transient_settings({'plugins_used': [{'name': KEYWORD_NAME}]}):
        with transient_settings({'plugins_used': [{'name': AWS_NAME}]}):
            pass
        after_normal = sorted(get_settings().plugins)

    # Exception.
    with transient_settings({'plugins_used': [{'name': KEYWORD_NAME}]}):
        try:
            with transient_settings({'plugins_used': [{'name': AWS_NAME}]}):
                raise RuntimeError('boom')
        except RuntimeError:
            pass
        after_exception = sorted(get_settings().plugins)

    # Task cancellation.
    async def cancellation():
        with transient_settings({'plugins_used': [{'name': KEYWORD_NAME}]}):
            started = asyncio.Event()

            async def child():
                with transient_settings({'plugins_used': [{'name': AWS_NAME}]}):
                    started.set()
                    await asyncio.sleep(10)

            task = asyncio.create_task(child())
            await started.wait()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return sorted(get_settings().plugins)

    after_cancel = asyncio.run(cancellation())
    ok = (
        after_normal == [KEYWORD_NAME]
        and after_exception == [KEYWORD_NAME]
        and after_cancel == [KEYWORD_NAME]
    )
    return report(
        '3. nested scopes restore on exit/exception/cancellation',
        ok,
        f'normal={after_normal}, exception={after_exception}, cancel={after_cancel}',
    )


def requirement_4():
    line = 'password = "AKIATESTTESTTESTTEST"'
    with transient_settings({
        'plugins_used': [{'name': KEYWORD_NAME}],
        'filters_used': [],
    }) as settings:
        detected_before = bool(list(scan_line(line)))       # warm caches
        settings.configure_filters([{
            'path': 'detect_secrets.filters.regex.should_exclude_secret',
            'pattern': ['AKIA'],
        }])
        detected_after = bool(list(scan_line(line)))
        policy_paths = {item['path'] for item in settings.json()['filters_used']}
    ok = (
        detected_before is True
        and detected_after is False
        and 'detect_secrets.filters.regex.should_exclude_secret' in policy_paths
    )
    return report(
        '4. filtering result + serialized policy change together',
        ok,
        f'detected {detected_before}->{detected_after}, policy has regex filter',
    )


def requirement_5():
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
                filters.wordlist.should_exclude_secret('2short'),
            )

    # Alternate with an opposite regex condition in between.
    short = run(3)
    with transient_settings({
        'filters_used': [{
            'path': 'detect_secrets.filters.regex.should_exclude_secret',
            'pattern': ['testPass'],
        }],
    }):
        regex_hit = filters.regex.should_exclude_secret('testPass')
    long = run(8)
    short_again = run(3)

    ok = (
        short == (True, True)
        and long == (True, False)
        and short_again == (True, True)
        and regex_hit is True
    )
    return report(
        '5. word list min_length=3/8 + regex interleaving stay correct',
        ok,
        f'len3={short}, len8={long}, len3_again={short_again}, regex={regex_hit}',
    )


def requirement_6():
    barrier = threading.Barrier(2)
    results = {}

    def worker(name, config, line):
        with transient_settings(config):
            barrier.wait(BARRIER_TIMEOUT)     # both must arrive within 5s
            results[name] = bool(list(scan_line(line)))
            barrier.wait(BARRIER_TIMEOUT)

    threads = [
        threading.Thread(
            target=worker,
            args=('keyword', {'plugins_used': [{'name': KEYWORD_NAME}]}, KEYWORD_LINE),
        ),
        threading.Thread(
            target=worker,
            args=('aws', {'plugins_used': [{'name': AWS_NAME}]}, 'AKIATESTTESTTESTTEST'),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(BARRIER_TIMEOUT)

    ok = results == {'keyword': True, 'aws': True}
    return report(
        '6. two threads meet their own 5s barriers, no serialization',
        ok,
        f'results={results}',
    )


def requirement_7():
    async def scenario():
        async def child():
            inherited = sorted(get_settings().plugins)
            from detect_secrets.settings import configure_settings_from_baseline
            configure_settings_from_baseline({'plugins_used': [{'name': AWS_NAME}]})
            await asyncio.sleep(0)
            return inherited, sorted(get_settings().plugins)

        with transient_settings({'plugins_used': [{'name': KEYWORD_NAME}]}):
            task = asyncio.create_task(child())
            from detect_secrets.settings import configure_settings_from_baseline
            configure_settings_from_baseline({'plugins_used': [{'name': 'HexHighEntropyString'}]})
            inherited, mutated = await task
            parent = sorted(get_settings().plugins)
        return inherited, mutated, parent

    inherited, mutated, parent = asyncio.run(scenario())
    ok = (
        inherited == [KEYWORD_NAME]
        and mutated == [AWS_NAME, KEYWORD_NAME]
        and parent == ['HexHighEntropyString', KEYWORD_NAME]
    )
    return report(
        '7. tasks inherit at creation, then mutate independently',
        ok,
        f'inherited={inherited}, child_mutated={mutated}, parent={parent}',
    )


def requirement_8():
    # Non-transient single-threaded behaviour: a single global settings object.
    from detect_secrets.settings import reset_settings_for_testing
    reset_settings_for_testing()
    first = get_settings()
    first.configure_plugins([{'name': AWS_NAME}])
    stable = get_settings() is first and sorted(get_settings().plugins) == [AWS_NAME]

    # Baseline scan / save / reload still works with the parent artefact.
    with transient_settings({'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 4.5}]}):
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.env')
        output = baseline.format_for_output(secrets)

    with mock_named_temporary_file() as f:
        baseline.save_to_file(output, f.name)
        f.seek(0)
        reloaded = baseline.load(baseline.load_from_file(f.name), f.name)

    round_trip = reloaded.files == secrets.files and bool(secrets)
    reset_settings_for_testing()

    ok = stable and round_trip
    return report(
        '8. non-scoped behaviour unchanged; baseline scan/save/reload works',
        ok,
        f'global_stable={stable}, round_trip={round_trip}',
    )


def main():
    checks = [
        requirement_1,
        requirement_2,
        requirement_3,
        requirement_4,
        requirement_5,
        requirement_6,
        requirement_7,
        requirement_8,
    ]
    outcomes = [check() for check in checks]
    print()
    if all(outcomes):
        print(f'All {len(outcomes)} requirement checks passed.')
        return 0

    print(f'{outcomes.count(False)} requirement check(s) failed.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
