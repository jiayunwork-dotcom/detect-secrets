"""
There may be known words that are definitely test keys (e.g. AKIATEST for AWS keys).
One way that we can filter these out is by passing in a list of words that we know
will result in false positives. This filter efficiently processes this through the
use of the Aho-Corasick algorithm.
"""
from functools import lru_cache
from typing import Any
from typing import Optional

from ..settings import get_settings
from .util import compute_file_hash


Automaton = Any

_CONFIG_PATH = f'{__name__}.should_exclude_secret'


def is_feature_enabled() -> bool:
    try:
        _import_ahocorasick()
        return True
    except ImportError:
        return False


def initialize(wordlist_filename: str, min_length: int = 3, file_hash: str = '') -> Automaton:
    """
    Register a word list for the current settings scope.

    :param min_length: if words are too small, the automaton will flag too many
        words. As a result, our recall will decrease without a precision boost.
        Tweak this value to customize it based on your own findings.

    :param file_hash: this is used for baseline reporting purposes. The built
        automaton itself is cached by ``(filename, min_length)`` so two scopes
        sharing the same word list reuse the same immutable artifact without
        ever sharing configuration.
    """
    resolve = compute_file_hash(wordlist_filename) if not file_hash else file_hash

    # Persist the configuration for this scope, then build (or reuse) the model.
    get_settings().filters[_CONFIG_PATH] = {
        'min_length': min_length,
        'file_name': wordlist_filename,
        'file_hash': resolve,
    }

    return _get_automaton(wordlist_filename, min_length)


def should_exclude_secret(secret: str) -> bool:
    automaton = _get_configured_automaton()
    if automaton is None:
        return False

    try:
        # .lower() to make everything case-insensitive
        next(automaton.iter(string=secret.lower()))
        return True
    except StopIteration:
        return False


def _get_configured_automaton() -> Optional[Automaton]:
    """
    Return the automaton that belongs to this scope's configuration.

    The configuration is read fresh every call (it is a tiny dict lookup); the
    built automaton itself is memoized on the settings object, and backed by a
    content-keyed shared cache so that identical word lists are not rebuilt.
    """
    settings = get_settings()
    config = settings.filters.get(_CONFIG_PATH)
    if not config:
        return None

    filename = config['file_name']
    min_length = config['min_length']
    return settings.get_derived(
        ('wordlist-automaton', filename, min_length),
        lambda: _get_automaton(filename, min_length),
    )


@lru_cache(maxsize=32)
def _build_automaton(wordlist_filename: str, min_length: int) -> Automaton:
    """Build an immutable automaton for the given file parameters."""
    ahocorasick = _import_ahocorasick()

    automaton = ahocorasick.Automaton()
    with open(wordlist_filename) as f:
        for line in f.readlines():
            line = line.lower().strip()

            if len(line) < min_length:
                continue

            automaton.add_word(line, line)

    automaton.make_automaton()
    return automaton


def _get_automaton(wordlist_filename: str, min_length: int) -> Automaton:
    return _build_automaton(wordlist_filename, min_length)


def _import_ahocorasick() -> Any:
    import ahocorasick
    return ahocorasick


def clear_caches() -> None:
    _build_automaton.cache_clear()


# Backwards-compatible helper. ``get_automaton`` used to return a single
# process-wide automaton; the engine now goes through
# ``_get_configured_automaton``.  Tests still poke at ``get_automaton`` and at
# ``get_automaton.cache_clear()``, so keep both behaviours available.
def get_automaton() -> Automaton:
    _import_ahocorasick()
    configured = _get_configured_automaton()
    if configured is not None:
        return configured
    return _import_ahocorasick().Automaton()


get_automaton.cache_clear = clear_caches      # type: ignore[attr-defined]
