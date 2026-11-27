import re
from functools import lru_cache
from typing import List
from typing import Pattern
from typing import Tuple
from typing import cast

from ..settings import get_settings

_LINE_PATH = f'{__name__}.should_exclude_line'
_FILE_PATH = f'{__name__}.should_exclude_file'
_SECRET_PATH = f'{__name__}.should_exclude_secret'


def should_exclude_line(line: str) -> bool:
    regexes = _get_line_exclusion_regex(_LINE_PATH)
    for regex in regexes:
        if regex.search(line):
            return True
    return False


def _get_line_exclusion_regex(path: str = _LINE_PATH) -> List[Pattern]:
    return _get_exclusion_regex(path)


def should_exclude_file(filename: str) -> bool:
    regexes = _get_file_exclusion_regex(_FILE_PATH)
    for regex in regexes:
        if regex.search(filename):
            return True
    return False


def _get_file_exclusion_regex(path: str = _FILE_PATH) -> List[Pattern]:
    return _get_exclusion_regex(path)


def should_exclude_secret(secret: str) -> bool:
    regexes = _get_secret_exclusion_regex(_SECRET_PATH)
    for regex in regexes:
        if regex.search(secret):
            return True
    return False


def _get_secret_exclusion_regex(path: str = _SECRET_PATH) -> List[Pattern]:
    return _get_exclusion_regex(path)


def _get_exclusion_regex(path: str) -> List[Pattern]:
    """
    Materialize the compiled patterns configured for ``path``.

    The memo lives on the *current* settings object, so it is discarded whenever
    the configuration changes or the scope is left.  The compiled patterns
    behind it come from a content-keyed shared cache: identical pattern tuples
    are safe to reuse across scopes because the artifact is immutable and fully
    determined by its key.
    """
    settings = get_settings()
    patterns = tuple(settings.filters[path]['pattern'])
    return cast(
        List[Pattern],
        settings.get_derived(
            ('regex', path, patterns),
            lambda: _compile_patterns(patterns),
        ),
    )


@lru_cache(maxsize=256)
def _compile_patterns(patterns: Tuple[str, ...]) -> List[Pattern]:
    return [re.compile(regex) for regex in patterns]


def clear_caches() -> None:
    _compile_patterns.cache_clear()
