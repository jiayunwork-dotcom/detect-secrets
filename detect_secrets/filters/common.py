import os
from typing import cast

import requests

from ..constants import VerifiedResult
from ..core.plugins import Plugin
from ..settings import get_settings
from ..util.code_snippet import CodeSnippet
from ..util.inject import call_function_with_arguments

_BASELINE_FILE_PATH = f'{__name__}.is_baseline_file'
_VERIFICATION_POLICY_PATH = f'{__name__}.is_ignored_due_to_verification_policies'


def is_invalid_file(filename: str) -> bool:
    return not os.path.isfile(filename)


def is_baseline_file(filename: str) -> bool:
    return os.path.basename(filename) == _get_baseline_filename()


def _get_baseline_filename() -> str:
    """
    Resolve the configured basename from the *current* settings scope.

    The memo lives on the settings object (and is cleared whenever its filter
    config changes), so it can never leak a filename between concurrent scans.
    """
    settings = get_settings()
    return cast(
        str,
        settings.get_derived(
            ('baseline-filename',),
            lambda: settings.filters[_BASELINE_FILE_PATH]['filename'],
        ),
    )


def is_ignored_due_to_verification_policies(
    secret: str,
    plugin: Plugin,
    context: CodeSnippet,
) -> bool:
    """
    Valid policies include:
        - Only VERIFIED_TRUE
        - Can be UNVERIFIED or VERIFIED_TRUE
        - Disabled check.

    There's no such thing as "only verified false", because if you're going to verify
    something, and it's verified false, why are you still including it as a valid secret?
    """
    try:
        verify_result = call_function_with_arguments(
            plugin.verify,
            secret=secret,
            context=context,
        )
    except requests.exceptions.RequestException:
        verify_result = VerifiedResult.UNVERIFIED

    if not verify_result:
        return False

    if verify_result.value < _get_verification_policy().value:
        return True

    return False


def _get_verification_policy() -> VerifiedResult:
    settings = get_settings()
    return cast(
        VerifiedResult,
        settings.get_derived(
            ('verification-policy',),
            lambda: VerifiedResult(settings.filters[_VERIFICATION_POLICY_PATH]['min_level']),
        ),
    )


def clear_caches() -> None:
    """Backwards-compatible hook; caches are scope owned now."""
