import argparse
import json
from typing import Any
from typing import cast
from typing import Dict

from .. import baseline
from ...exceptions import UnableToReadBaselineError
from .common import initialize_plugin_settings
from .common import valid_path


def add_baseline_option(parser: argparse.ArgumentParser, help: str) -> None:
    parser.add_argument(
        '--baseline',
        nargs=1,
        metavar='FILENAME',
        type=valid_path,
        help=help,
    )


def parse_args(args: argparse.Namespace) -> None:
    if not hasattr(args, 'baseline') or not args.baseline:
        return initialize_plugin_settings(args)

    baseline_filename = args.baseline[0]
    try:
        loaded_baseline = _load_baseline_contents(baseline_filename)
    except UnableToReadBaselineError:
        raise argparse.ArgumentTypeError('Unable to read baseline.')

    try:
        args.baseline_filename = baseline_filename
        args.baseline_version = loaded_baseline['version']
        args.baseline_is_occurrence_tracked = bool(
            loaded_baseline.get('occurrence_tracking'),
        )
        args.baseline = baseline.load(loaded_baseline, filename=baseline_filename)
    except KeyError:
        raise argparse.ArgumentTypeError('Invalid baseline.')


def _load_baseline_contents(baseline_filename: str) -> Dict[str, Any]:
    """
    In --staged mode the baseline itself is read from the same frozen index
    snapshot as the scanned files: an unstaged edit to the baseline must not
    influence this check, and a baseline deleted from the working tree after
    being staged must still be honored.
    """
    from ...core import staged

    snapshot = staged.get_active_snapshot()
    if snapshot is None:
        return baseline.load_from_file(baseline_filename)

    repo_relative = snapshot.resolve_repo_relative_path(baseline_filename)
    if repo_relative is None:
        # valid_path already rejected this, but keep the failure explicit.
        raise UnableToReadBaselineError

    try:
        contents = snapshot.read_bytes(repo_relative).decode('utf-8')
        return cast(Dict[str, Any], json.loads(contents))
    except (OSError, UnicodeError, json.decoder.JSONDecodeError):
        raise UnableToReadBaselineError
