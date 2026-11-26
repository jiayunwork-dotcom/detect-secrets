import argparse
from typing import cast

from . import baseline
from ...settings import get_settings
from .common import initialize_plugin_settings


def add_scan_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'scan',
        help='Creates a baseline by scanning a repository for secrets.',
        description=(
            'Scans a repository for secrets in code. The generated output is compatible with '
            '`detect-secrets-hook --baseline`.'
        ),
    )

    _add_adhoc_scanning(parser)
    _add_pragma_scanning(parser)
    _add_initialize_baseline_options(parser)

    return cast(argparse.ArgumentParser, parser)


def _add_adhoc_scanning(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--string',
        nargs='?',
        const=True,
        help=(
            'Scans an individual string, and displays configured plugins\' verdict.'
        ),
    )


def _add_pragma_scanning(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--only-allowlisted',
        action='store_true',
        help=(
            'Only scans the lines that are flagged with `allowlist secret`. This helps '
            'verify that individual exceptions are indeed non-secrets.'
        ),
    )


def _add_initialize_baseline_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        'path',
        nargs='*',
        default=['.'],
        help=(
            'Scans the entire codebase and outputs a snapshot of '
            'currently identified secrets.'
        ),
    )

    group = parser.add_argument_group(title='scan options')
    group.add_argument(
        '--all-files',
        action='store_true',
        help='Scan all files recursively (as compared to only scanning git tracked files).',
    )
    baseline.add_baseline_option(
        cast(argparse.ArgumentParser, group),
        help='If provided, will update existing baseline by importing settings from it.',
    )
    group.add_argument(
        '--force-use-all-plugins',
        action='store_true',
        help=(
            'If a baseline is provided, detect-secrets will default to loading the plugins '
            'specified by that baseline. However, this may also mean it doesn\'t perform the '
            'scan with the latest plugins. If this flag is provided, it will always use the '
            'latest plugins'
        ),
    )
    group.add_argument(
        '--slim',
        action='store_true',
        help=(
            'Slim baselines are created with the intention of minimizing differences between '
            'commits. However, they are not compatible with the `audit` functionality, and '
            'slim baselines will need to be remade to be audited.'
        ),
    )
    group.add_argument(
        '--track-occurrences',
        action='store_true',
        help=(
            'Create an occurrence-tracked baseline. Multiple same-type/same-hash hits in one '
            'file are stored separately and reconciled with non-reversible position evidence. '
            'Updating an existing occurrence-tracked baseline with --baseline keeps this format.'
        ),
    )
    group.add_argument(
        '--staged',
        action='store_true',
        help=(
            'Scan a fixed snapshot of the Git staging area instead of the working tree. '
            'All stage-0 regular files staged at launch are scanned from their indexed blob '
            'contents, so concurrent `git add` calls and working-tree edits or deletions cannot '
            'change what is checked. The baseline is printed to stdout only.'
        ),
    )


def parse_args(args: argparse.Namespace) -> None:
    if args.action != 'scan':
        return

    if getattr(args, 'staged', False):
        if getattr(args, 'string', None):
            raise argparse.ArgumentTypeError(
                '--staged cannot be combined with --string: adhoc string scans do not '
                'operate on Git index contents.',
            )

        if getattr(args, 'only_allowlisted', False):
            raise argparse.ArgumentTypeError(
                '--staged cannot be combined with --only-allowlisted.',
            )

        # scan --baseline rewrites the baseline file on disk, which is forbidden
        # in --staged mode (frozen snapshot, stdout-only output).
        if getattr(args, 'baseline', None) is not None:
            raise argparse.ArgumentTypeError(
                '--staged scans always write a fresh baseline to stdout; updating a '
                'baseline file in place is not supported. Feed the output to '
                '`detect-secrets-hook --staged --baseline` instead.',
            )

    # NOTE: This is assumed to run *after* the baseline argument processor, and before
    # the plugin argument processor.
    if args.baseline is not None and args.force_use_all_plugins:
        get_settings().plugins.clear()
        initialize_plugin_settings(args)

    if getattr(args, 'track_occurrences', False) and getattr(args, 'slim', False):
        raise argparse.ArgumentTypeError(
            '--track-occurrences cannot be combined with --slim; occurrence baselines '
            'retain line coordinates for audit and continuation matching.',
        )

    if (
        getattr(args, 'track_occurrences', False)
        and args.baseline is not None
        and not getattr(args.baseline, 'occurrence_tracking', False)
    ):
        raise argparse.ArgumentTypeError(
            '--track-occurrences cannot migrate a legacy baseline. Create a new '
            'occurrence-tracked baseline file instead.',
        )
