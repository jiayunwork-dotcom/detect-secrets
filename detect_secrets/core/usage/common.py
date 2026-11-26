import argparse
import os

from ...settings import default_settings
from ...settings import get_settings


def valid_path(path: str) -> str:
    # In --staged mode, the frozen index snapshot -- not the working tree --
    # is the source of truth for file existence.  A staged path may have been
    # deleted or modified on disk after `git add`, so os.path.isfile alone is
    # not sufficient.
    from ...core import staged

    snapshot = staged.get_active_snapshot()
    if snapshot is not None:
        repo_relative = snapshot.resolve_repo_relative_path(path)
        if repo_relative is None:
            raise argparse.ArgumentTypeError(
                f'Invalid path: {path} (not present in the staged snapshot)',
            )

        return path

    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(
            f'Invalid path: {path}',
        )

    return path


def initialize_plugin_settings(args: argparse.Namespace) -> None:
    """
    This is a stand-in function, which should be replaced if baseline options are used.
    This ensures that our global settings object is initialized to a minimal state
    (all built-in plugins, default options)
    """
    # This is a sanity check to ensure we don't override any current settings.
    if get_settings().plugins:
        return

    # We initialize the `settings` variable here, but we can't save it to the global object
    # yet, since the contextmanager will revert those changes. As such, we quit the context
    # first, then set it to the global namespace.
    with default_settings() as settings:
        pass

    get_settings().set(settings)
