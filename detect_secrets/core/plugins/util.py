import inspect
from abc import abstractproperty
from functools import lru_cache
from types import ModuleType
from typing import Any
from typing import cast
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Type
from typing import TypeVar

from ... import plugins
from ...plugins.base import BasePlugin
from ...util.importlib import import_file_as_module
from ...util.importlib import import_types_from_module
from ...util.importlib import import_types_from_package


Plugin = TypeVar('Plugin', bound=BasePlugin)

# Initializers registered process-wide (e.g. by test helpers through
# ``testing.plugins.register_plugin``).  These overlay the built-in mapping for
# every settings scope and are keyed by ``secret_type``.
_registered_plugin_initializers: Dict[str, Any] = {}


@lru_cache(maxsize=1)
def get_builtin_mapping() -> Dict[str, Type[Plugin]]:
    """Mapping of ``secret_type`` to class for the packaged detectors only."""
    output = {}
    for plugin_class in import_types_from_package(
        plugins,
        filter=lambda x: not _is_valid_plugin(x),
    ):
        output[plugin_class.secret_type] = plugin_class

    return output


def get_registered_plugin_initializers() -> Dict[str, Any]:
    return _registered_plugin_initializers


def register_plugin_initializer(secret_type: str, initializer: Any) -> None:
    from ...settings import bump_plugin_mapping_version

    _registered_plugin_initializers[secret_type] = initializer
    bump_plugin_mapping_version()


def unregister_plugin_initializer(secret_type: str) -> None:
    from ...settings import bump_plugin_mapping_version

    _registered_plugin_initializers.pop(secret_type, None)
    bump_plugin_mapping_version()


def clear_caches() -> None:
    """Reset the module-level registries and cached built-in mapping."""
    from ...settings import bump_plugin_mapping_version

    get_builtin_mapping.cache_clear()
    _registered_plugin_initializers.clear()
    bump_plugin_mapping_version()


def get_plugin_classes_from_file(filename: str) -> List[Type[Plugin]]:
    """
    Eagerly resolve plugin classes from a file.

    This is deliberately *not* a generator: import errors (``FileNotFoundError``,
    ``InvalidFile``) must surface at the call site so callers can report them,
    rather than during a later iteration.
    """
    return list(get_plugins_from_file(filename))


def get_mapping_from_secret_type_to_class(
    settings: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Return the ``secret_type`` -> initializer mapping for the given (or current) scope.

    Kept as a mutable mapping for backwards compatibility.  Writes are treated
    as process-wide plugin registrations (the historical
    ``mapping[secret_type] = class`` idiom keeps working).
    """
    from ...settings import get_settings

    settings = settings if settings is not None else get_settings()
    return _ScopeAwareMapping(settings.get_plugin_mapping())


class _ScopeAwareMapping(dict):
    """A dict view over a scope's plugin mapping with registering writes."""

    def __setitem__(self, secret_type: str, initializer: Any) -> None:
        super().__setitem__(secret_type, initializer)
        register_plugin_initializer(secret_type, initializer)

    def __delitem__(self, secret_type: str) -> None:
        super().__delitem__(secret_type)
        unregister_plugin_initializer(secret_type)

    def cache_clear(self) -> None:
        clear_caches()


# The old API was an ``lru_cache``-decorated function, so callers used
# ``get_mapping_from_secret_type_to_class.cache_clear()``.  Preserve that.
get_mapping_from_secret_type_to_class.cache_clear = clear_caches     # type: ignore[attr-defined]


def get_plugins_from_file(filename: str) -> Generator[Type[Plugin], None, None]:
    plugin_class: Type[Plugin]
    for plugin_class in get_plugins_from_module(import_file_as_module(filename)):
        yield plugin_class


def get_plugins_from_module(module: ModuleType) -> Generator[Type[Plugin], None, None]:
    for plugin_class in import_types_from_module(module, filter=lambda x: not _is_valid_plugin(x)):
        yield cast(Type[Plugin], plugin_class)


def _is_valid_plugin(attribute: Any) -> bool:
    return (
        inspect.isclass(attribute)
        and issubclass(attribute, BasePlugin)
        # Heuristic to determine abstract classes
        and not isinstance(attribute.secret_type, abstractproperty)
    )
