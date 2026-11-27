"""
Scope-aware settings for detect-secrets.

The engine used to rely on a single, process-wide ``Settings`` object which
``transient_settings`` mutated in place.  That works for a strictly sequential
CLI run, but it silently corrupts concurrent scans: one thread entering a
temporary configuration would overwrite the configuration another thread was
still scanning with, and the module level ``lru_cache``-d plugin/filter lookups
and derived artifacts (compiled regexes, word list automata, ...) were shared by
everybody.

This module replaces that with a *context-scoped* configuration built on
``contextvars``:

* ``get_settings()`` returns the ``Settings`` bound to the current execution
  context.  Contexts are per-thread and per-asyncio-task, so independent threads
  and interleaved tasks each see their own configuration.
* ``transient_settings()`` installs a brand new ``Settings`` object for the
  duration of the ``with`` block and restores the previously active object on
  exit -- including the exception and task-cancellation paths.  Because the
  object is new rather than mutated, an inner scope can never undo another
  scope's configuration.
* Configuration is also captured as an immutable *snapshot* in a second
  ``ContextVar``.  A task created inside a scope copies the snapshot at creation
  time, so it starts from the configuration that was active then; mutating the
  parent afterwards (or the child) publishes a fresh snapshot into that context
  only.  That is the copy-on-write boundary the bug report asks for.
* Plugin instances, filter functions and derived filter artifacts are cached
  *on the ``Settings`` instance they were derived from*.  Changing the config
  therefore changes the identity of the cache owner, so the actual filtering
  behaviour and the serialized policy always agree.

Expensive, immutable artifacts that depend only on their inputs (a tuple of
regex strings, a word list plus its minimum length and hash, a gibberish model
plus its hash) are shared through small content-keyed caches in the individual
filter modules.  Reusing them is safe because the key fully determines the
artifact, and it is much cheaper than rebuilding them for every scope.
"""
import contextvars
import threading
from contextlib import contextmanager
from copy import deepcopy
from importlib import import_module
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from urllib.parse import urlparse

from .exceptions import InvalidFile
from .util.importlib import import_file_as_module

# Sentinel for "no value bound in this execution context".
_UNSET: Any = object()

# Bumped whenever the process-wide plugin registry changes, so per-scope plugin
# mappings can be rebuilt lazily.
_PLUGIN_MAPPING_VERSION = 0


def _to_plain(value: Any) -> Any:
    """Recursively unwrap our invalidating dicts back into ordinary containers."""
    if isinstance(value, dict):
        return {key: _to_plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_to_plain(item) for item in value)
    return value


class _InvalidatingDict(dict):
    """
    A ``dict`` that notifies its owning ``Settings`` when it is mutated.

    Configuration happens through plain dict operations in many places (e.g.
    ``get_settings().plugins['X']['limit'] = 3``).  Wrapping the mappings means
    those in-place edits invalidate the cached plugin/filter derivations and
    refresh the context snapshot, so a configuration change can never leave a
    stale cache or a stale inheritance snapshot behind.
    """

    def __init__(
        self,
        *args: Any,
        on_change: Optional[Callable[[], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.on_change = on_change
        self._suppress = 0
        # Populate through __setitem__, so nested mappings get wrapped as well.
        self.update(dict(*args, **kwargs))

    def _wrap(self, value: Any) -> Any:
        if isinstance(value, _InvalidatingDict):
            value.on_change = self.on_change
            return value
        if isinstance(value, dict):
            return _InvalidatingDict(value, on_change=self.on_change)
        return value

    def _changed(self) -> None:
        if self.on_change is not None and not self._suppress:
            self.on_change()

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(key, self._wrap(value))
        self._changed()

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(key)
        self._changed()

    def clear(self) -> None:
        super().clear()
        self._changed()

    def pop(self, *args: Any) -> Any:
        output = super().pop(*args)
        self._changed()
        return output

    def popitem(self) -> Any:
        output = super().popitem()
        self._changed()
        return output

    def setdefault(self, key: Any, default: Any = None) -> Any:
        if key not in self:
            self[key] = default
        return self[key]

    def update(self, *args: Any, **kwargs: Any) -> None:
        # Batch the change notification: bulk updates (e.g. ``configure_filters``
        # installing dozens of entries) should publish a single snapshot, not one
        # per key.
        self._suppress += 1
        try:
            for key, value in dict(*args, **kwargs).items():
                self[key] = value
        finally:
            self._suppress -= 1
        self._changed()


class FrozenSettings:
    """
    An immutable snapshot of a configuration.

    ``ContextVar`` copies hold a reference to this object, never to a mutable
    ``Settings``.  Reconfiguring a scope publishes a *new* snapshot into that
    scope's context; other contexts that copied the old one are unaffected.
    """

    __slots__ = ('plugins', 'filters')

    def __init__(self, plugins: Dict[str, Any], filters: Dict[str, Any]) -> None:
        self.plugins = plugins
        self.filters = filters

    @classmethod
    def from_settings(cls, settings: 'Settings') -> 'FrozenSettings':
        return cls(
            deepcopy(_to_plain(settings.plugins)),
            deepcopy(_to_plain(settings.filters)),
        )


class _Binding:
    __slots__ = ('settings', 'identity')

    def __init__(self, settings: 'Settings', identity: Any) -> None:
        self.settings = settings
        self.identity = identity


# Two context variables:
#   * `_binding_var`    -> the materialized `Settings` for this context.
#   * `_snapshot_var`   -> the immutable config snapshot this context inherited.
# Both are copied into asyncio tasks at creation time and are independent for
# every thread, which gives us the inheritance / isolation boundaries we need.
_binding_var: Any = None
_snapshot_var: Any = None

# Process-wide default settings, used outside of any ``transient_settings``.
_GLOBAL_SETTINGS: Optional['Settings'] = None

_identity_local = threading.local()


def _init_contextvars() -> None:
    global _binding_var, _snapshot_var
    if _binding_var is None:
        _binding_var = contextvars.ContextVar('detect_secrets_settings_binding')
        _snapshot_var = contextvars.ContextVar('detect_secrets_settings_snapshot')


def _execution_identity() -> Any:
    """
    Identity of the current execution context: thread plus (optional) task.

    Cached per thread, keyed on the current task object, to keep the repeated
    lookups made during a scan cheap.  ``asyncio`` is imported lazily so the
    CLI does not pay its import cost for purely synchronous runs.
    """
    loop: Any
    try:
        import asyncio
        loop = asyncio.get_running_loop()
    except (ImportError, RuntimeError):
        return (threading.get_ident(), None)

    task = asyncio.current_task(loop)
    thread_id = threading.get_ident()

    cached = getattr(_identity_local, 'cache', None)
    identity = (thread_id, task)
    if cached is not None and cached[0] is task and cached[1] == thread_id:
        return cached[2]
    _identity_local.cache = (task, thread_id, identity)
    return identity


def _global_settings() -> 'Settings':
    global _GLOBAL_SETTINGS
    if _GLOBAL_SETTINGS is None:
        _GLOBAL_SETTINGS = Settings()
    return _GLOBAL_SETTINGS


def get_settings() -> 'Settings':
    """
    Return the settings for the current execution context.

    Outside of any ``transient_settings`` block (and in threads/tasks that never
    entered one) this is the process-wide default settings object, exactly like
    before.  Inside a scope -- or in a task that inherited one at creation time
    -- it is a ``Settings`` object private to this context.
    """
    _init_contextvars()

    binding = _binding_var.get(_UNSET)
    if binding is not _UNSET:
        identity = _execution_identity()
        if binding.identity == identity:
            return cast(Settings, binding.settings)

        # We inherited a *reference* to the parent context's binding.  Replace it
        # with a fresh settings object materialized from the inherited snapshot,
        # so this context can mutate freely without touching the parent.
        snapshot = _snapshot_var.get(_UNSET)
        settings = Settings.materialize(snapshot) if snapshot is not _UNSET else Settings()
        _install(settings, identity)
        return settings

    snapshot = _snapshot_var.get(_UNSET)
    if snapshot is _UNSET:
        return _global_settings()

    settings = Settings.materialize(snapshot)
    _install(settings, _execution_identity())
    return settings


def _install(settings: 'Settings', identity: Any) -> None:
    """Bind ``settings`` to the current context and wire its snapshot publisher."""
    _binding_var.set(_Binding(settings, identity))
    settings._set_publisher(_make_publisher(settings, identity))


def _republish_active_snapshot() -> None:
    binding = _binding_var.get(_UNSET)
    if binding is _UNSET:
        return
    if binding.identity != _execution_identity():
        return
    _snapshot_var.set(FrozenSettings.from_settings(binding.settings))


def configure_settings_from_baseline(baseline: Dict[str, Any], filename: str = '') -> 'Settings':
    """
    Apply a baseline-shaped config to the *current* settings.

    Kept as a public entry point for backwards compatibility: baseline loading
    and multiprocessing workers rely on it configuring the ambient settings.

    :raises: KeyError
    """
    settings = get_settings()
    _configure_settings(settings, baseline, filename=filename)
    return settings


def _configure_settings(settings: 'Settings', baseline: Dict[str, Any], filename: str = '') -> None:
    if 'plugins_used' in baseline:
        settings.configure_plugins(baseline['plugins_used'])

    if 'filters_used' in baseline:
        settings.configure_filters(baseline['filters_used'])

        if 'detect_secrets.filters.wordlist.should_exclude_secret' in settings.filters:
            config = settings.filters['detect_secrets.filters.wordlist.should_exclude_secret']

            from detect_secrets import filters
            filters.wordlist.initialize(
                wordlist_filename=config['file_name'],
                min_length=config['min_length'],
                file_hash=config['file_hash'],
            )

        if 'detect_secrets.filters.gibberish.should_exclude_secret' in settings.filters:
            config = settings.filters['detect_secrets.filters.gibberish.should_exclude_secret']

            from detect_secrets import filters
            filters.gibberish.initialize(
                model_path=config.get('model'),
                limit=config['limit'],
            )

    if filename:
        settings.filters['detect_secrets.filters.common.is_baseline_file'] = {
            'filename': filename,
        }


@contextmanager
def default_settings() -> Generator['Settings', None, None]:
    """Convenience function to enable all plugins and default filters."""
    from .core.plugins.util import get_mapping_from_secret_type_to_class

    with transient_settings({
        'plugins_used': [
            {'name': plugin_type.__name__}
            for plugin_type in get_mapping_from_secret_type_to_class().values()
        ],
    }) as settings:
        yield settings


@contextmanager
def transient_settings(config: Dict[str, Any]) -> Generator['Settings', None, None]:
    """
    Install a temporary configuration scoped to the current execution context.

    A fresh ``Settings`` is created for this scope, so anything mutated inside it
    (including plugin/filter cache derivations) is discarded on exit.  The
    previously active bindings are restored directly -- no serialization round
    trip -- which makes nested scopes, exceptions and task cancellation all safe,
    and means a finishing scan can never undo another live scan's configuration.

    The configuration is additionally captured as an immutable snapshot in a
    context variable.  A task created while this scope is active copies that
    snapshot, so it starts from the creation-time configuration regardless of
    later mutations by either side.
    """
    _init_contextvars()

    new_settings = Settings()
    identity = _execution_identity()

    # Bind before configuring so that helpers which resolve ``get_settings()``
    # (e.g. ``filters.wordlist.initialize``) write into *this* scope.
    binding_token = _binding_var.set(_Binding(new_settings, identity))
    snapshot_token = _snapshot_var.set(_UNSET)

    try:
        _configure_settings(new_settings, config)

        # Capture the fully configured scope for inheritance, then start
        # publishing subsequent mutations into this context's snapshot.
        _snapshot_var.set(FrozenSettings.from_settings(new_settings))
        new_settings._set_publisher(_make_publisher(new_settings, identity))

        yield new_settings
    finally:
        _binding_var.reset(binding_token)
        _snapshot_var.reset(snapshot_token)
        # If an enclosing scope's settings were mutated from within this one,
        # refresh the restored context's snapshot so later task creation sees
        # the current configuration rather than a stale one.
        _republish_active_snapshot()


def _make_publisher(settings: 'Settings', identity: Any) -> Callable[[], None]:
    def publisher() -> None:
        binding = _binding_var.get(_UNSET)
        if binding is _UNSET or binding.settings is not settings:
            # Not the active settings in this context (e.g. an enclosing scope's
            # object mutated from within a nested one).
            return
        if binding.identity != _execution_identity():
            return
        _snapshot_var.set(FrozenSettings.from_settings(settings))

    return publisher


def reset_settings_for_testing() -> None:
    """Drop the ambient settings object and context binding (test helper)."""
    global _GLOBAL_SETTINGS
    global _PLUGIN_MAPPING_VERSION

    _init_contextvars()
    _binding_var.set(_UNSET)
    _snapshot_var.set(_UNSET)
    _GLOBAL_SETTINGS = None
    _PLUGIN_MAPPING_VERSION += 1
    _identity_local.cache = None


def cache_bust() -> None:
    """
    Invalidate every derived cache.

    Retained for backwards compatibility (the test harness and some callers use
    it as a blunt reset).  With context-scoped settings this only touches the
    current scope plus the shared content-keyed artifact caches.
    """
    get_settings().invalidate()

    from .core.plugins import util as plugin_util
    from .filters import common
    from .filters import gibberish
    from .filters import regex
    from .filters import wordlist

    plugin_util.clear_caches()
    common.clear_caches()
    gibberish.clear_caches()
    regex.clear_caches()
    wordlist.clear_caches()


def bump_plugin_mapping_version() -> None:
    """Signal that the process-wide plugin registry changed."""
    global _PLUGIN_MAPPING_VERSION
    _PLUGIN_MAPPING_VERSION += 1


class Settings:
    DEFAULT_FILTERS = {
        'detect_secrets.filters.common.is_invalid_file',
        'detect_secrets.filters.heuristic.is_non_text_file',
    }

    def __init__(self) -> None:
        self._plugins_cache: Optional[List[Any]] = None
        self._filters_cache: Optional[List[Any]] = None
        self._plugin_mapping: Optional[Dict[str, Any]] = None
        self._plugin_mapping_version = -1
        self._derived: Dict[Any, Any] = {}
        self._publisher: Optional[Callable[[], None]] = None
        self.clear()

    @classmethod
    def materialize(cls, snapshot: 'FrozenSettings') -> 'Settings':
        """Build a mutable settings object from an immutable snapshot."""
        settings = cls()
        settings.plugins = _InvalidatingDict(
            snapshot.plugins,
            on_change=settings._invalidate_plugins,
        )
        settings.filters = _InvalidatingDict(
            snapshot.filters,
            on_change=settings._invalidate_filters,
        )
        settings.invalidate()
        return settings

    # -- storage -----------------------------------------------------------

    def clear(self) -> None:
        # mapping of class names to initialization variables
        self.plugins: Dict[str, Dict[str, Any]] = _InvalidatingDict(
            on_change=self._invalidate_plugins,
        )

        # mapping of python import paths to configuration variables
        self.filters: Dict[str, Dict[str, Any]] = _InvalidatingDict(
            {
                path: {}
                for path in {
                    *self.DEFAULT_FILTERS,
                    'detect_secrets.filters.allowlist.is_line_allowlisted',
                    'detect_secrets.filters.heuristic.is_sequential_string',
                    'detect_secrets.filters.heuristic.is_potential_uuid',
                    'detect_secrets.filters.heuristic.is_likely_id_string',
                    'detect_secrets.filters.heuristic.is_templated_secret',
                    'detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign',
                    'detect_secrets.filters.heuristic.is_indirect_reference',
                    'detect_secrets.filters.heuristic.is_lock_file',
                    'detect_secrets.filters.heuristic.is_not_alphanumeric_string',
                    'detect_secrets.filters.heuristic.is_swagger_file',
                }
            },
            on_change=self._invalidate_filters,
        )

        self.invalidate()

    def set(self, other: 'Settings') -> None:
        # Copy, rather than alias, so the two settings objects never share
        # mutable state.  The invalidating wrappers are rebuilt by update().
        self.plugins.clear()
        self.plugins.update(_to_plain(other.plugins))

        self.filters.clear()
        self.filters.update(_to_plain(other.filters))

    # -- invalidation ------------------------------------------------------

    def _set_publisher(self, publisher: Optional[Callable[[], None]]) -> None:
        self._publisher = publisher

    def _publish(self) -> None:
        if self._publisher is not None:
            self._publisher()

    def _invalidate_plugins(self) -> None:
        self._plugins_cache = None
        self._plugin_mapping = None
        self._publish()

    def _invalidate_filters(self) -> None:
        self._filters_cache = None
        # Derived filter artifacts (compiled regexes, automatons, baseline
        # filename, verification policy, ...) are cheap to recompute and must
        # always reflect this settings object.
        self._derived.clear()
        self._publish()

    def invalidate(self) -> None:
        self._invalidate_plugins()
        self._invalidate_filters()

    def get_derived(self, key: Any, factory: Callable[[], Any]) -> Any:
        """
        Per-scope memoization for derived values.

        The cache lives on, and dies with, this ``Settings`` object, so it is
        never shared with another scope.
        """
        try:
            return self._derived[key]
        except KeyError:
            value = factory()
            self._derived[key] = value
            return value

    # -- configuration -----------------------------------------------------

    def configure_plugins(self, config: List[Dict[str, Any]]) -> 'Settings':
        """
        :param config: e.g.
            [
                {'name': 'AWSKeyDetector'},
                {'limit': 4.5, 'name': 'Base64HighEntropyString'}
            ]
        """
        for plugin in config:
            plugin = {**plugin}
            name = plugin.pop('name')
            self.plugins[name] = plugin

        self._invalidate_plugins()
        return self

    def disable_plugins(self, *plugin_names: str) -> 'Settings':
        for name in plugin_names:
            try:
                self.plugins.pop(name)
            except KeyError:
                pass

        self._invalidate_plugins()
        return self

    def configure_filters(self, config: List[Dict[str, Any]]) -> 'Settings':
        """
        :param config: e.g.
            [
                {'path': 'detect_secrets.filters.heuristic.is_sequential_string'},
                {
                    'path': 'detect_secrets.filters.regex.should_exclude_files',
                    'pattern': '^test.*',
                }
            ]
        """
        filters: Dict[str, Dict[str, Any]] = {
            path: {}
            for path in self.DEFAULT_FILTERS
        }

        # Make a copy, so we don't affect the original.
        filter_configs = deepcopy(_to_plain(config))
        for filter_config in filter_configs:
            path = filter_config['path']
            filters[path] = filter_config

        self.filters.clear()
        self.filters.update(filters)
        self._invalidate_filters()
        return self

    def disable_filters(self, *filter_paths: str) -> 'Settings':
        for filter_path in filter_paths:
            self.filters.pop(filter_path, None)

        self._invalidate_filters()
        return self

    # -- materialization ---------------------------------------------------

    def get_plugin_mapping(self) -> Dict[str, Any]:
        """
        Map ``secret_type`` to a plugin initializer for this scope.

        Built-in classes are immutable code and are shared globally.  Custom
        plugin classes referenced by a ``path`` in this scope's config are
        resolved per-scope.  Initializers registered process-wide (e.g. by test
        helpers) overlay both.  The result is cached on this ``Settings`` object
        and rebuilt when the process-wide registry version changes.
        """
        from .core.plugins.util import get_builtin_mapping
        from .core.plugins.util import get_plugin_classes_from_file
        from .core.plugins.util import get_registered_plugin_initializers

        if (
            self._plugin_mapping is not None
            and self._plugin_mapping_version == _PLUGIN_MAPPING_VERSION
        ):
            return self._plugin_mapping

        mapping: Dict[str, Any] = dict(get_builtin_mapping())
        mapping.update(get_registered_plugin_initializers())

        # Load custom plugins referenced by the current configuration.
        for config in list(self.plugins.values()):
            path = config.get('path')
            if not path or not path.startswith('file://'):
                continue

            filename = path[len('file://'):]
            # NOTE: Import errors are allowed to propagate here. Baseline loading
            # relies on a FileNotFoundError surfacing (see issue #718) so it can
            # report the missing custom plugin path.
            classes: List[Any] = get_plugin_classes_from_file(filename)

            for plugin_class in classes:
                mapping[plugin_class.secret_type] = plugin_class

        self._plugin_mapping = mapping
        self._plugin_mapping_version = _PLUGIN_MAPPING_VERSION
        return mapping

    def get_plugins(self) -> List[Any]:
        if self._plugins_cache is None:
            # We need to import this here, otherwise it will result in a
            # circular dependency.
            from .core import plugins

            self._plugins_cache = [
                plugins.initialize.from_plugin_classname(classname, settings=self)
                for classname in list(self.plugins)
            ]

        return self._plugins_cache

    def get_filters(self) -> List[Any]:
        if self._filters_cache is None:
            from .core.log import log
            from .util.inject import get_injectable_variables

            output = []
            for path, config in list(self.filters.items()):
                parts = urlparse(path)
                if not parts.scheme:
                    module_path, function_name = path.rsplit('.', 1)
                    try:
                        function = getattr(import_module(module_path), function_name)
                    except (ModuleNotFoundError, AttributeError):
                        log.warning(f'Invalid filter: {path}')
                        continue

                elif parts.scheme == 'file':
                    file_path, function_name = path[len('file://'):].split('::')

                    try:
                        function = getattr(import_file_as_module(file_path), function_name)
                    except (FileNotFoundError, InvalidFile, AttributeError):
                        log.warning(f'Invalid filter: {path}')
                        continue

                else:
                    log.warning(f'Invalid filter: {path}')
                    continue

                # We attach this metadata to the function itself, so that we
                # don't need to compute it every time. This allows dependency
                # injection for filters.
                function.injectable_variables = set(get_injectable_variables(function))
                output.append(function)

                # This is for better logging.
                function.path = path

            self._filters_cache = output

        return self._filters_cache

    def json(self) -> Dict[str, Any]:
        plugins_used = []
        for plugin in self.get_plugins():
            # NOTE: We use the initialized plugin's JSON representation (rather
            # than the configured settings) to deal with cases where plugins
            # define their own default variables that are not necessarily
            # carried through the settings object.
            serialized_plugin = plugin.json()

            plugins_used.append({
                # We want this to appear first.
                'name': serialized_plugin['name'],

                # NOTE: We still need to use the saved settings configuration
                # though, since there are keys specifically in the settings
                # object that we need to carry over (e.g. `path` for custom
                # plugins).
                **self.plugins[serialized_plugin['name']],

                # Finally, this comes last so that it overrides any values that
                # are saved in the settings object.
                **serialized_plugin,
            })

        return {
            'plugins_used': sorted(
                plugins_used,
                key=lambda x: str(x['name'].lower()),
            ),
            'filters_used': sorted(
                [
                    {
                        'path': path,
                        **config,
                    }
                    for path, config in self.filters.items()
                    if path not in self.DEFAULT_FILTERS
                ],
                key=lambda x: str(x['path'].lower()),
            ),
        }


def get_plugins() -> List[Any]:
    """Return the initialized plugins for the current settings scope."""
    return get_settings().get_plugins()


def get_filters() -> List[Any]:
    """Return the active filter functions for the current settings scope."""
    return get_settings().get_filters()
