from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Type

from ..log import log
from .util import get_mapping_from_secret_type_to_class
from .util import get_plugins_from_file
from .util import Plugin


def from_secret_type(secret_type: str, settings: Optional[Any] = None) -> Plugin:
    """
    :raises: TypeError
    """
    try:
        plugin_type = get_mapping_from_secret_type_to_class(settings)[secret_type]
    except KeyError:
        raise TypeError

    try:
        return cast(Plugin, plugin_type(**_get_config(_classname(plugin_type), settings)))
    except TypeError:
        log.error('Unable to initialize plugin!')
        raise


def from_plugin_classname(classname: str, settings: Optional[Any] = None) -> Plugin:
    """
    :raises: TypeError
    """
    try:
        plugin_mapping = get_mapping_from_secret_type_to_class(settings)
    except FileNotFoundError as e:
        log.error(f'Error: Failed to load `{classname}` plugin: {e}')
        log.error(
            'This error can occur when using a baseline that references a '
            'custom plugin with a path that does not exist.',
        )
        raise

    for initializer in plugin_mapping.values():
        if _classname(initializer) == classname:
            break
    else:
        log.error(f'Error: No such `{classname}` plugin to initialize.')
        log.error('Chances are you should run `pre-commit autoupdate`.')
        log.error(
            'This error can occur when using a baseline that was made by '
            'a newer detect-secrets version than the one running.',
        )
        raise TypeError

    try:
        return cast(Plugin, initializer(**_get_config(classname, settings)))
    except TypeError:
        log.error('Unable to initialize plugin!')
        raise


def from_file(filename: str) -> Iterable[Type[Plugin]]:
    """
    :raises: FileNotFoundError
    :raises: InvalidFile
    """
    output: List[Type[Plugin]] = []
    plugin_class: Type[Plugin]
    for plugin_class in get_plugins_from_file(filename):
        secret_type = plugin_class.secret_type  # type: ignore
        if secret_type in get_mapping_from_secret_type_to_class():
            log.info(f'Duplicate plugin detected: {plugin_class.__name__}. Skipping...')

        get_mapping_from_secret_type_to_class()[secret_type] = plugin_class
        output.append(plugin_class)

    return output


def _classname(initializer: Any) -> str:
    return str(getattr(initializer, '__name__', ''))


def _get_config(classname: str, settings: Optional[Any] = None) -> Dict[str, Any]:
    if settings is None:
        from ...settings import get_settings
        settings = get_settings()

    output = {**settings.plugins.get(classname, {})}

    # External plugins use this key to specify the source. However, this key is not an
    # initialization variable. Therefore, let's remove it when initializing this config.
    if 'path' in output:
        output.pop('path')

    return output
