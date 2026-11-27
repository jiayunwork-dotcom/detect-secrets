import os
import string
from functools import lru_cache
from typing import Any
from typing import Dict
from typing import Optional
from typing import Union

from ...core.plugins import Plugin
from ...plugins.private_key import PrivateKeyDetector
from ...settings import get_settings
from ..util import compute_file_hash


Model = Any

_CONFIG_PATH = f'{__name__}.should_exclude_secret'


def is_feature_enabled() -> bool:
    try:
        from gibberish_detector import serializer  # noqa: F401
        return True
    except ImportError:
        return False


def initialize(model_path: Optional[str] = None, limit: float = 3.7) -> None:
    """
    Register a gibberish model for the current settings scope.

    :param limit: this limit was obtained through trial and error. Check out
        the original pull request for rationale.

    :raises: ValueError
    """
    path = model_path
    if not path:
        path = os.path.join(__path__[0], 'rfc.model')

    # Get (or build) the model.  The model is immutable once loaded, so it is
    # safe to share through the content-keyed cache below.  Configuration --
    # including which model and which threshold -- is stored per scope.
    get_model_for(path)

    config: Dict[str, Union[float, str]] = {
        'limit': limit,
    }
    if model_path:
        config['model'] = model_path
        config['file_hash'] = compute_file_hash(model_path)

    get_settings().filters[_CONFIG_PATH] = config


def should_exclude_secret(secret: str, plugin: Optional[Plugin] = None) -> bool:
    """
    :param plugin: optional, for easier testing. The dependency injection system
        will populate its proper value on complete runs.
    """
    # Private keys are actual words, so they will be a false negative.
    if isinstance(plugin, PrivateKeyDetector):
        return False

    # Through real-life experimentation, we discovered that the gibberish detector
    # works best with non-hex strings, since hex strings have a too limited charset
    # to fit our trained models. As such, we cannot make a deterministic decision
    # in such cases.
    if not (set(secret) - set(string.hexdigits + '-')):
        return False

    model = _get_configured_model()
    if not model.data or not model.charset:
        raise AssertionError('Attempting to use uninitialized gibberish model.')

    from gibberish_detector.detector import Detector
    detector = Detector(
        model=model,
        threshold=get_settings().filters[_CONFIG_PATH]['limit'],
    )

    # TODO: secret.lower() is only used currently, since the default model is only
    # trained with lower case letters. However, in the future, if people want to train
    # a model that is case-sensitive, we can figure out how to change this.
    # Unfortunately, it's not straight-forward to just remove the `.lower()` function call,
    # since if the string is *not* lowered (and the model expects it to be), the results
    # will be quite different.
    return not detector.is_gibberish(secret.lower())


def _get_configured_model() -> 'Model':
    """Return the model configured for the current scope."""
    settings = get_settings()
    config = settings.filters.get(_CONFIG_PATH) or {}
    model_path = config.get('model')
    path = model_path or os.path.join(__path__[0], 'rfc.model')
    return settings.get_derived(
        ('gibberish-model', path),
        lambda: get_model_for(path),
    )


@lru_cache(maxsize=4)
def get_model_for(model_path: str) -> 'Model':
    """
    Load (and memoize) the model at ``model_path``.

    The returned model is treated as immutable: ``should_exclude_secret`` only
    reads it.  Sharing it across scopes is therefore safe, and saves a ~0.5ms
    parse per scope.
    """
    from gibberish_detector import serializer
    from gibberish_detector.exceptions import ParsingError
    from gibberish_detector.model import Model as GibberishModel

    model = GibberishModel(charset='')
    with open(model_path) as f:
        try:
            model.update(serializer.deserialize(f.read()))
        except ParsingError:
            raise ValueError('Invalid model.')

    return model


def clear_caches() -> None:
    get_model_for.cache_clear()


# Backwards-compatible helpers.  The old API exposed a single process-wide model
# via ``get_model``; the engine now uses ``_get_configured_model``.  Tests call
# ``get_model`` and ``get_model.cache_clear()``, so preserve both.
def get_model() -> 'Model':
    configured = _get_configured_model()
    return configured


get_model.cache_clear = clear_caches      # type: ignore[attr-defined]
