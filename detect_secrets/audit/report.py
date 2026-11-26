from enum import Enum
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple

from ..constants import VerifiedResult
from .common import get_baseline_from_file
from .common import get_raw_secrets_from_file
from .common import LineGetter
from .common import open_file


class SecretClassToPrint(Enum):
    REAL_SECRET = 1
    FALSE_POSITIVE = 2

    @staticmethod
    def from_class(secret_class: VerifiedResult) -> 'SecretClassToPrint':
        if secret_class in [VerifiedResult.UNVERIFIED, VerifiedResult.VERIFIED_TRUE]:
            return SecretClassToPrint.REAL_SECRET
        else:
            return SecretClassToPrint.FALSE_POSITIVE


def generate_report(
    baseline_file: str,
    class_to_print: SecretClassToPrint = None,
    line_getter_factory: Callable[[str], 'LineGetter'] = open_file,
) -> Dict[str, List[Dict[str, Any]]]:

    secrets: Dict[Tuple[Any, ...], Any] = {}
    for filename, secret in get_baseline_from_file(baseline_file):
        verified_result = VerifiedResult.from_secret(secret)
        if (
            class_to_print is not None and
            SecretClassToPrint.from_class(verified_result) != class_to_print
        ):
            continue

        occurrence_id = secret.occurrence.id if secret.occurrence is not None else None
        if occurrence_id is not None:
            # Occurrence-tracked baselines must report each labelled location
            # separately. Preserve the line coordinate instead of scanning the
            # whole file and merging by value hash.
            detections = get_raw_secrets_from_file(secret)
            identity_key: Tuple[Any, ...] = ('occurrence', occurrence_id)
        else:
            # Removal of the stored line number is required to force the complete file scanning to obtain all the secret occurrences. # noqa: E501
            secret.line_number = 0
            detections = get_raw_secrets_from_file(secret)
            identity_key = (secret.secret_hash, filename)

        line_getter = line_getter_factory(filename)
        for detection in detections:
            if identity_key in secrets:
                secrets[identity_key]['lines'][detection.line_number] = line_getter.lines[detection.line_number - 1]  # noqa: E501
                if secret.type not in secrets[identity_key]['types']:
                    secrets[identity_key]['types'].append(secret.type)
                secrets[identity_key]['category'] = get_prioritized_verified_result(  # noqa: E501
                    verified_result,
                    VerifiedResult[secrets[identity_key]['category']],
                ).name
            else:
                entry = {
                    'secrets': detection.secret_value,
                    'filename': filename,
                    'lines': {
                        detection.line_number: line_getter.lines[detection.line_number - 1],
                    },
                    'types': [
                        secret.type,
                    ],
                    'category': verified_result.name,
                }
                if occurrence_id is not None:
                    entry['occurrence_id'] = occurrence_id
                secrets[identity_key] = entry
    return {
        'results': list(secrets.values()),
    }


def get_prioritized_verified_result(
    result1: VerifiedResult,
    result2: VerifiedResult,
) -> VerifiedResult:
    if result1.value > result2.value:
        return result1
    else:
        return result2
