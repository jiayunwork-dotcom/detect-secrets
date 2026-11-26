"""
Occurrence-aware identity and continuation matching for baselines.

The legacy baseline identity is ``(filename, secret type, secret hash)``.  That
is intentionally value-oriented, so several copies of the same secret in one
file collapse into one result.  This module adds an opt-in, position-aware
identity layer.

An occurrence id is only a stable label for a reviewed baseline entry.  It is
not, by itself, proof that a newly scanned line is the same occurrence.
Continuation is established from non-reversible, redacted local content
fingerprints.  When the evidence is absent or ambiguous, callers must not copy
a prior manual judgement to a new scan result.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import os
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field
from dataclasses import replace
from secrets import token_hex
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .secrets_collection import SecretsCollection


SCHEME = 'position-v1'
MARKER_KEY = 'occurrence_tracking'
ANCHOR_RADIUS = 5
MIN_CONTEXT_ANCHORS = 2
REDACTION = '\x00detect-secrets:redacted\x00'


def generate_fingerprint_key() -> str:
    """Return a baseline-local HMAC key for content fingerprints."""
    return token_hex(32)


def is_tracked_baseline(baseline: Dict[str, Any]) -> bool:
    marker = baseline.get(MARKER_KEY)
    return bool(marker)


@dataclass(frozen=True)
class OccurrenceIdentity:
    """Stable identity and continuation evidence for one hit."""

    id: str
    scheme: str = SCHEME
    continuity: str = 'tracked'
    evidence: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def generate(
        cls,
        continuity: str = 'new',
        evidence: Optional[Dict[str, Any]] = None,
    ) -> 'OccurrenceIdentity':
        return cls(
            id=f'occ_{token_hex(16)}',
            continuity=continuity,
            evidence=evidence or {},
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OccurrenceIdentity':
        if not isinstance(data, dict) or not data.get('id'):
            raise KeyError('occurrence.id')

        evidence = data.get('evidence') or {}
        if not isinstance(evidence, dict):
            raise KeyError('occurrence.evidence')

        return cls(
            id=str(data['id']),
            scheme=str(data.get('scheme', SCHEME)),
            continuity=str(data.get('continuity', 'tracked')),
            evidence=dict(evidence),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'scheme': self.scheme,
            'continuity': self.continuity,
            'evidence': self.evidence,
        }


@dataclass(frozen=True)
class OccurrenceMatch:
    old: Any
    current: Any
    updated: Any
    old_id: str
    current_id: str
    score: int
    confidence: str


@dataclass
class Reconciliation:
    updated: 'SecretsCollection'
    matched: 'SecretsCollection'
    new: 'SecretsCollection'
    matches: List[OccurrenceMatch]


def marker_for_output(secrets: 'SecretsCollection') -> Dict[str, Any]:
    if not secrets.fingerprint_key:
        secrets.fingerprint_key = generate_fingerprint_key()

    return {
        'scheme': SCHEME,
        'fingerprint_algorithm': 'HMAC-SHA256',
        'fingerprint_key': secrets.fingerprint_key,
        'anchor_radius': ANCHOR_RADIUS,
    }


def capture_evidence(collection: 'SecretsCollection') -> None:
    """
    Attach non-reversible continuation evidence to every scanned secret.

    Secret values discovered during the current scan are redacted before lines
    are fingerprinted.  Raw file/line contents are never placed in the baseline.
    """
    if not collection.occurrence_tracking:
        return

    if not collection.fingerprint_key:
        collection.fingerprint_key = generate_fingerprint_key()

    secret_values = _secret_values_by_file(collection)
    file_data = _read_file_fingerprints(collection)

    for filename, secret in collection:
        if secret.occurrence is None:
            # Scan collection insertion assigns identities before set insertion.
            # This branch keeps direct API use from creating an unkeyed result.
            secret.occurrence = OccurrenceIdentity.generate(continuity='candidate')

        if filename not in file_data:
            evidence = {
                'version': 1,
                'available': False,
            }
        else:
            lines, file_fingerprint = file_data[filename]
            evidence = build_evidence(
                lines=lines,
                line_number=secret.line_number,
                secret_values=secret_values.get(filename, []),
                fingerprint_key=collection.fingerprint_key,
                file_fingerprint=file_fingerprint,
            )

        secret.occurrence = replace(secret.occurrence, evidence=evidence)


def build_evidence(
    lines: List[str],
    line_number: int,
    secret_values: Iterable[str],
    fingerprint_key: str,
    file_fingerprint: str,
) -> Dict[str, Any]:
    """Build the JSON-safe evidence for one location."""
    if not line_number or not 1 <= line_number <= len(lines):
        return {
            'version': 1,
            'available': False,
            'file_fingerprint': file_fingerprint,
            'line_count': len(lines),
        }

    values = list(secret_values)
    target_index = line_number - 1
    line_fingerprint = _line_fingerprint(
        lines[target_index],
        values,
        fingerprint_key,
    )

    anchors = []
    for offset in range(-ANCHOR_RADIUS, ANCHOR_RADIUS + 1):
        if offset == 0:
            continue

        index = target_index + offset
        if not 0 <= index < len(lines):
            continue

        anchors.append({
            'offset': offset,
            'fingerprint': _line_fingerprint(lines[index], values, fingerprint_key),
        })

    return {
        'version': 1,
        'available': True,
        'file_fingerprint': file_fingerprint,
        'line_count': len(lines),
        'line_fingerprint': line_fingerprint,
        'anchors': anchors,
        'anchor_radius': ANCHOR_RADIUS,
    }


def mark_tracked(collection: 'SecretsCollection') -> None:
    """Convert provisional scan identities to catalogued baseline identities."""
    if not collection.occurrence_tracking:
        return

    for _, secret in collection:
        if secret.occurrence is not None and secret.occurrence.continuity == 'candidate':
            secret.occurrence = replace(secret.occurrence, continuity='tracked')


def reconcile(
    current: 'SecretsCollection',
    previous: 'SecretsCollection',
) -> Reconciliation:
    """
    Match fresh findings to baseline occurrence ids using content evidence.

    Judgements are copied only for reciprocal, unique high-confidence matches.
    All other current findings receive their own identity and no judgement.
    """
    # Local import avoids a runtime import cycle.
    from .secrets_collection import SecretsCollection

    key = current.fingerprint_key or previous.fingerprint_key
    updated = SecretsCollection(
        root=current.root,
        occurrence_tracking=True,
        fingerprint_key=key,
    )
    matched = SecretsCollection(
        root=current.root,
        occurrence_tracking=True,
        fingerprint_key=key,
    )
    new = SecretsCollection(
        root=current.root,
        occurrence_tracking=True,
        fingerprint_key=key,
    )

    matches: List[OccurrenceMatch] = []

    for filename in sorted(current.files):
        current_groups = _group_by_detection_key(current[filename])
        previous_groups = _group_by_detection_key(
            previous.data.get(filename, set()),
        )

        for detection_key, current_secrets in current_groups.items():
            previous_secrets = previous_groups.get(detection_key, [])
            edges = _score_edges(previous_secrets, current_secrets)
            accepted = _select_unique_edges(edges)
            accepted_current_ids = {edge.current_id for edge in accepted}

            for edge in accepted:
                updated_secret = _copy_judgement(edge)
                edge = replace(edge, updated=updated_secret)
                matches.append(edge)
                updated.data[filename].add(updated_secret)
                matched.data[filename].add(updated_secret)

            for current_secret in current_secrets:
                current_id = _occurrence_id(current_secret)
                if current_id in accepted_current_ids:
                    continue

                updated_secret = copy.copy(current_secret)
                if updated_secret.occurrence is None:
                    updated_secret.occurrence = OccurrenceIdentity.generate(
                        continuity='tracked',
                    )

                updated_secret.occurrence = replace(
                    updated_secret.occurrence,
                    continuity='ambiguous'
                    if _has_plausible_edge(current_id, edges)
                    else 'tracked',
                )

                updated.data[filename].add(updated_secret)
                new.data[filename].add(updated_secret)

    return Reconciliation(
        updated=updated,
        matched=matched,
        new=new,
        matches=matches,
    )


def subtract_known(
    current: 'SecretsCollection',
    baseline: 'SecretsCollection',
) -> 'SecretsCollection':
    """Return current occurrences that cannot be assigned a baseline identity."""
    return reconcile(current, baseline).new


def merge_into(
    current: 'SecretsCollection',
    old_results: 'SecretsCollection',
) -> Reconciliation:
    """Replace a fresh scan's provisional identities with reconciled identities."""
    reconciliation = reconcile(current, old_results)
    current.data = reconciliation.updated.data
    current.occurrence_tracking = True
    if not current.fingerprint_key and old_results.fingerprint_key:
        current.fingerprint_key = old_results.fingerprint_key
    return reconciliation


def trim(
    baseline_collection: 'SecretsCollection',
    scanned_results: 'SecretsCollection',
    filelist: Optional[List[str]],
) -> None:
    """Occurrence-aware implementation of ``SecretsCollection.trim``."""
    # Local import avoids a runtime import cycle.
    from .secrets_collection import SecretsCollection

    fileset = set(filelist or [])
    reconciliation = reconcile(scanned_results, baseline_collection)
    result = SecretsCollection(
        root=baseline_collection.root,
        occurrence_tracking=True,
        fingerprint_key=baseline_collection.fingerprint_key,
    )

    for match in reconciliation.matches:
        filename = match.updated.filename
        result.data[filename].add(match.updated)

    for filename in baseline_collection.files:
        if filename in result.files:
            continue

        # A scanned file with no surviving match means the occurrence is gone or
        # its identity is no longer trusted.  An explicitly scanned clean file
        # list also allows removal.  Files not touched by this invocation are
        # retained unchanged.
        if filename in scanned_results.files or filename in fileset:
            continue

        result.data[filename] = baseline_collection.data[filename]

    baseline_collection.data = result.data


def same_detected_value(a: Any, b: Any) -> bool:
    """
    Compare plugin-level detection identity without claiming occurrence identity.

    Audit uses the requested line number as the location evidence; occurrence ids
    are baseline labels and are not present on freshly yielded plugin results.
    """
    return (
        getattr(a, 'filename', None) == getattr(b, 'filename', None)
        and getattr(a, 'type', None) == getattr(b, 'type', None)
        and getattr(a, 'secret_hash', None) == getattr(b, 'secret_hash', None)
    )


def _secret_values_by_file(
    collection: 'SecretsCollection',
) -> Dict[str, List[str]]:
    values: Dict[str, List[str]] = defaultdict(list)
    for filename, secret in collection:
        if secret.secret_value:
            values[filename].append(secret.secret_value)
    return values


def _read_file_fingerprints(
    collection: 'SecretsCollection',
) -> Dict[str, Tuple[List[str], str]]:
    cache: Dict[str, Tuple[List[str], str]] = {}
    key = collection.fingerprint_key or generate_fingerprint_key()

    for filename in collection.files:
        path = os.path.join(collection.root, filename) if collection.root else filename
        try:
            with open(path, 'rb') as f:
                raw = f.read()
            lines = raw.decode('utf-8').splitlines()
        except (OSError, UnicodeError):
            continue

        cache[filename] = (
            lines,
            _digest(key, 'file-bytes', raw),
        )

    return cache


def _line_fingerprint(
    line: str,
    secret_values: Iterable[str],
    fingerprint_key: str,
) -> str:
    redacted = _redact_secret_values(line, secret_values)
    return _digest(fingerprint_key, 'redacted-line', redacted)


def _redact_secret_values(line: str, secret_values: Iterable[str]) -> str:
    result = line.rstrip()
    for value in sorted(
        {value for value in secret_values if value},
        key=len,
        reverse=True,
    ):
        result = result.replace(value, REDACTION)
    return result


def _digest(key: str, domain: str, value: Any) -> str:
    if isinstance(value, str):
        value = value.encode('utf-8')
    message = domain.encode('utf-8') + b'\0' + value
    return hmac.new(str(key).encode('utf-8'), message, hashlib.sha256).hexdigest()


def _group_by_detection_key(
    secrets: Iterable[Any],
) -> Dict[Tuple[str, str], List[Any]]:
    groups: Dict[Tuple[str, str], List[Any]] = defaultdict(list)
    for secret in secrets:
        groups[(secret.type, secret.secret_hash)].append(secret)

    for values in groups.values():
        values.sort(key=lambda item: (item.line_number or 0, _occurrence_id(item)))

    return dict(groups)


def _score_edges(
    old_secrets: List[Any],
    current_secrets: List[Any],
) -> List[OccurrenceMatch]:
    edges = []
    for old in old_secrets:
        for current in current_secrets:
            score, confidence = _score_pair(old, current)
            if score <= 0:
                continue

            edges.append(OccurrenceMatch(
                old=old,
                current=current,
                updated=current,
                old_id=_occurrence_id(old),
                current_id=_occurrence_id(current),
                score=score,
                confidence=confidence,
            ))
    return edges


def _score_pair(old: Any, current: Any) -> Tuple[int, str]:
    old_evidence = getattr(old, 'occurrence', None)
    current_evidence = getattr(current, 'occurrence', None)
    if old_evidence is None or current_evidence is None:
        return 0, 'missing-occurrence'

    old_data = old_evidence.evidence or {}
    current_data = current_evidence.evidence or {}

    old_file = old_data.get('file_fingerprint')
    current_file = current_data.get('file_fingerprint')
    old_line_fp = old_data.get('line_fingerprint')
    current_line_fp = current_data.get('line_fingerprint')

    if (
        old_file
        and hmac.compare_digest(str(old_file), str(current_file or ''))
        and old.line_number
        and old.line_number == current.line_number
        and old_line_fp
        and hmac.compare_digest(str(old_line_fp), str(current_line_fp or ''))
    ):
        return 1000, 'unchanged-file-position'

    if not old_line_fp or not current_line_fp:
        return 0, 'missing-line-fingerprint'

    if not hmac.compare_digest(str(old_line_fp), str(current_line_fp)):
        return 0, 'line-content-changed'

    old_anchors = {
        anchor['offset']: anchor['fingerprint']
        for anchor in old_data.get('anchors', [])
        if isinstance(anchor, dict) and 'offset' in anchor and 'fingerprint' in anchor
    }
    current_anchors = {
        anchor['offset']: anchor['fingerprint']
        for anchor in current_data.get('anchors', [])
        if isinstance(anchor, dict) and 'offset' in anchor and 'fingerprint' in anchor
    }

    matching_anchors = sum(
        1
        for offset, fingerprint in old_anchors.items()
        if offset in current_anchors
        and hmac.compare_digest(str(fingerprint), str(current_anchors[offset]))
    )

    required = min(MIN_CONTEXT_ANCHORS, len(old_anchors))
    if required and matching_anchors >= required:
        return 10 + matching_anchors, 'local-anchor-continuity'

    return 0, 'insufficient-continuity'


def _select_unique_edges(edges: List[OccurrenceMatch]) -> List[OccurrenceMatch]:
    """
    Select safe one-to-one continuations.

    An unchanged-file coordinate match is authoritative because the whole-file
    fingerprint is identical. For edited files, any endpoint with more than one
    plausible local-neighborhood match is considered ambiguous: a stronger score
    does not prove which copy was moved/copied.
    """
    exact_edges = [
        edge for edge in edges
        if edge.confidence == 'unchanged-file-position'
    ]
    exact_old_ids = {edge.old_id for edge in exact_edges}
    exact_current_ids = {edge.current_id for edge in exact_edges}

    context_edges = [
        edge
        for edge in edges
        if edge.confidence != 'unchanged-file-position'
        and edge.old_id not in exact_old_ids
        and edge.current_id not in exact_current_ids
    ]

    old_degree: Dict[str, int] = defaultdict(int)
    current_degree: Dict[str, int] = defaultdict(int)
    for edge in context_edges:
        old_degree[edge.old_id] += 1
        current_degree[edge.current_id] += 1

    accepted = list(exact_edges)
    accepted.extend(
        edge
        for edge in context_edges
        if old_degree[edge.old_id] == 1
        and current_degree[edge.current_id] == 1
    )
    return accepted


def _has_plausible_edge(current_id: str, edges: List[OccurrenceMatch]) -> bool:
    return any(edge.current_id == current_id for edge in edges)


def _copy_judgement(edge: OccurrenceMatch) -> Any:
    current = edge.current
    old = edge.old
    updated = copy.copy(current)

    # A newer explicit result wins if one ever exists.  Normal scans leave the
    # fresh result unlabelled, so this copies the prior manual/audit judgement.
    if updated.is_secret is None:
        updated.is_secret = old.is_secret

    if not updated.is_verified:
        updated.is_verified = old.is_verified

    if old.occurrence is not None:
        evidence = old.occurrence.evidence
        if current.occurrence is not None and current.occurrence.evidence:
            evidence = current.occurrence.evidence

        updated.occurrence = replace(
            old.occurrence,
            evidence=evidence,
        )

    return updated


def _occurrence_id(secret: Any) -> str:
    if getattr(secret, 'occurrence', None) is not None:
        return str(secret.occurrence.id)
    # Defensive fallback for direct API objects.  Scan insertion normally
    # assigns an identity before the object enters a tracked set.
    return f'provisional-{id(secret)}'
