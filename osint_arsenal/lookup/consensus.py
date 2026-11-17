from __future__ import annotations
from ..models import ModuleResult, Verdict, LookupKind, Status


CATEGORY_WEIGHTS = {
    "major": 1.0, "medium": 0.7, "forum": 0.5,
    "niche": 0.4, "uncategorized": 0.5,
}


def _weight(r: ModuleResult) -> float:
    base = CATEGORY_WEIGHTS.get(r.category, 0.5)
    return base * max(0.05, min(1.0, r.confidence))


def compute_verdict(kind: LookupKind, query: str,
                    results: list[ModuleResult]) -> Verdict:
    found = [r for r in results if r.status == Status.FOUND]
    not_found = [r for r in results if r.status == Status.NOT_FOUND]
    inconc = [r for r in results if r.status == Status.INCONCLUSIVE]
    errors = [r for r in results if r.status == Status.ERROR]

    w_found = sum(_weight(r) for r in found)
    w_not = sum(_weight(r) for r in not_found)
    w_inc = sum(_weight(r) for r in inconc)
    w_err = sum(_weight(r) for r in errors)

    denom = w_found + w_not
    k = 0.0
    shrunk = w_found / denom if denom else 0.0
    total = w_found + w_not + w_inc + w_err
    penalty = 1.0 - 0.3 * (w_inc + w_err) / total if total else 1.0
    score = max(0.0, min(1.0, shrunk * penalty))

    if score >= 0.7 and len(found) >= 3:
        label = "high"
    elif score >= 0.4 and len(found) >= 1:
        label = "medium"
    elif len(found) >= 1:
        label = "low"
    else:
        label = "insufficient"

    notes: list[str] = []
    if errors:
        notes.append(f"{len(errors)} module(s) errored")
    if inconc:
        notes.append(f"{len(inconc)} inconclusive — verify at source")
    if len(found) == 1:
        notes.append("Single match — weak evidence on its own")

    return Verdict(
        kind=kind, query=query, total_modules=len(results),
        checked=len(results), found=len(found), not_found=len(not_found),
        inconclusive=len(inconc), errors=len(errors),
        confidence=round(score, 3), label=label, notes=notes,
    )
