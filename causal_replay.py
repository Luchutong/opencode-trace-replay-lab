"""Summarize paired rollouts of the fixed replay fixture."""

from math import sqrt
from random import Random
from statistics import mean


def wilson_rate(values):
    values = [value for value in values if value is not None]
    n = len(values)
    if not n:
        return {"numerator": 0, "denominator": 0, "rate": None, "ci95": None}
    count = sum(values)
    p = count / n
    z = 1.959963984540054
    scale = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / scale
    radius = z * sqrt((p * (1 - p) + z**2 / (4 * n)) / n) / scale
    return {
        "numerator": count,
        "denominator": n,
        "rate": p,
        "ci95": [max(0, center - radius), min(1, center + radius)],
    }


def paired_deltas(deltas, seed):
    if not deltas:
        return {"n": 0, "values": [], "mean": None, "bootstrap_ci95": None}
    interval = None
    if len(deltas) >= 2:
        rng = Random(seed)
        estimates = sorted(
            mean(rng.choices(deltas, k=len(deltas))) for _ in range(2000)
        )
        interval = [estimates[49], estimates[1949]]
    return {
        "n": len(deltas),
        "values": deltas,
        "mean": mean(deltas),
        "bootstrap_ci95": interval,
    }


def summarize(pairs, seed):
    comparable = [pair for pair in pairs if pair["comparable"]]
    result = {
        "requested_pairs": len(pairs),
        "comparable_pairs": len(comparable),
        "first_action_pair_match_rate": wilson_rate(
            a == b if a is not None and b is not None else None
            for pair in comparable
            for a, b in [
                (pair["a"]["first_action_sha256"], pair["b"]["first_action_sha256"])
            ]
        ),
        "answer_correct": {
            arm: wilson_rate(pair[arm]["answer_correct"] for pair in comparable)
            for arm in ("a", "b")
        },
        "paired_deltas_b_minus_a": {},
    }
    for metric in (
        "answer_correct",
        "request_count",
        "tool_call_count",
        "duration_seconds",
    ):
        deltas = [
            pair["b"][metric] - pair["a"][metric]
            for pair in comparable
            if pair["a"][metric] is not None and pair["b"][metric] is not None
        ]
        result["paired_deltas_b_minus_a"][metric] = paired_deltas(deltas, seed)
    return result
