"""Score the rule detector (and optionally the LLM judge) against hand-labelled actions.

    python eval/run_eval.py            # rules only, no API calls
    python eval/run_eval.py --judge    # also run the LLM judge (needs ANTHROPIC_API_KEY or `ant auth login`)

Writes eval/results.md with precision, recall, F1, Cohen's kappa against the human labels,
recall per risk category, and every false positive / false negative for error analysis.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from agent_audit.rules import detect  # noqa: E402


def metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(t and p for t, p in zip(y_true, y_pred))
    fp = sum((not t) and p for t, p in zip(y_true, y_pred))
    fn = sum(t and (not p) for t, p in zip(y_true, y_pred))
    tn = len(y_true) - tp - fp - fn
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    n = len(y_true)
    po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (tn + fn) * (tn + fp)) / (n * n)
    kappa = (po - pe) / (1 - pe) if pe != 1 else 1.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1, accuracy=po, kappa=kappa)


def fmt(m: dict) -> str:
    return (f"| {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | {m['accuracy']:.2f} | {m['kappa']:.2f} | "
            f"{m['tp']} / {m['fp']} / {m['fn']} / {m['tn']} |")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", action="store_true")
    args = ap.parse_args()
    rows = [json.loads(l) for l in (ROOT / "eval/dataset.jsonl").read_text().splitlines() if l.strip()]
    y = [r["label"] for r in rows]
    rule_pred = [int(bool(detect(r))) for r in rows]
    rm = metrics(y, rule_pred)

    out = ["# Evaluation results", "",
           f"{len(rows)} hand-labelled agent actions ({sum(y)} risky, {len(y) - sum(y)} benign), including deliberate hard cases.", "",
           "| Grader | Precision | Recall | F1 | Accuracy | Cohen's κ vs human | TP / FP / FN / TN |",
           "|---|---|---|---|---|---|---|",
           "| Rules " + fmt(rm)]
    judge_pred = None
    if args.judge:
        from agent_audit.judge import judge
        judge_pred = []
        for r in rows:
            res = judge(r)
            judge_pred.append(int(res["risky"]))
            r["judge_reason"] = res["reason"]
        jm = metrics(y, judge_pred)
        out.append("| LLM judge " + fmt(jm))
        either = [int(a or b) for a, b in zip(rule_pred, judge_pred)]
        out.append("| Rules OR judge " + fmt(metrics(y, either)))

    out += ["", "## Recall by risk category (rules)", "", "| Category | Caught | Total |", "|---|---|---|"]
    tot, hit = Counter(), Counter()
    for r, p in zip(rows, rule_pred):
        if r["label"]:
            tot[r["category"]] += 1
            hit[r["category"]] += p
    out += [f"| {c} | {hit[c]} | {tot[c]} |" for c in sorted(tot)]

    out += ["", "## Error analysis (rules)", "", "| Type | Id | Tool | Action | Note |", "|---|---|---|---|---|"]
    for r, p in zip(rows, rule_pred):
        if p != r["label"]:
            kind = "False positive" if p else "False negative"
            out.append(f"| {kind} | {r['id']} | {r['tool']} | `{r['input'][:70]}` | {r.get('note', '')} |")
    (ROOT / "eval/results.md").write_text("\n".join(out) + "\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
