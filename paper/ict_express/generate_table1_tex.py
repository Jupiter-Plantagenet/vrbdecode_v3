import argparse
import csv
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _parse_int_list(s: str) -> List[int]:
    return [int(x.strip()) for x in s.split(",") if x.strip()]


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(float(s))
    except ValueError:
        return None


def _to_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise SystemExit(f"missing input: {path}")
    with path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        return list(r)


def _fmt_int(v: Optional[int]) -> str:
    if v is None:
        return "--"
    return f"{v:,}"


def _fmt_float(v: Optional[float], nd: int = 4) -> str:
    if v is None:
        return "--"
    return f"{v:.{nd}f}"


def _step_rows(step_csv: Path) -> List[Tuple[int, int, Optional[float], int, Optional[float]]]:
    rows = _read_csv_rows(step_csv)
    out: List[Tuple[int, int, Optional[float], int, Optional[float]]] = []
    for r in rows:
        k = _to_int(r.get("k"))
        scc = _to_int(r.get("step_circuit_constraints"))
        sct = _to_float(r.get("step_circuit_gen_time_s"))
        sfc = _to_int(r.get("step_fcircuit_constraints"))
        sft = _to_float(r.get("step_fcircuit_gen_time_s"))
        if k is None or scc is None or sfc is None:
            continue
        out.append((k, scc, sct, sfc, sft))
    out.sort(key=lambda x: x[0])
    return out


def _nova_rows_by_k(
    nova_csv: Path,
    allowed_ns: Optional[List[int]] = None,
) -> Dict[int, Tuple[Optional[float], List[Tuple[int, Optional[float], Optional[float], Optional[float], Optional[int]]]]]:
    rows = _read_csv_rows(nova_csv)
    allowed = set(allowed_ns or []) if allowed_ns else None
    parsed: List[
        Tuple[int, int, Optional[float], Optional[float], Optional[float], Optional[int], Optional[float]]
    ] = []
    for r in rows:
        k = _to_int(r.get("k"))
        n = _to_int(r.get("n_steps"))
        if k is None or n is None:
            continue
        if allowed is not None and n not in allowed:
            continue
        parsed.append(
            (
                k,
                n,
                _to_float(r.get("avg_step_time_s")),
                _to_float(r.get("total_fold_time_s")),
                _to_float(r.get("verify_time_s")),
                _to_int(r.get("proof_size_bytes")),
                _to_float(r.get("preprocess_time_s")),
            )
        )

    by_k: Dict[int, List[Tuple[int, Optional[float], Optional[float], Optional[float], Optional[int], Optional[float]]]] = {}
    for (k, n, avg, total, verify, size, preprocess) in parsed:
        by_k.setdefault(k, []).append((n, avg, total, verify, size, preprocess))

    out: Dict[
        int,
        Tuple[
            Optional[float],
            List[Tuple[int, Optional[float], Optional[float], Optional[float], Optional[int]]],
        ],
    ] = {}
    for k, rows_k in by_k.items():
        rows_k.sort(key=lambda x: x[0])
        preprocess_time = None
        for (_, _, _, _, _, p) in rows_k:
            if p is not None:
                preprocess_time = p
                break

        rows_out: List[Tuple[int, Optional[float], Optional[float], Optional[float], Optional[int]]] = []
        for (n, avg, total, verify, size, _) in rows_k:
            rows_out.append((n, avg, total, verify, size))
        out[k] = (preprocess_time, rows_out)

    return out


def build_table(step_csv: Path, nova_csv: Path, allowed_ns: Optional[List[int]] = None) -> str:
    step = _step_rows(step_csv)
    nova_by_k = _nova_rows_by_k(nova_csv, allowed_ns=allowed_ns)

    lines: List[str] = []
    lines.append("\\begin{table}[t]")
    lines.append("\\centering")
    lines.append("\\caption{Constraint counts and performance for verifiable decoding and folding.}")
    lines.append("\\label{tab:table1}")
    lines.append("\\small")
    lines.append("\\begin{tabular}{@{}rrrrr@{}}")
    lines.append("\\toprule")
    lines.append("$K$ & StepCircuit & Gen(s) & StepFCircuit & Gen(s)\\\\")
    lines.append("\\midrule")
    for (k, scc, sct, sfc, sft) in step:
        lines.append(
            f"{k} & {_fmt_int(scc)} & {_fmt_float(sct)} & {_fmt_int(sfc)} & {_fmt_float(sft)}\\\\"
        )
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("")
    lines.append("\\vspace{2mm}")
    lines.append("\\begin{tabular}{@{}rrrrrr@{}}")
    lines.append("\\toprule")
    lines.append("$K$ & Steps & Avg step(s) & Total(s) & Verify(s) & Size(bytes)\\\\")
    lines.append("\\midrule")
    for k in sorted(nova_by_k.keys()):
        preprocess, rows_k = nova_by_k[k]
        if preprocess is not None:
            lines.append(
                f"\\multicolumn{{6}}{{@{{}}l@{{}}}}{{K={k} preprocess time: {_fmt_float(preprocess)} s}}\\\\"
            )
        for (n, avg, total, verify, size) in rows_k:
            lines.append(
                f"{k} & {n} & {_fmt_float(avg)} & {_fmt_float(total)} & {_fmt_float(verify)} & {_fmt_int(size)}\\\\"
            )
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--step-csv", default="eval/ict_express_step.csv")
    ap.add_argument("--nova-csv", default="eval/ict_express_nova.csv")
    ap.add_argument("--ns", default="32,64,128,256")
    ap.add_argument("--out-tex", default="paper/ict_express/table1.tex")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent.parent
    step_csv = (root / args.step_csv).resolve()
    nova_csv = (root / args.nova_csv).resolve()
    out_tex = (root / args.out_tex).resolve()

    text = build_table(step_csv, nova_csv, allowed_ns=_parse_int_list(args.ns))
    out_tex.parent.mkdir(parents=True, exist_ok=True)
    out_tex.write_text(text, encoding="utf-8")

    print(str(out_tex))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
