import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class StepRow:
    k: int
    step_circuit_constraints: int
    step_circuit_gen_time_s: Optional[float]
    step_fcircuit_constraints: int
    step_fcircuit_gen_time_s: Optional[float]


@dataclass(frozen=True)
class NovaRow:
    k: int
    n_steps: int
    avg_step_time_s: Optional[float]
    total_fold_time_s: Optional[float]
    verify_time_s: Optional[float]
    proof_size_bytes: Optional[int]
    peak_rss_kb: Optional[int]
    preprocess_time_s: Optional[float]


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


def load_step(path: Path) -> List[StepRow]:
    rows = _read_csv_rows(path)
    out: List[StepRow] = []
    for r in rows:
        k = _to_int(r.get("k"))
        scc = _to_int(r.get("step_circuit_constraints"))
        sct = _to_float(r.get("step_circuit_gen_time_s"))
        sfc = _to_int(r.get("step_fcircuit_constraints"))
        sft = _to_float(r.get("step_fcircuit_gen_time_s"))
        if k is None or scc is None or sfc is None:
            continue
        out.append(
            StepRow(
                k=k,
                step_circuit_constraints=scc,
                step_circuit_gen_time_s=sct,
                step_fcircuit_constraints=sfc,
                step_fcircuit_gen_time_s=sft,
            )
        )
    out.sort(key=lambda x: x.k)
    return out


def load_nova(path: Path, allowed_ns: Optional[List[int]] = None) -> List[NovaRow]:
    rows = _read_csv_rows(path)
    allowed = set(allowed_ns or []) if allowed_ns else None
    out: List[NovaRow] = []
    for r in rows:
        k = _to_int(r.get("k"))
        n_steps = _to_int(r.get("n_steps"))
        if k is None or n_steps is None:
            continue
        if allowed is not None and n_steps not in allowed:
            continue
        out.append(
            NovaRow(
                k=k,
                n_steps=n_steps,
                avg_step_time_s=_to_float(r.get("avg_step_time_s")),
                total_fold_time_s=_to_float(r.get("total_fold_time_s")),
                verify_time_s=_to_float(r.get("verify_time_s")),
                proof_size_bytes=_to_int(r.get("proof_size_bytes")),
                peak_rss_kb=_to_int(r.get("peak_rss_kb")),
                preprocess_time_s=_to_float(r.get("preprocess_time_s")),
            )
        )
    out.sort(key=lambda x: (x.k, x.n_steps))
    return out


def _group_by_k_nova(rows: List[NovaRow]) -> Dict[int, List[NovaRow]]:
    out: Dict[int, List[NovaRow]] = {}
    for r in rows:
        out.setdefault(r.k, []).append(r)
    for k in list(out.keys()):
        out[k].sort(key=lambda x: x.n_steps)
    return out


def _ensure_matplotlib() -> Tuple[Any, Any, Any, Any]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    from matplotlib.patches import FancyArrowPatch

    return matplotlib, plt, FancyBboxPatch, FancyArrowPatch


def _save(fig: Any, out_base: Path) -> None:
    out_base.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(out_base.with_suffix(".pdf")), bbox_inches="tight")
    fig.savefig(str(out_base.with_suffix(".png")), dpi=250, bbox_inches="tight")


def fig_system_architecture(out_dir: Path) -> None:
    _, plt, FancyBboxPatch, FancyArrowPatch = _ensure_matplotlib()

    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5)
    ax.axis("off")

    def box(x: float, y: float, w: float, h: float, text: str, fc: str) -> Any:
        p = FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.2,rounding_size=0.12",
            linewidth=1.2,
            edgecolor="#2b2b2b",
            facecolor=fc,
        )
        ax.add_patch(p)
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=10)
        return p

    def arrow(x1: float, y1: float, x2: float, y2: float, text: str) -> None:
        a = FancyArrowPatch(
            (x1, y1),
            (x2, y2),
            arrowstyle="-|>",
            mutation_scale=12,
            linewidth=1.2,
            color="#2b2b2b",
        )
        ax.add_patch(a)
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.25, text, ha="center", va="center", fontsize=9)

    client = box(0.6, 2.8, 2.4, 1.3, "Client\n(request)", "#e6f2ff")
    provider = box(3.8, 2.6, 2.6, 1.7, "Provider\n(decoding + proof)", "#e9f7ef")
    auditor = box(7.2, 2.8, 2.3, 1.3, "Auditor/Verifier\n(check proof)", "#fff3cd")

    arrow(3.0, 3.45, 3.8, 3.45, "request_id,\npolicy_hash,\nseed_commit")
    arrow(6.4, 3.45, 7.2, 3.45, "tokens, proof,\nreceipt h_T")

    box(3.9, 0.8, 5.4, 1.2, "Receipt artifact: h_T commits to policy, randomness, candidate sets, and outputs", "#f8f9fa")
    a2 = FancyArrowPatch((5.1, 2.6), (5.1, 2.0), arrowstyle="-|>", mutation_scale=12, linewidth=1.2, color="#2b2b2b")
    ax.add_patch(a2)

    _save(fig, out_dir / "system_architecture")
    plt.close(fig)


def fig_decoding_pipeline(out_dir: Path) -> None:
    _, plt, FancyBboxPatch, FancyArrowPatch = _ensure_matplotlib()

    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5)
    ax.axis("off")

    def box(x: float, y: float, w: float, h: float, text: str, fc: str) -> None:
        p = FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.18,rounding_size=0.10",
            linewidth=1.1,
            edgecolor="#2b2b2b",
            facecolor=fc,
        )
        ax.add_patch(p)
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=8.5)

    def arrow(x1: float, y1: float, x2: float, y2: float) -> None:
        a = FancyArrowPatch(
            (x1, y1),
            (x2, y2),
            arrowstyle="-|>",
            mutation_scale=10,
            linewidth=1.1,
            color="#2b2b2b",
        )
        ax.add_patch(a)

    box(0.5, 3.4, 1.8, 1.0, "(token_id, logit)\nK candidates", "#e6f2ff")
    box(2.6, 3.4, 1.6, 1.0, "Fixed-point\nscaling", "#f8f9fa")
    box(4.5, 3.4, 1.6, 1.0, "Sort +\ntie-break", "#f8f9fa")
    box(6.4, 3.4, 1.4, 1.0, "Top-k", "#f8f9fa")
    box(8.1, 3.4, 1.4, 1.0, "Top-p", "#f8f9fa")

    arrow(2.3, 3.9, 2.6, 3.9)
    arrow(4.2, 3.9, 4.5, 3.9)
    arrow(6.1, 3.9, 6.4, 3.9)
    arrow(7.8, 3.9, 8.1, 3.9)

    box(2.0, 1.9, 2.3, 1.0, "Poseidon PRF\nU_t = H(request_id,\npolicy_hash, seed_commit, t)", "#fff3cd")
    box(4.7, 1.9, 1.8, 1.0, "Weights\n(exp approx)\nW_s", "#e9f7ef")
    box(6.9, 1.9, 2.3, 1.0, "Unbiased sample\nR = high64(U_t * W_s)\nselect y_t", "#e9f7ef")

    arrow(3.0, 3.4, 3.15, 2.9)
    arrow(5.3, 3.4, 5.3, 2.9)
    arrow(7.2, 3.4, 7.6, 2.9)

    box(3.1, 0.5, 3.8, 0.9, "Receipt update: h_t = Poseidon(h_{t-1}, ..., y_t, W_s, R)", "#f8d7da")
    a = FancyArrowPatch((8.05, 1.9), (6.85, 1.0), arrowstyle="-|>", mutation_scale=10, linewidth=1.1, color="#2b2b2b")
    ax.add_patch(a)

    _save(fig, out_dir / "decoding_pipeline")
    plt.close(fig)


def plot_constraints_vs_k(step_rows: List[StepRow], out_dir: Path) -> None:
    _, plt, _, _ = _ensure_matplotlib()

    ks = [r.k for r in step_rows]
    step_constraints = [r.step_circuit_constraints for r in step_rows]
    stepf_constraints = [r.step_fcircuit_constraints for r in step_rows]

    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    ax.plot(ks, step_constraints, marker="o", label="StepCircuit")
    ax.plot(ks, stepf_constraints, marker="o", label="StepFCircuit")
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("Constraints")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")

    _save(fig, out_dir / "constraints_vs_k")
    plt.close(fig)


def plot_nova_avg_step_time_vs_n(nova_rows: List[NovaRow], out_dir: Path) -> None:
    _, plt, _, _ = _ensure_matplotlib()

    by_k = _group_by_k_nova(nova_rows)
    fig, ax = plt.subplots(figsize=(5.2, 3.2))

    plotted = False
    for k, rows in sorted(by_k.items()):
        ns = [r.n_steps for r in rows]
        ys = [r.avg_step_time_s for r in rows]
        if not any(v is not None for v in ys):
            continue
        plotted = True
        ax.plot(ns, [v if v is not None else float("nan") for v in ys], marker="o", label=f"K={k}")

    if plotted:
        ax.set_xlabel("N (number of decoding steps)")
        ax.set_ylabel("Avg proving time per step (s)")
        ax.grid(True, alpha=0.3)
        ax.legend(loc="best")
        _save(fig, out_dir / "nova_avg_step_time_vs_n")

    plt.close(fig)


def plot_nova_peak_rss_vs_n(nova_rows: List[NovaRow], out_dir: Path) -> None:
    _, plt, _, _ = _ensure_matplotlib()

    by_k = _group_by_k_nova(nova_rows)
    fig, ax = plt.subplots(figsize=(5.2, 3.2))

    plotted = False
    for k, rows in sorted(by_k.items()):
        ns = [r.n_steps for r in rows]
        ys = [r.peak_rss_kb for r in rows]
        if not any(v is not None for v in ys):
            continue
        plotted = True
        ax.plot(ns, [v if v is not None else float("nan") for v in ys], marker="o", label=f"K={k}")

    if plotted:
        ax.set_xlabel("N (number of decoding steps)")
        ax.set_ylabel("Peak RSS (KiB)")
        ax.grid(True, alpha=0.3)
        ax.legend(loc="best")
        _save(fig, out_dir / "nova_peak_rss_vs_n")

    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--step-csv", default="eval/ict_express_step.csv")
    ap.add_argument("--nova-csv", default="eval/ict_express_nova.csv")
    ap.add_argument("--ns", default="32,64,128,256")
    ap.add_argument("--out-dir", default="paper/ict_express/figures")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent.parent
    step_csv = (root / args.step_csv).resolve()
    nova_csv = (root / args.nova_csv).resolve()
    out_dir = (root / args.out_dir).resolve()

    step_rows = load_step(step_csv)
    nova_rows = load_nova(nova_csv, allowed_ns=_parse_int_list(args.ns))

    fig_system_architecture(out_dir)
    fig_decoding_pipeline(out_dir)

    if step_rows:
        plot_constraints_vs_k(step_rows, out_dir)

    if nova_rows:
        plot_nova_avg_step_time_vs_n(nova_rows, out_dir)
        plot_nova_peak_rss_vs_n(nova_rows, out_dir)

    print(str(out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
