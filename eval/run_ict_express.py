import argparse
import csv
import json
import os
import subprocess
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _parse_int_list(s: str) -> List[int]:
    return [int(x.strip()) for x in s.split(",") if x.strip()]


def _bin_path(target_dir: Path, name: str) -> Path:
    suffix = ".exe" if sys.platform.startswith("win") else ""
    return target_dir / "release" / f"{name}{suffix}"


def _mean(xs: List[float]) -> Optional[float]:
    if not xs:
        return None
    return float(sum(xs)) / float(len(xs))


def _stdev(xs: List[float]) -> Optional[float]:
    if len(xs) < 2:
        return None
    return float(statistics.stdev(xs))


def _aggregate(rows: List[Dict], key_fields: List[str], metric_fields: List[str], int_metrics: List[str]) -> List[Dict]:
    grouped: Dict[Tuple, List[Dict]] = {}
    for r in rows:
        key = tuple(r.get(k) for k in key_fields)
        grouped.setdefault(key, []).append(r)

    out: List[Dict] = []
    for key, rs in grouped.items():
        agg: Dict = {}
        for i, kf in enumerate(key_fields):
            agg[kf] = key[i]
        agg["reps"] = len(rs)

        for mf in metric_fields:
            vals: List[float] = []
            for r in rs:
                v = r.get(mf)
                if isinstance(v, (int, float)):
                    vals.append(float(v))
            mu = _mean(vals)
            sd = _stdev(vals)
            if mu is None:
                agg[mf] = None
                agg[f"{mf}_std"] = None
                continue
            if mf in int_metrics:
                agg[mf] = int(round(mu))
            else:
                agg[mf] = mu
            agg[f"{mf}_std"] = sd

        out.append(agg)

    out.sort(key=lambda r: tuple(r.get(k) for k in key_fields))
    return out


def run(cmd: List[str], cwd: Path, env: Dict[str, str]) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        sys.stderr.write(f"\n[run_ict_express] command failed (rc={p.returncode}): {' '.join(cmd)}\n")
        if (p.stdout or "").strip():
            sys.stderr.write("[run_ict_express] --- stdout ---\n")
            sys.stderr.write(p.stdout)
            if not p.stdout.endswith("\n"):
                sys.stderr.write("\n")
        if (p.stderr or "").strip():
            sys.stderr.write("[run_ict_express] --- stderr ---\n")
            sys.stderr.write(p.stderr)
            if not p.stderr.endswith("\n"):
                sys.stderr.write("\n")
        raise SystemExit(p.returncode)
    if (p.stderr or "").strip():
        sys.stderr.write(p.stderr)
        if not p.stderr.endswith("\n"):
            sys.stderr.write("\n")
    return p.stdout.strip()


def write_csv(path: Path, rows: List[Dict], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fieldnames})


def run_with_retries(
    root: Path,
    ks: List[int],
    ns: List[int],
    reps: int,
    max_attempts: int = 3,
) -> Tuple[List[Dict], List[Dict], List[Dict], List[Dict]]:
    base_env = dict(os.environ)
    base_env["CARGO_INCREMENTAL"] = "0"
    base_env["CARGO_BUILD_JOBS"] = "1"
    base_env["RAYON_NUM_THREADS"] = "1"

    base_target = root / "target_eval_release"

    last_err: Optional[BaseException] = None
    for attempt in range(1, max_attempts + 1):
        env = dict(base_env)
        env["CARGO_TARGET_DIR"] = str(base_target / f"ict_{attempt}_{uuid.uuid4().hex}")
        try:
            run(
                [
                    "cargo",
                    "build",
                    "--release",
                    "-p",
                    "vrbdecode-zk",
                    "--bin",
                    "bench_step",
                    "--bin",
                    "bench_nova",
                ],
                cwd=root,
                env=env,
            )

            target_dir = Path(env["CARGO_TARGET_DIR"])
            bench_step_bin = _bin_path(target_dir, "bench_step")
            bench_nova_bin = _bin_path(target_dir, "bench_nova")

            step_raw_rows: List[Dict] = []
            for rep in range(reps):
                bench_step_out = run(
                    [str(bench_step_bin), "--json"],
                    cwd=root,
                    env=env,
                )
                rows = json.loads(bench_step_out)
                for r in rows:
                    row = dict(r)
                    row["rep"] = rep
                    step_raw_rows.append(row)

            step_rows = _aggregate(
                step_raw_rows,
                key_fields=["k"],
                metric_fields=[
                    "step_circuit_constraints",
                    "step_circuit_gen_time_s",
                    "step_fcircuit_constraints",
                    "step_fcircuit_gen_time_s",
                ],
                int_metrics=["step_circuit_constraints", "step_fcircuit_constraints"],
            )

            nova_raw_rows: List[Dict] = []
            steps_arg = ",".join(str(x) for x in ns)
            for k in ks:
                for rep in range(reps):
                    nova_out_s = run(
                        [
                            str(bench_nova_bin),
                            "--json",
                            "--progress",
                            "--k",
                            str(k),
                            "--steps",
                            steps_arg,
                        ],
                        cwd=root,
                        env=env,
                    )
                    nova_out = json.loads(nova_out_s)
                    for r in nova_out.get("results", []):
                        row = dict(r)
                        row["k"] = k
                        row["rep"] = rep
                        row["attempt"] = attempt
                        row["preprocess_time_s"] = nova_out.get("preprocess_time_s")
                        nova_raw_rows.append(row)

            nova_rows = _aggregate(
                nova_raw_rows,
                key_fields=["k", "n_steps"],
                metric_fields=[
                    "avg_step_time_s",
                    "total_fold_time_s",
                    "proof_size_bytes",
                    "verify_time_s",
                    "peak_rss_kb",
                    "preprocess_time_s",
                ],
                int_metrics=["proof_size_bytes", "peak_rss_kb"],
            )

            return step_rows, nova_rows, step_raw_rows, nova_raw_rows
        except BaseException as e:
            last_err = e
            sys.stderr.write(f"\n[run_ict_express] attempt {attempt}/{max_attempts} failed; retrying...\n")
            time.sleep(2)

    raise last_err if last_err is not None else SystemExit(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ks", default="16,32,64")
    ap.add_argument("--ns", default="32,64,128,256")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--attempts", type=int, default=3)
    args = ap.parse_args()

    ks = _parse_int_list(args.ks)
    ns = _parse_int_list(args.ns)

    root = Path(__file__).resolve().parent.parent

    step_rows, nova_rows, step_raw_rows, nova_raw_rows = run_with_retries(
        root,
        ks=ks,
        ns=ns,
        reps=args.reps,
        max_attempts=args.attempts,
    )

    out = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ks": ks,
        "ns": ns,
        "reps": args.reps,
        "bench_step": {"rows": step_rows, "raw_rows": step_raw_rows},
        "bench_nova": {"rows": nova_rows, "raw_rows": nova_raw_rows},
    }

    eval_dir = root / "eval"
    json_path = eval_dir / "ict_express.json"
    json_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    step_csv = eval_dir / "ict_express_step.csv"
    write_csv(
        step_csv,
        step_rows,
        [
            "k",
            "step_circuit_constraints",
            "step_circuit_gen_time_s",
            "step_circuit_gen_time_s_std",
            "step_fcircuit_constraints",
            "step_fcircuit_gen_time_s",
            "step_fcircuit_gen_time_s_std",
            "reps",
        ],
    )

    nova_csv = eval_dir / "ict_express_nova.csv"
    write_csv(
        nova_csv,
        nova_rows,
        [
            "k",
            "n_steps",
            "avg_step_time_s",
            "avg_step_time_s_std",
            "total_fold_time_s",
            "total_fold_time_s_std",
            "proof_size_bytes",
            "proof_size_bytes_std",
            "verify_time_s",
            "verify_time_s_std",
            "peak_rss_kb",
            "peak_rss_kb_std",
            "preprocess_time_s",
            "preprocess_time_s_std",
            "reps",
        ],
    )

    print(str(json_path))
    print(str(step_csv))
    print(str(nova_csv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
