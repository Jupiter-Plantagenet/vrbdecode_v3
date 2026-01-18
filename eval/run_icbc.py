import csv
import argparse
import json
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid
from typing import List, Dict, Optional


def run(cmd: List[str], cwd: Path, env: Dict[str, str]) -> str:
    p = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if p.returncode != 0:
        sys.stderr.write(f"\n[run_icbc] command failed (rc={p.returncode}): {' '.join(cmd)}\n")
        if (p.stdout or "").strip():
            sys.stderr.write("[run_icbc] --- stdout ---\n")
            sys.stderr.write(p.stdout)
            if not p.stdout.endswith("\n"):
                sys.stderr.write("\n")
        if (p.stderr or "").strip():
            sys.stderr.write("[run_icbc] --- stderr ---\n")
            sys.stderr.write(p.stderr)
            if not p.stderr.endswith("\n"):
                sys.stderr.write("\n")
        raise SystemExit(p.returncode)

    if (p.stderr or "").strip():
        sys.stderr.write(p.stderr)
        if not p.stderr.endswith("\n"):
            sys.stderr.write("\n")

    return p.stdout.strip()


def run_decider_with_retries(root: Path, steps: str, max_attempts: int = 5) -> List[Dict]:
    base_env = dict(os.environ)
    base_env["CARGO_INCREMENTAL"] = "0"
    base_env["CARGO_BUILD_JOBS"] = "1"
    base_env["VRBDECODE_BENCH_PROGRESS"] = base_env.get("VRBDECODE_BENCH_PROGRESS", "1")

    base_target = root / "target_eval_release"
    stable_target = base_target / "icbc_cache"

    last_err: Optional[BaseException] = None
    for attempt in range(1, max_attempts + 1):
        env = dict(base_env)
        if attempt == 1:
            env["CARGO_TARGET_DIR"] = str(stable_target)
        else:
            env["CARGO_TARGET_DIR"] = str(base_target / f"icbc_run_{attempt}_{uuid.uuid4().hex}")
        try:
            out = run(
                [
                    "cargo",
                    "run",
                    "-j",
                    "1",
                    "--release",
                    "-p",
                    "vrbdecode-zk",
                    "--bin",
                    "decider_evm",
                    "--",
                    "--json",
                    "--progress",
                    "--steps",
                    steps,
                ],
                cwd=root,
                env=env,
            )
            return json.loads(out)
        except BaseException as e:
            last_err = e
            sleep_s = min(30, 5 * attempt)
            sys.stderr.write(
                f"\n[run_icbc] attempt {attempt}/{max_attempts} failed; retrying in {sleep_s}s...\n"
            )
            time.sleep(sleep_s)

    raise last_err if last_err is not None else SystemExit(1)


def write_csv(path: Path, rows: List[Dict], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fieldnames})


def main() -> int:
    root = Path(__file__).resolve().parent.parent

    p = argparse.ArgumentParser()
    p.add_argument("--steps", default=None)
    p.add_argument("--max-attempts", type=int, default=5)
    args = p.parse_args()

    steps = (
        (args.steps or "").strip()
        or os.environ.get("VRBDECODE_ICBC_STEPS", "").strip()
        or "32"
    )

    rows = run_decider_with_retries(root, steps, max_attempts=args.max_attempts)

    out = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "steps": steps,
        "results": rows,
    }

    eval_dir = root / "eval"
    json_path = eval_dir / "icbc_decider_evm.json"
    json_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    csv_path = eval_dir / "icbc_decider_evm.csv"
    write_csv(
        csv_path,
        rows,
        [
            "k",
            "n_steps",
            "avg_step_time_s",
            "total_fold_time_s",
            "decider_prove_time_s",
            "proof_calldata_bytes",
            "evm_verify_ok",
            "evm_gas_used",
        ],
    )

    print(str(json_path))
    print(str(csv_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
