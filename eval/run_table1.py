import csv
import json
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid
from typing import List, Dict, Tuple, Optional


def run(cmd: list[str], cwd: Path, env: dict[str, str]) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise SystemExit(p.returncode)
    return p.stdout.strip()


def run_table1_with_retries(root: Path, nova_steps: Optional[str], max_attempts: int = 5) -> Tuple[List[Dict], Dict]:
    base_env = dict(os.environ)
    base_env["CARGO_INCREMENTAL"] = "0"
    base_env["CARGO_BUILD_JOBS"] = "1"

    base_target = root / "target_eval_release"

    last_err: Optional[BaseException] = None
    for attempt in range(1, max_attempts + 1):
        env = dict(base_env)
        env["CARGO_TARGET_DIR"] = str(base_target / f"run_{attempt}_{uuid.uuid4().hex}")
        try:
            bench_step_out = run(
                ["cargo", "run", "--release", "-p", "vrbdecode-zk", "--bin", "bench_step", "--", "--json"],
                cwd=root,
                env=env,
            )
            step_rows = json.loads(bench_step_out)

            nova_cmd = [
                "cargo",
                "run",
                "--release",
                "-p",
                "vrbdecode-zk",
                "--bin",
                "bench_nova",
                "--",
                "--json",
                "--progress",
            ]
            if nova_steps is not None:
                nova_cmd.extend(["--steps", nova_steps])

            bench_nova_out = run(nova_cmd, cwd=root, env=env)
            nova_out = json.loads(bench_nova_out)
            return step_rows, nova_out
        except BaseException as e:
            last_err = e
            sys.stderr.write(f"\n[run_table1] attempt {attempt}/{max_attempts} failed; retrying...\n")
            time.sleep(2)

    raise last_err if last_err is not None else SystemExit(1)


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fieldnames})


def main() -> int:
    root = Path(__file__).resolve().parent.parent

    nova_steps = os.environ.get("VRBDECODE_BENCH_NOVA_STEPS")
    if nova_steps is not None:
        nova_steps = nova_steps.strip() or None

    step_rows, nova_out = run_table1_with_retries(root, nova_steps)

    out = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "bench_step": {"rows": step_rows},
        "bench_nova": nova_out,
    }

    eval_dir = root / "eval"
    json_path = eval_dir / "table1.json"
    json_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    step_csv = eval_dir / "table1_step.csv"
    write_csv(
        step_csv,
        step_rows,
        [
            "k",
            "step_circuit_constraints",
            "step_circuit_gen_time_s",
            "step_fcircuit_constraints",
            "step_fcircuit_gen_time_s",
        ],
    )

    nova_csv = eval_dir / "table1_nova.csv"
    write_csv(
        nova_csv,
        nova_out.get("results", []),
        ["n_steps", "avg_step_time_s", "total_fold_time_s", "proof_size_bytes", "verify_time_s"],
    )

    print(str(json_path))
    print(str(step_csv))
    print(str(nova_csv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
