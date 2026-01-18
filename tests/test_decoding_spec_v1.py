import json
import os
import sys
import subprocess

import pytest


ROOT = os.path.dirname(os.path.dirname(__file__))
REF_PY = os.path.join(ROOT, "ref", "python")
VECTORS = os.path.join(ROOT, "vectors")

sys.path.insert(0, REF_PY)

from decoding_ref import decode_step  # noqa: E402


def _ensure_vectors() -> None:
    golden = os.path.join(VECTORS, "golden.jsonl")
    randomized = os.path.join(VECTORS, "random.jsonl")
    if os.path.exists(golden) and os.path.exists(randomized):
        try:
            with open(golden, "r", encoding="utf-8") as f:
                if any('"tag":"policy_sensitive_v1"' in line for line in f):
                    return
        except OSError:
            pass

    script = os.path.join(REF_PY, "generate_vectors.py")
    subprocess.check_call(
        [
            sys.executable,
            script,
            "--out-dir",
            VECTORS,
            "--golden",
            "50",
            "--random",
            "1000",
            "--seed",
            "1",
        ]
    )


def _load_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def test_vectors_exist():
    _ensure_vectors()
    assert os.path.exists(os.path.join(VECTORS, "golden.jsonl"))
    assert os.path.exists(os.path.join(VECTORS, "random.jsonl"))


@pytest.mark.parametrize("name", ["golden.jsonl", "random.jsonl"])
def test_vector_set(name: str):
    _ensure_vectors()
    path = os.path.join(VECTORS, name)
    rows = list(_load_jsonl(path))
    assert len(rows) > 0

    for row in rows:
        res = decode_step(
            K=int(row["K"]),
            top_k=int(row["top_k"]),
            top_p_q16=int(row["top_p_q16"]),
            T_q16=int(row["T_q16"]),
            token_id=row["token_id"],
            logit_q16=row["logit_q16"],
            U_t=int(row["U_t"]),
        )
        exp = row["expected"]
        assert int(res.y) == int(exp["y"])
        assert int(res.Ws) == int(exp["Ws"])
        assert int(res.R) == int(exp["R"])


def test_negative_tamper_output_token_detectable():
    _ensure_vectors()
    path = os.path.join(VECTORS, "golden.jsonl")
    row = next(r for r in _load_jsonl(path) if r.get("tag") == "policy_sensitive_v1")

    exp = row["expected"]

    res = decode_step(
        K=int(row["K"]),
        top_k=int(row["top_k"]),
        top_p_q16=int(row["top_p_q16"]),
        T_q16=int(row["T_q16"]),
        token_id=row["token_id"],
        logit_q16=row["logit_q16"],
        U_t=int(row["U_t"]),
    )

    assert int(res.y) == int(exp["y"])
    assert int(res.Ws) == int(exp["Ws"])
    assert int(res.R) == int(exp["R"])

    claimed_y = (int(res.y) + 1) % 10_000_000
    assert claimed_y != int(exp["y"])


def test_negative_tamper_randomness_detectable_via_R():
    _ensure_vectors()
    path = os.path.join(VECTORS, "golden.jsonl")
    row = next(r for r in _load_jsonl(path) if r.get("tag") == "policy_sensitive_v1")

    exp = row["expected"]

    res1 = decode_step(
        K=int(row["K"]),
        top_k=int(row["top_k"]),
        top_p_q16=int(row["top_p_q16"]),
        T_q16=int(row["T_q16"]),
        token_id=row["token_id"],
        logit_q16=row["logit_q16"],
        U_t=int(row["U_t"]),
    )

    assert int(res1.y) == int(exp["y"])
    assert int(res1.Ws) == int(exp["Ws"])
    assert int(res1.R) == int(exp["R"])

    res2 = decode_step(
        K=int(row["K"]),
        top_k=int(row["top_k"]),
        top_p_q16=int(row["top_p_q16"]),
        T_q16=int(row["T_q16"]),
        token_id=row["token_id"],
        logit_q16=row["logit_q16"],
        U_t=(int(row["U_t"]) + 1) & 0xFFFFFFFFFFFFFFFF,
    )

    assert (int(res2.y), int(res2.Ws), int(res2.R)) != (
        int(exp["y"]),
        int(exp["Ws"]),
        int(exp["R"]),
    )


def test_negative_tamper_policy_parameters_mismatch_expected():
    _ensure_vectors()
    path = os.path.join(VECTORS, "golden.jsonl")
    row = next(r for r in _load_jsonl(path) if r.get("tag") == "policy_sensitive_v1")
    exp = row["expected"]

    res = decode_step(
        K=int(row["K"]),
        top_k=int(row["top_k"]),
        top_p_q16=min(int(row["top_p_q16"]) + 1, 65536),
        T_q16=int(row["T_q16"]),
        token_id=row["token_id"],
        logit_q16=row["logit_q16"],
        U_t=int(row["U_t"]),
    )

    assert (int(res.y), int(res.Ws), int(res.R)) != (
        int(exp["y"]),
        int(exp["Ws"]),
        int(exp["R"]),
    )
