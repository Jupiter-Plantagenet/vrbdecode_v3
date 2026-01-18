# Agent Implementation Guide (Codex / Windsurf / Antigravity)

This guide is designed to make AI coding agents succeed **even if they don't understand the research**.

## Principles (non-negotiable)
1) **Specs are law.** Agents MUST NOT change specs to make tests pass.
2) Everything must be proven by **tests + vectors + negative tests**.
3) Each milestone ends with a single command: `./ci.sh` (or GitHub Actions) is green.

## Milestones (do in order)

### M0 — Repo skeleton + CI
- Create the folder layout from README
- Add `ci.sh` that runs:
  - format/lint (optional)
  - unit tests for reference
  - randomized equivalence tests
  - folding E2E test (can be skipped in early commits)

### M1 — Python reference + vectors
Files:
- `ref/python/decoding_ref.py` implements DecodingSpec_v1 exactly.
- `ref/python/generate_vectors.py` outputs JSONL vectors.

Tests:
- `pytest -q` runs golden + 1000 randomized tests.

Acceptance:
- any spec mismatch fails.
- include negative tests: mutate y_t, top_p, etc.

### M2 — Rust core math library
- Implement fixed-point ops and exp approximation in Rust:
  - floor_div toward -∞ for signed
  - Q16.16 and Q30 helpers
- Match Python reference bit-for-bit.

Acceptance:
- `cargo test` runs 1000 randomized equivalence vs Python vectors (load JSONL).

### M3 — StepCircuit (R1CS)
- Circuit proves one step:
  - sorting check (or provide permutation + verify ordering)
  - top-k/top-p prefix selection
  - sampling threshold rule
  - receipt hash update
- The circuit output is (y_t, h_t).

Acceptance:
- proof verifies for valid vectors
- fails for tampered vectors

### M4 — Folding/IVC
- Fold N steps into accumulator
- Produce final decider proof
- Verify off-chain first

Acceptance:
- N in {10,50,100} passes reliably

### M5 — On-chain integration (ICBC)
- Settlement contract stores request_id, policy_hash, seed_commit, escrow
- Verifier contract verifies decider proof
- Happy path + slashing path tests

Acceptance:
- `forge test` passes and prints gas tables

## How to prompt agents (templates)

### Template A — “Implement exactly what the spec says”
> Implement DecodingSpec_v1 in `ref/python/decoding_ref.py` exactly.  
> Do not modify any files in `spec/`.  
> Add 50 golden vectors and 1000 randomized tests.  
> Include negative tamper tests.  
> Output a git diff only.

### Template B — “Bit-for-bit equivalence”
> Implement the same decoding in Rust in `vrbdecode-core`.  
> Add a test that loads vectors.jsonl and asserts exact output token matches Python.  
> If any test fails, fix the implementation (not the spec).

### Template C — “Circuit correctness”
> Implement StepCircuit that enforces the exact DecodingSpec_v1 relation.  
> Add tests to prove/verify a small batch of vectors.  
> Add negative tests that should fail verification.

## Guardrails that force success
- Golden vectors cover edge cases where “almost correct” implementations diverge.
- Randomized tests catch off-by-one, rounding, and ordering mistakes.
- Negative tests prevent agents from “making proofs pass” by loosening constraints.

## Hardware note
Your EliteBook-class CPU is enough for:
- reference + vectors + correctness testing
- StepCircuit development
- local chain tests

GPU is only needed if you want to generate logits from large LLMs at scale.
