# VRBDecode (v2) — ICT Express Research Plan (6 pages target)

## Venue constraints
ICT Express invites **original research articles up to 6 pages (double-column)**. (Cited in the paper; see journal “Guide for Authors”.)

## Thesis statement
Proving compliance with a decoding policy (temperature/top-k/top-p) in AI services requires handling complex categorical sampling constraints. VRBDecode introduces a memory-efficient ZK proof system using **Nova-based folding (Sonobe)** that produces verifiable receipts. We specifically optimize the **Top-P/Top-K constraint generation** to enable high-throughput verification of long-sequence decoding without the memory explosion associated with standard SNARKs.

## Scope (locked)
- Verified module: **DecodingSpec v1.0** (fixed-point arithmetic, categorical sampling).
- Algorithmic Optimization: **O(K log K) constraint reduction** for candidate set permutation checks.
- Scalability: IVC/folding across tokens to achieve constant-time verification for variable-length outputs.
- Evaluation: strictly focused on ZK system performance (prover/verifier/constraints).

## Key contributions (paper claims)
1) **Efficient R1CS Mapping**: optimized constraints for fixed-point Exp and candidate sorting ($O(K \log K)$ vs $O(K^2)$).
2) **Folding-based IVC for Decoding**: first application of Sonobe folding to stochastic decoding receipts.
3) **Systems Scaling Analysis**: comprehensive study of prover memory and time scaling as a function of sequence length ($N$) and candidate size ($K$).

## Evaluation plan
- **Constraint Analysis**: breakdown of constraints per step (Exp, Sort, Hash).
- **K-Scaling Study**: benchmark for candidate sizes $K \in \{16, 32, 64, 128\}$.
- **Memory Efficiency**: comparison of prover memory growth ($N \in \{32, 64, 128, 256, 512\}$) for folding vs naive SNARKs.
- **Latency Breakdown**:
  - Prover time per step.
  - Verification latency.
- **Correctness**:
  - Equivalence tests vs reference Python implementation.
  - Fixed-point precision error analysis.

## Deliverables (implementation)
- Python reference implementation and vector generator
- Rust circuits for StepCircuit (R1CS)
- Sonobe folding driver and decider proof generator
- Reproducible scripts to output figures/tables

## Risks and mitigations
- Top-p ambiguity: eliminated by DecodingSpec v1.0 (sorting + tie-break rules).
- Exp approximation accuracy: fixed polynomial + fixed-point rules; tested against reference.
