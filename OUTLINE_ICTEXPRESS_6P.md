# OUTLINE — ICT Express (Original Research Article, 6 pages double-column)

> Writing strategy: treat this as a **systems paper** with one core cryptographic contribution (verifiable decoding) + one core systems contribution (streaming proofs). Everything else is supporting detail.

## Page budget (hard)
Total: **6 pages** (excluding references if allowed, but assume strict).

## Required figures/tables (max 4)
- **Fig 1 (0.35p):** System architecture & receipt flow (service provider ↔ client ↔ optional auditor)
- **Fig 2 (0.35p):** DecodingSpec pipeline (sort → top-k → top-p → sample) + where proof binds
- **Fig 3 (0.35p):** Memory vs tokens (naive vs folding/streaming)
- **Table 1 (0.25p):** Performance + size summary (constraints/step, prover time/step, proof size, verifier time)

## Section-by-section outline with target space

### 1. Introduction (0.75 pages)
- Problem: decoding policy compliance is currently non-verifiable
- Why it matters for AI services / SLAs
- Contributions (3 bullets): protocol + proof + streaming evaluation
- One-sentence scope note: candidate-set decoding; forward-pass is composable future work

### 2. Problem definition & threat model (0.6 pages)
- Parties: client, provider, optional auditor
- What cheating looks like (T/top-k/top-p/randomness)
- Security goal: detect deviation with publicly verifiable receipt/proof

### 3. VRBDecode design (1.6 pages)
- 3.1 Policy commitment & public inputs (policy_hash, seed_commit)
- 3.2 Randomness binding (seed → PRF → per-step U_t)
- 3.3 Receipt chaining (h_t update)
- 3.4 Streaming proof generation (fold per token; decider proof)

### 4. Decoding proof (0.9 pages)
- State the relation: token y_t must equal DecodingSpec_v1 output
- Explain key sub-constraints: sorting check, top-k/top-p prefix, sampling threshold
- Mention exp approximation + fixed-point rules (refer to spec)

### 5. Implementation (0.5 pages)
- arkworks R1CS circuit
- Sonobe folding + decider
- Reference implementation + vector harness

### 6. Evaluation (1.4 pages)
- Setup: K ∈ {16,32,64}; N ∈ {32,64,128,256}
- Results:
  - constraints/step scaling with K
  - prover time scaling with N
  - memory plot demonstrates streaming advantage
- Correctness: 50 golden vectors + 1000 randomized equivalence; negative tamper tests

### 7. Related work (0.35 pages)
- zkML forward-pass proof systems (brief)
- why decoding verification is distinct

### 8. Limitations & conclusion (0.2 pages)
- Candidate-set scope; forward-pass composability; top-p full-vocab sorting not covered
- Conclusion: VRBDecode enables audit-grade decoding compliance receipts
