# OUTLINE — IEEE ICBC (Full Paper, 8 pages IEEE 2-column)

> Writing strategy: ICBC wants **blockchain-native accountability**. The ZK proof is a means to a settlement/dispute mechanism. Lead with protocol and incentives.

## Page budget (hard)
Total: **8 pages** (assume strict; references may be excluded depending on year, but do not rely on that).

## Required figures/tables (max 5)
- **Fig 1 (0.35p):** Protocol sequence diagram (request → seed binding → stream → receipt/proof → settlement)
- **Fig 2 (0.35p):** Contract state machine (Requested/InProgress/Submitted/Settled/Slashed)
- **Fig 3 (0.35p):** Proof/receipt pipeline (folding into one decider proof)
- **Table 1 (0.25p):** Gas costs for each contract call
- **Table 2 (0.25p):** Latency breakdown (proving, submit, verify) + scalability (N,K)

## Section-by-section outline with target space

### 1. Introduction (0.9 pages)
- Motivation: accountable AI services require verifiable behavior
- Gap: decoding randomness is unverified → provider can cheat while appearing compliant
- Contributions:
  - settlement protocol tied to VRF-bound randomness
  - proof-carrying receipts via streaming IVC
  - prototype + gas/latency evaluation

### 2. Background & model (0.9 pages)
- VRF / seed binding concept at protocol level (don’t over-teach)
- ZK proof role: enforce decoding policy correctness
- Threat model: deviation, abort/grind, replay

### 3. On-chain protocol (2.0 pages)
- 3.1 Data structures (request_id, policy_hash, seed_commit, h_final, escrow)
- 3.2 Happy path (commit → generate → submit → settle)
- 3.3 Disputes & slashing
- 3.4 Abort/grind mitigation (deadlines, nonces, penalty)
- 3.5 Privacy options (what is public vs hashed)

### 4. Verifiable decoding via DecodingSpec v1.0 (1.4 pages)
- Formal relation statement
- Sorting + top-k/top-p + sampling threshold
- Receipt chaining and public inputs
- Note on candidate-set scope and composability

### 5. Streaming proofs (IVC/folding) (1.1 pages)
- Per-step witness/proof folded into accumulator
- Final decider proof verification
- Why streaming matters for long outputs

### 6. Implementation (0.7 pages)
- Rust: arkworks R1CS circuits + Sonobe folding
- Solidity: settlement + verifier (decider)
- Local chain setup; note testnet VRF path

### 7. Evaluation (0.9 pages)
- Gas table (Table 1) and how it scales with proof size
- Latency table (Table 2) and scaling in N,K
- Correctness: golden vectors + randomized equivalence + negative tests

### 8. Related work & conclusion (0.1–0.2 pages each)
- Related work: 1 short paragraph
- Conclusion: VRBDecode turns decoding compliance into enforceable on-chain facts
