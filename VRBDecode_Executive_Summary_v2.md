# VRBDecode (v2) — Executive Summary

## One-line pitch
**VRBDecode** makes stochastic decoding *auditable and enforceable* by binding randomness to a verifiable seed (e.g., VRF output) and producing a **cryptographic proof** that each generated token follows a **public decoding policy** (temperature/top-k/top-p) over a candidate set.

## Core idea
Modern “verifiable inference” work tends to focus on proving the forward pass (that logits came from a model). **But the output distribution is also controlled by decoding**—temperature scaling, top-k/top-p filtering, and randomized sampling. If these are not verified, a provider can silently change behavior while still claiming compliance.

VRBDecode isolates this gap and provides a practical first system:
- prove decoding correctness over a **candidate set** per step (default `K=64`),
- support long outputs via **streaming proofs** (IVC/folding),
- optionally anchor receipts and settlement on-chain.

## What is proven (v2 scope)
Given, per step `t`:
- candidate IDs + logits for `K` candidates,
- policy parameters (T, top_k, top_p),
- a VRF-bound seed commitment and deterministic PRF-derived per-step randomness,
VRBDecode proves the emitted token is exactly the result of DecodingSpec v1.0.

> Forward-pass correctness (“these logits came from model M on prompt P”) is composable and out-of-scope for v2 MVP; it can be added as a separate module later.

## Two paper targets
### ICT Express (6 pages)
Systems/ICT framing: verifiable AI service compliance and audit receipts. Minimal blockchain.
- Contribution: decoding verification + streaming proof memory scaling + service audit narrative.
- Deliverable: end-to-end prototype (off-chain verifier) with reproducible measurements.

### IEEE ICBC (8 pages)
Blockchain framing: accountable AI services with settlement, disputes, and slashing.
- Contribution: on-chain workflow + VRF binding + receipts + verification-driven settlement.
- Deliverable: local-chain demo + gas table + end-to-end trace, with a clear path to testnet VRF.

## Locked engineering choices
- Proving stack: **arkworks R1CS + Sonobe IVC/folding + EVM-verifiable decider proof**
- Hashing inside circuits: Poseidon (receipt chaining)
- Chain layer: EVM local chain (Anvil/Hardhat) for development; testnet optional for credibility.

## Success criteria (for “agent-proof” implementation)
- 50+ golden vectors; 1,000+ randomized equivalence tests vs reference implementation
- Negative tests: tampering with policy, step index, seed commitment, or token must fail verification
- Folding demo: N ∈ {10, 50, 100} tokens with stable memory growth
