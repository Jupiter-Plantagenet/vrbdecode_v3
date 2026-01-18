# VRBDecode (v2) — IEEE ICBC Research Plan (8 pages target)

## Venue constraints
ICBC submission guidelines specify IEEE 2-column format with **full papers not exceeding 8 pages**.

## Thesis statement
Blockchain settlement can enforce AI-service guarantees only if the service behavior is verifiable. VRBDecode enables **accountable stochastic decoding** by binding randomness to an auditable seed and producing receipts/proofs that can drive on-chain settlement and slashing.

## Scope (locked)
- Verified module: DecodingSpec v1.0 over candidate set (`K=64`).
- Streaming proofs: folding/IVC across tokens; produce a single decider proof verifiable on EVM.
- Chain: local EVM chain demo with settlement contract; VRF mocked (with a clear testnet path).

## Key contributions (paper claims)
1) **On-chain protocol**: request/escrow → seed binding → receipt/proof submission → settlement or slashing.
2) **Proof-carrying receipts**: streaming proof generation for long outputs.
3) **Prototype + evaluation**: gas/latency breakdown and scalability in N and K.

## Evaluation plan
- End-to-end: N tokens {32, 64, 128} with folding.
- Gas costs:
  - commit request
  - submit proof/receipt
  - settle/slash
- Latency breakdown:
  - proving
  - on-chain submit/verify
- Correctness:
  - equivalence tests vs reference
  - negative tests: modify seed_commit/policy_hash/y_t must fail.

## Threat model focus
- Provider cannot “grind” outputs without being detected because randomness is bound to seed_commit and receipt chain.
- Abort handling: escrow + deadlines; replay or mismatch triggers slashing.
