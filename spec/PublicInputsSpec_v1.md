# PublicInputsSpec v1.0 (Normative)

This spec defines the public inputs bound into VRBDecode proofs and receipts.

## 1. Identifiers and hashes

### 1.1 request_id
- `request_id`: `bytes32`
- MUST be unique per service request.
- Suggested: `keccak256(client_nonce || prompt_hash || provider_id)` (not required)

### 1.2 policy_hash (MUST)
`policy_hash: bytes32` binds the decoding policy.
It MUST be computed as:
```
policy_hash = keccak256(
  "VRBDecode.Policy.v1" ||
  K (u32 LE) ||
  top_k (u32 LE) ||
  top_p (u32 LE, Q16.16) ||
  T (u32 LE, Q16.16) ||
  max_tokens (u32 LE) ||
  hash_fn_id (u32 LE) ||
  exp_approx_id (u32 LE)
)
```
Where:
- `hash_fn_id`: 1=Poseidon (in-circuit), 2=Keccak (off-circuit)
- `exp_approx_id`: 1=ExpPoly5_Q16_16_to_Q30 (as in DecodingSpec v1.0)

## 2. Randomness binding

### 2.1 seed_commit (MUST)
`seed_commit: bytes32 = keccak256(seed)`
- `seed` is 32 bytes, derived from VRF output or an agreed protocol.
- The ZK proof MUST bind to `seed_commit` and MUST use `seed` as a witness.

### 2.2 per-step U_t
Per-step randomness is derived by:
```
U_t = low64( Poseidon(seed || u32_le(t)) )
```
- The circuit MUST compute the same mapping.
- If Poseidon is unavailable, implementations MAY derive U_t off-circuit and pass it as witness, but then U_t MUST be included in the receipt hash update to prevent substitution.

## 3. Receipt chain commitments

### 3.1 h_0 (MUST)
`h_0: field_element` (Poseidon field) is the starting receipt state.
- Typically derived from `Poseidon(request_id || policy_hash || seed_commit || prompt_hash)`
- The exact encoding is specified in ReceiptSpec v1.0.

### 3.2 h_final (MUST)
`h_final: field_element` is the final receipt state after N tokens.

The proof MUST expose `h_final` as a public output (or a hash of it if field exposure is inconvenient on-chain).

## 4. Token outputs
The proof MUST bind to either:
- the sequence of emitted token IDs (public), OR
- a rolling hash of outputs inside the receipt chain (recommended).

For v1.0 MVP:
- emitted token `y_t` is included in each receipt update (see ReceiptSpec).
