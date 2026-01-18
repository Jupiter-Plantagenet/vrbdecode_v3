# ReceiptSpec v1.0 (Normative)

Receipt chaining provides a tamper-evident transcript of the generation that can be stored, audited, or anchored on-chain.

## 1. Hash function
In-circuit receipt updates MUST use **Poseidon** over the circuit field.

On-chain contracts MAY treat receipt hashes as opaque values (no need to recompute Poseidon).

## 2. Encoding
All non-field data MUST be encoded deterministically into field elements.

### 2.1 Field packing
- `bytes32` values are split into two 128-bit limbs and mapped into two field elements.
- `u32` is embedded directly into a field element.
- `u64` is embedded directly into a field element.

## 3. Receipt state update per step
Let `h_{t-1}` be previous receipt state (field element).

Define receipt update at step t:
```
h_t = Poseidon(
  "VRBDecode.Receipt.v1" ||
  h_{t-1} ||
  request_id ||
  policy_hash ||
  seed_commit ||
  t ||
  y_t ||
  Ws_t ||
  R_t
)
```
Where:
- `y_t` is emitted token id (u32)
- `Ws_t` is sum of weights after top-p (u64 / Q30)
- `R_t` is the sampling threshold used (u64)

The ZK circuit MUST compute and enforce this update.

## 4. Final receipt
After N steps, prover outputs:
- `h_final = h_N`
- optionally `y_hash = Poseidon(y_0 || y_1 || ... || y_{N-1})` if needed

## 5. Tamper detection requirements
Changing any of:
- policy parameters (affecting policy_hash)
- seed or seed_commit
- step index t
- emitted token y_t
MUST result in verification failure because the receipt chain cannot be recomputed consistently.
