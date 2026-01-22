# Peer Review: VRBDecode — ICT Express Submission

---

## Summary

This paper presents **VRBDecode**, a proof-carrying receipt protocol for verifiable stochastic decoding in language model inference. The system binds decoding policy parameters (temperature, top-k, top-p) and per-step pseudo-randomness to tamper-evident receipts using Poseidon hashing and Nova folding for streaming proofs. The authors evaluate constraint costs, proving time, verification time, proof size, and memory across candidate sizes K∈{16,32,64} and sequence lengths N∈{32,64,128,256}.

---

## Strengths

1. **Novel and timely problem**: The accountability gap in LLM decoding is a real concern for regulated deployments. Focusing on the decoding layer rather than the full forward pass is a pragmatic scoping decision that yields tractable circuits.

2. **Sound technical approach**: The use of deterministic fixed-point arithmetic to eliminate floating-point ambiguity is well-motivated. The receipt chaining via Poseidon and Nova folding for IVC is appropriate for the streaming setting.

3. **Comprehensive evaluation**: The experimental design covers multiple K and N values with 5 repetitions. Reporting constraint counts, generation time, proving time, verification time, proof size, and peak RSS provides a complete picture.

4. **Clear scope acknowledgment**: The authors are upfront that VRBDecode does not prove candidate set derivation or the forward pass—this honesty strengthens the paper.

5. **Well-written**: The paper is clearly organized and the technical exposition is accessible.

---

## Weaknesses and Questions

### Major

1. **Proof size concern**: The proof sizes are very large—~13 MB for K=16 and ~84 MB for K=64. This is acknowledged but not adequately addressed. For practical deployment (especially on-chain anchoring mentioned in the introduction), this is prohibitive. The authors should discuss:
   - Why proof size is independent of N but grows with K
   - Concrete plans or known techniques to reduce this (e.g., Groth16 compression of the final folded proof)

2. **Missing security analysis**: The paper lacks a formal or semi-formal security argument. What exactly does the receipt guarantee? Under what assumptions? A threat model is sketched (Section 3.1) but no security claims are stated or justified. Even an informal security argument would strengthen the contribution.

3. **Limited practical applicability discussion**: The proving times (2.5–17 s/step) make real-time or near-real-time proof generation infeasible for interactive use. The paper should discuss target deployment scenarios more concretely—is this for batch auditing? Post-hoc verification? This affects how readers evaluate the contribution.

### Minor

4. **Figure references without figures**: The manuscript references `system_architecture.pdf`, `decoding_pipeline.pdf`, `constraints_vs_k.pdf`, `nova_avg_step_time_vs_n.pdf`, and `nova_peak_rss_vs_n.pdf`. I assume these are provided separately, but the review package should confirm their presence.

5. **Table formatting**: In `table1.tex`, the preprocess time rows (e.g., "K=16 preprocess time: 4.2594 s") break the tabular structure. Consider:
   - Moving preprocess times to a separate mini-table or inline text
   - Or using a proper multicolumn header row

6. **Missing units in Table 1 header**: The first sub-table has "Gen(s)" which is clear, but the column headers "StepCircuit" and "StepFCircuit" should indicate these are constraint counts (e.g., "StepCircuit (constraints)").

7. **Fixed-point approximation details**: The paper mentions a "fixed-point approximation of exponentiation" but does not specify the approximation method (Taylor series? Lookup table? Piecewise linear?). This is relevant for reproducibility and for understanding the approximation error.

8. **Bibliography formatting**: The `.bib` file has excessive blank lines between fields, which is unusual. More substantively:
   - `teutsch2019scalableverificationsolutionblockchains` has a malformed author field: `Christian Reitwie{\\ss}ner` should be `Christian Reitwießner` or `Christian Reitwie{\ss}ner` (single backslash).

9. **Minor textual issues**:
   - Line 36: "common policies---temperature scaling" — the em-dashes are inconsistent with standard LaTeX (`---` is correct, but spacing around them varies in the document).
   - Line 125: "Sonobe" should likely be "Sonobe" or checked for correct capitalization/spelling of the library name.

---

## Requested Corrections

1. **Add a security discussion** (even informal) explaining what guarantees the receipt provides and under what assumptions.

2. **Clarify proof size scaling** and discuss compression strategies.

3. **Specify the fixed-point exponentiation method** used in the circuit.

4. **Fix the bibliography entry** for Teutsch & Reitwießner (line 220 of refs.bib):
   ```bibtex
   author = {Jason Teutsch and Christian Reitwie{\ss}ner},
   ```

5. **Improve Table 1 clarity**:
   - Add "(constraints)" to StepCircuit/StepFCircuit headers
   - Consider restructuring preprocess time presentation

6. **Confirm all referenced figures are included** in the submission package.

---

## Minor Suggestions (Optional)

- Consider adding a "Limitations" subsection header in Section 4.4 for clarity.
- The abstract could briefly mention the proof sizes and verification times to give readers immediate performance intuition.
- A comparison row in Table 1 showing how VRBDecode compares to a hypothetical "no folding" baseline would contextualize the Nova benefits.

---

## Recommendation

**Minor Revision**

The paper addresses a relevant problem with a sound technical approach and thorough evaluation. The main gaps are: (1) missing security discussion, (2) insufficient treatment of the large proof sizes, and (3) minor presentation issues. These can be addressed without fundamental changes to the contribution. I recommend acceptance contingent on the authors addressing the requested corrections above.
