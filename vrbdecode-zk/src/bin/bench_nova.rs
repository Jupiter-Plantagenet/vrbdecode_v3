use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Projective as Projective2;
use ark_serialize::CanonicalSerialize;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::FoldingScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;

use vrbdecode_zk::{StepExternalInputs, StepFCircuit};

type N = Nova<
    Projective,
    Projective2,
    StepFCircuit<16>,
    KZG<'static, Bn254>,
    Pedersen<Projective2>,
    false,
>;

fn poseidon_params_bn254_rate8() -> PoseidonConfig<Fr> {
    let rate = 8usize;
    let capacity = 1usize;
    let full_rounds = 8usize;
    let partial_rounds = 57usize;
    let alpha = 5u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0u64,
    );
    PoseidonConfig {
        full_rounds,
        partial_rounds,
        alpha,
        ark,
        mds,
        rate,
        capacity,
    }
}

fn floor_div_i128(n: i128, d: i128) -> i128 {
    if d <= 0 { return 0; }
    if n >= 0 { n / d } else { -((-n + d - 1) / d) }
}

fn prf_u_t(
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_lo: Fr,
    policy_hash_hi: Fr,
    seed_commit_lo: Fr,
    seed_commit_hi: Fr,
    step_idx: u32,
) -> u64 {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);
    let mut elems: Vec<Fr> = Vec::new();
    for &b in b"VRBDecode.U_t.v1" {
        elems.push(Fr::from(b as u64));
    }
    elems.push(request_id_lo);
    elems.push(request_id_hi);
    elems.push(policy_hash_lo);
    elems.push(policy_hash_hi);
    elems.push(seed_commit_lo);
    elems.push(seed_commit_hi);
    elems.push(Fr::from(step_idx as u64));
    sponge.absorb(&elems);
    let out = sponge.squeeze_native_field_elements(1)[0];
    let mut bytes = out.into_bigint().to_bytes_le();
    bytes.resize(8, 0u8);
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}

fn candidate_hash<const K: usize>(token_id: &[u32], logit_q16: &[i32], t_q16: u32) -> Fr {
    let t_clamped = t_q16.max(1);
    let mut slog_native: Vec<i64> = Vec::with_capacity(K);
    for i in 0..K {
        let num = (logit_q16[i] as i128) << 16;
        let q = floor_div_i128(num, t_clamped as i128) as i64;
        slog_native.push(q);
    }
    let mut perm: Vec<usize> = (0..K).collect();
    perm.sort_by(|&i, &j| {
        if slog_native[i] != slog_native[j] { return slog_native[j].cmp(&slog_native[i]); }
        token_id[i].cmp(&token_id[j])
    });
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);
    let mut elems: Vec<Fr> = Vec::new();
    for &b in b"VRBDecode.Candidates.v1" { elems.push(Fr::from(b as u64)); }
    for &idx in &perm {
        elems.push(Fr::from(token_id[idx] as u64));
        elems.push(Fr::from(logit_q16[idx] as u32 as u64));
    }
    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

fn receipt_update(
    h_prev: Fr, request_id_lo: Fr, request_id_hi: Fr, policy_hash_lo: Fr, policy_hash_hi: Fr,
    seed_commit_lo: Fr, seed_commit_hi: Fr, step_idx: u32, cand_hash: Fr, y: u32, ws: u64, r: u64,
) -> Fr {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);
    let mut elems: Vec<Fr> = Vec::new();
    for &b in b"VRBDecode.Receipt.v1" { elems.push(Fr::from(b as u64)); }
    elems.push(h_prev);
    elems.push(request_id_lo);
    elems.push(request_id_hi);
    elems.push(policy_hash_lo);
    elems.push(policy_hash_hi);
    elems.push(seed_commit_lo);
    elems.push(seed_commit_hi);
    elems.push(Fr::from(step_idx as u64));
    elems.push(cand_hash);
    elems.push(Fr::from(y as u64));
    elems.push(Fr::from(ws));
    elems.push(Fr::from(r));
    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

const Q30: u64 = 1 << 30;
const Z_MIN_Q16: i64 = -(12 << 16);
const E_Q30: [u64; 13] = [1073741824,395007542,145315154,53458458,19666268,7234816,2661540,979126,360200,132510,48748,17933,6597];

fn mul_q30_i64(a: i64, b: i64) -> i64 { ((a as i128 * b as i128) >> 30) as i64 }

fn exp_poly5_q16_16_to_q30(r_q16: i64) -> u64 {
    let r_q30: i64 = r_q16 << 14;
    let r2 = mul_q30_i64(r_q30, r_q30);
    let r3 = mul_q30_i64(r2, r_q30);
    let r4 = mul_q30_i64(r3, r_q30);
    let r5 = mul_q30_i64(r4, r_q30);
    let p: i128 = Q30 as i128
        + r_q30 as i128
        + (r2 as i128) / 2
        + floor_div_i128(r3 as i128, 6)
        + (r4 as i128) / 24
        + floor_div_i128(r5 as i128, 120);
    if p <= 0 { return 0; }
    if p >= Q30 as i128 { return Q30; }
    p as u64
}

fn decode_step_native(k: usize, top_k: usize, top_p_q16: u32, t_q16: u32, token_id: &[u32], logit_q16: &[i32], u_t: u64) -> (u32, u64, u64) {
    let t_clamped = t_q16.max(1);
    let mut items: Vec<(u32, i64)> = Vec::with_capacity(k);
    for i in 0..k {
        let num = (logit_q16[i] as i128) << 16;
        let s = floor_div_i128(num, t_clamped as i128) as i64;
        items.push((token_id[i], s));
    }
    items.sort_by(|a, b| { if a.1 != b.1 { return b.1.cmp(&a.1); } a.0.cmp(&b.0) });
    let m = items[0].1;
    let mut w: Vec<u64> = vec![0; k];
    for i in 0..top_k {
        let mut z = items[i].1 - m;
        if z < Z_MIN_Q16 { z = Z_MIN_Q16; }
        let neg_z = -z;
        let mut n = (neg_z >> 16) as i64;
        if n < 0 { n = 0; }
        if n > 12 { n = 12; }
        let r = z + (n << 16);
        let p = exp_poly5_q16_16_to_q30(r);
        w[i] = ((E_Q30[n as usize] as u128 * p as u128) >> 30) as u64;
    }
    let mut wk: u64 = 0;
    for i in 0..top_k { wk = wk.wrapping_add(w[i]); }
    let th = ((top_p_q16 as u128 * wk as u128) >> 16) as u64;
    let mut prefix: u64 = 0;
    let mut s: usize = 1;
    for i in 0..top_k { prefix = prefix.wrapping_add(w[i]); if prefix >= th { s = i + 1; break; } }
    let mut ws: u64 = 0;
    for i in 0..s { ws = ws.wrapping_add(w[i]); }
    let r = (((u_t as u128) * (ws as u128)) >> 64) as u64;
    let mut prefix2: u64 = 0;
    let mut j: usize = 0;
    for i in 0..s { prefix2 = prefix2.wrapping_add(w[i]); if prefix2 > r { j = i; break; } }
    (items[j].0, ws, r)
}

#[derive(Debug, Deserialize, Clone)]
struct Vector {
    #[serde(rename = "K")] k: usize,
    top_k: usize,
    top_p_q16: u32,
    #[serde(rename = "T_q16")] t_q16: u32,
    token_id: Vec<u32>,
    logit_q16: Vec<i32>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn load_jsonl(path: &PathBuf) -> Vec<Vector> {
    let f = File::open(path).expect("open vectors file");
    let r = BufReader::new(f);
    r.lines().filter_map(|l| l.ok()).filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Vector>(&l).expect("parse")).collect()
}

fn vectors_k16() -> Vec<Vector> {
    let root = workspace_root().join("vectors");
    let mut rows: Vec<Vector> = Vec::new();
    rows.extend(load_jsonl(&root.join("golden.jsonl")));
    rows.extend(load_jsonl(&root.join("random.jsonl")));
    rows.into_iter().filter(|v| v.k == 16).collect()
}

fn mk_external_inputs(
    row: &Vector, request_id_lo: Fr, request_id_hi: Fr, policy_hash_lo: Fr, policy_hash_hi: Fr,
    seed_commit_lo: Fr, seed_commit_hi: Fr, step_idx: u32, h_prev: Fr,
) -> StepExternalInputs<16> {
    let u_t = prf_u_t(request_id_lo, request_id_hi, policy_hash_lo, policy_hash_hi, seed_commit_lo, seed_commit_hi, step_idx);
    let (y, ws, r) = decode_step_native(16, row.top_k, row.top_p_q16, row.t_q16, &row.token_id, &row.logit_q16, u_t);
    let lo = ((u_t as u128) * (ws as u128)) as u64;
    let cand_hash = candidate_hash::<16>(&row.token_id, &row.logit_q16, row.t_q16);
    let h_new = receipt_update(h_prev, request_id_lo, request_id_hi, policy_hash_lo, policy_hash_hi, seed_commit_lo, seed_commit_hi, step_idx, cand_hash, y, ws, r);
    let token_id: [u32; 16] = row.token_id.clone().try_into().unwrap();
    let logit_q16: [i32; 16] = row.logit_q16.clone().try_into().unwrap();
    StepExternalInputs { top_k: row.top_k as u32, top_p_q16: row.top_p_q16, t_q16: row.t_q16, token_id, logit_q16, expected_y: y, expected_ws: ws, expected_r: r, expected_lo: lo, h_new }
}

#[derive(Debug, Clone, Serialize)]
struct BenchRow {
    n_steps: usize,
    avg_step_time_s: f64,
    total_fold_time_s: f64,
    proof_size_bytes: usize,
    verify_time_s: f64,
}

#[derive(Debug, Clone, Serialize)]
struct BenchOutput {
    preprocess_time_s: f64,
    results: Vec<BenchRow>,
}

fn bench_nova_n(
    num_steps: usize,
    params: &(
        <N as FoldingScheme<Projective, Projective2, StepFCircuit<16>>>::ProverParam,
        <N as FoldingScheme<Projective, Projective2, StepFCircuit<16>>>::VerifierParam,
    ),
    vectors: &[Vector],
    verbose: bool,
    progress: bool,
) -> Result<BenchRow, folding_schemes::Error> {
    assert!(vectors.len() >= num_steps, "Need {} K=16 vectors", num_steps);

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let policy_hash_lo = Fr::from(0u64);
    let policy_hash_hi = Fr::from(0u64);
    let seed_commit_lo = Fr::from(0u64);
    let seed_commit_hi = Fr::from(0u64);

    let initial_state = vec![request_id_lo, request_id_hi, policy_hash_lo, policy_hash_hi, seed_commit_lo, seed_commit_hi, Fr::from(0u64)];

    let f_circuit = StepFCircuit::<16>::new_default()?;

    let mut ext_inputs: Vec<StepExternalInputs<16>> = Vec::with_capacity(num_steps);
    let mut h_prev = Fr::from(0u64);
    for (step_idx, row) in vectors.iter().take(num_steps).enumerate() {
        let ext = mk_external_inputs(row, request_id_lo, request_id_hi, policy_hash_lo, policy_hash_hi, seed_commit_lo, seed_commit_hi, step_idx as u32, h_prev);
        h_prev = ext.h_new;
        ext_inputs.push(ext);
    }

    let mut rng = StdRng::seed_from_u64(123456789u64 + num_steps as u64);
    let mut folding = N::init(params, f_circuit, initial_state)?;

    if verbose {
        println!("  Folding {} steps...", num_steps);
    }
    if progress {
        eprintln!("Folding {} steps...", num_steps);
    }
    let fold_start = Instant::now();
    for ext in ext_inputs.iter() {
        folding.prove_step(&mut rng, ext.clone(), None)?;
    }
    let total_fold_time = fold_start.elapsed().as_secs_f64();
    let avg_step_time = total_fold_time / num_steps as f64;

    let proof = folding.ivc_proof();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).expect("serialize proof");
    let proof_size = proof_bytes.len();

    if verbose {
        println!("  Verifying...");
    }
    if progress {
        eprintln!("Verifying...");
    }
    let verify_start = Instant::now();
    N::verify(params.1.clone(), proof)?;
    let verify_time = verify_start.elapsed().as_secs_f64();

    Ok(BenchRow {
        n_steps: num_steps,
        avg_step_time_s: avg_step_time,
        total_fold_time_s: total_fold_time,
        proof_size_bytes: proof_size,
        verify_time_s: verify_time,
    })
}

fn main() {
    let json_only = std::env::args().any(|a| a == "--json");
    let progress = std::env::args().any(|a| a == "--progress")
        || std::env::var("VRBDECODE_BENCH_PROGRESS").is_ok();
    let verbose = !json_only;

    if verbose {
        println!("=== VRBDecode Nova Folding Benchmarks (K=16) ===\n");
    }

    let mut step_counts: Vec<usize> = vec![32, 64, 128, 256];
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--steps" {
            if let Some(v) = args.next() {
                let parsed: Vec<usize> = v
                    .split(',')
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.trim().parse::<usize>().expect("parse steps"))
                    .collect();
                if !parsed.is_empty() {
                    step_counts = parsed;
                }
            }
        }
    }

    let vectors = vectors_k16();
    let max_n = *step_counts.iter().max().unwrap_or(&0);
    assert!(
        vectors.len() >= max_n,
        "Need at least {} K=16 vectors (golden+random), found {}",
        max_n,
        vectors.len()
    );

    if verbose {
        println!("Preprocessing (once)...");
    }
    if progress {
        eprintln!("Preprocessing (once)...");
    }
    let poseidon_config = poseidon_params_bn254_rate8();
    let f_circuit = StepFCircuit::<16>::new_default().expect("fcircuit");
    let mut rng = StdRng::seed_from_u64(123456789u64);
    let pp = PreprocessorParam::new(poseidon_config, f_circuit);
    let preprocess_start = Instant::now();
    let params = N::preprocess(&mut rng, &pp).expect("preprocess");
    let preprocess_time_s = preprocess_start.elapsed().as_secs_f64();

    let mut results: Vec<BenchRow> = Vec::new();

    if !json_only {
        println!(
            "\n{:<8} {:>14} {:>14} {:>12} {:>14}",
            "N steps", "Avg Step (s)", "Total (s)", "Proof (B)", "Verify (s)"
        );
        println!("{}", "-".repeat(66));
    }

    for &n in &step_counts {
        if verbose {
            println!("\nBenchmarking N={}...", n);
        }
        if progress {
            eprintln!("Benchmarking N={}...", n);
        }
        let row = bench_nova_n(n, &params, &vectors, verbose, progress).expect("bench");
        if verbose {
            println!(
                "{:<8} {:>14.3} {:>14.3} {:>12} {:>14.4}",
                row.n_steps, row.avg_step_time_s, row.total_fold_time_s, row.proof_size_bytes, row.verify_time_s
            );
        }
        results.push(row);
    }

    let out = BenchOutput {
        preprocess_time_s,
        results,
    };

    if json_only {
        println!("{}", serde_json::to_string(&out).expect("json"));
        return;
    }

    println!("\nPreprocess time: {:.2}s", preprocess_time_s);
    println!("\n=== Summary for Table 1 ===");
    println!("Run complete. See above for detailed metrics.");
}
