//! degree — PROVABLE algebraic degree upper bounds for cube3d_sponge.
//!
//! ===================== WHY NOT REAL DIVISION PROPERTY =====================
//!
//! Modern Ascon/Keccak cryptanalysis uses BIT-BASED DIVISION PROPERTY (Todo-Morii
//! FSE'16) modelled as MILP (Xiang et al. ASIACRYPT'16) and solved with Gurobi.
//! That is not tractable here:
//!
//!     Ascon state     :  320 bits
//!     Keccak-f state  : 1600 bits
//!     cube3d state    : 4096 bits   <- 2.5x Keccak
//!
//! A bit-based DP model of 5 rounds needs ~400k binary variables and ~300k
//! constraints. Keccak division property is a paper in its own right at 1600 bits;
//! at 4096 with no solver installed it's a research project, not a harness.
//!
//! So this file implements NUMERIC MAPPING (Liu, CRYPTO 2017) instead — the
//! degree-propagation relative of division property. It is strictly LOOSER than
//! bit-based DP, but it is:
//!
//!   * SOUND  — it over-approximates, so every bound it reports is a real upper
//!              bound. No sampling, no z-scores, no "probably".
//!   * CHEAP  — O(state x rounds), milliseconds, not solver-hours.
//!   * USEFUL — a per-bit degree bound finds DETERMINISTIC zero-sum distinguishers.
//!
//! ========================= THE PROPAGATION RULES =========================
//!
//! For each state bit, track an upper bound on its algebraic degree in the chosen
//! variable set (the cube's nonce bits). Key bits and unchosen nonce bits are
//! constants, degree 0.
//!
//!     NOT   : deg(!x)    = deg(x)              since !x = 1 + x over GF(2)
//!     XOR   : deg(a^b)  <= max(deg a, deg b)
//!     AND   : deg(a&b)  <= deg(a) + deg(b)     sound even when a,b share variables
//!     chi3  : out = (!a&b) ^ (!c&d) ^ (!e&f)
//!             deg(out) <= max(da+db, dc+dd, de+df)
//!     rho   : bit rotation within a byte -> degrees permute with the bits
//!     pi    : cell transposition          -> degrees permute with the cells
//!     round constant: degree 0, so max(deg, 0) = deg. No effect on the bound.
//!
//! The Feistel is the reason the per-round factor is 4 and not 2: A' = A ^ chi3(B)
//! doubles the degree, then B' = B ^ chi3(A') doubles it again. Hence deg <= 4^R.
//!
//! ============================ WHAT IT PROVES ============================
//!
//! If the degree of output bit o in a set of d cube variables is PROVABLY < d, then
//! summing o over all 2^d assignments of that cube is PROVABLY 0 — every monomial
//! is missing at least one cube variable, so each cancels in pairs. That is a
//! deterministic zero-sum distinguisher: it holds for every key, always, with no
//! statistics attached. Compare the distinguish.rs z-scores, which are evidence.
//!
//! IMPORTANT ASYMMETRY: an upper bound on degree can PROVE a distinguisher exists.
//! It can NEVER prove one doesn't. Numeric mapping ignores cancellation, so the real
//! degree may be lower than the bound and MORE zero-sums may exist than we find.
//! A negative result here is weak; a positive result is certain.

use cube3d_sponge::*;
use std::time::{SystemTime, UNIX_EPOCH};

const BITS: usize = CELLS * 8; // 4096
const KEY_BYTES: usize = 16;
const NONCE_BYTES: usize = 64;
const NONCE_BITS: usize = NONCE_BYTES * 8;

type DegVec = Vec<u32>;

#[inline]
fn bidx(cell: usize, bit: usize) -> usize {
    cell * 8 + bit
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Degree bound of chi3's 8 output bits at cell i.
#[inline]
fn chi3_deg(d: &DegVec, i: usize, round: u32, cap: u32) -> [u32; 8] {
    let nbrs = tables().nbrs[i];
    let r = (round % 3) as usize;
    let a = nbrs[(2 * r) % 6];
    let b = nbrs[(1 + 2 * r) % 6];
    let c = nbrs[(2 + 2 * r) % 6];
    let dd = nbrs[(3 + 2 * r) % 6];
    let e = nbrs[(4 + 2 * r) % 6];
    let f = nbrs[(5 + 2 * r) % 6];
    let mut out = [0u32; 8];
    for k in 0..8 {
        let t1 = d[bidx(a, k)] + d[bidx(b, k)];
        let t2 = d[bidx(c, k)] + d[bidx(dd, k)];
        let t3 = d[bidx(e, k)] + d[bidx(f, k)];
        out[k] = t1.max(t2).max(t3).min(cap);
    }
    out
}

/// Feistel degree propagation, mirroring feistel_variant exactly.
fn feistel_deg(d: &DegVec, round: u32, cap: u32) -> DegVec {
    let t = tables();
    let mut out = d.clone();
    // A' = A ^ chi3(B)  — chi3 at an A-cell reads only B-cells.
    for &i in &t.a_cells {
        let cd = chi3_deg(d, i, round, cap);
        for k in 0..8 {
            out[bidx(i, k)] = d[bidx(i, k)].max(cd[k]);
        }
    }
    // round constant into cell 0 is degree 0 -> no change to the bound.
    let a1 = out.clone();
    // B' = B ^ chi3(A')  — chi3 at a B-cell reads only the updated A-cells.
    for &i in &t.b_cells {
        let cd = chi3_deg(&a1, i, round, cap);
        for k in 0..8 {
            out[bidx(i, k)] = d[bidx(i, k)].max(cd[k]);
        }
    }
    out
}

/// rho rotates each byte left by rho_off[i]: output bit k = input bit (k - r) mod 8.
fn rho_deg(d: &DegVec) -> DegVec {
    let t = tables();
    let mut out = vec![0u32; BITS];
    for i in 0..CELLS {
        let r = t.rho_off[i] as usize;
        for k in 0..8 {
            out[bidx(i, k)] = d[bidx(i, (k + 8 - r) % 8)];
        }
    }
    out
}

fn pi_deg(d: &DegVec) -> DegVec {
    let t = tables();
    let mut out = vec![0u32; BITS];
    for i in 0..CELLS {
        for k in 0..8 {
            out[bidx(t.pi_fwd[i], k)] = d[bidx(i, k)];
        }
    }
    out
}

fn round_deg(d: &DegVec, round: u32, cap: u32) -> DegVec {
    let s = feistel_deg(d, round, cap);
    let s = rho_deg(&s);
    pi_deg(&s)
}

fn propagate(vars: &[usize], rounds: u32, rate: &[usize], cap: u32) -> DegVec {
    let mut d = vec![0u32; BITS];
    for &vb in vars {
        d[bidx(rate[KEY_BYTES + vb / 8], vb % 8)] = 1;
    }
    for r in 0..rounds {
        d = round_deg(&d, r, cap);
    }
    d
}

// ---------------------------------------------------------------------------
// Empirical side, for cross-validating the bound
// ---------------------------------------------------------------------------

type Key = [u8; KEY_BYTES];
type Nonce = [u8; NONCE_BYTES];

fn random_key(rng: &mut u64) -> Key {
    let mut k = [0u8; KEY_BYTES];
    for b in k.iter_mut() {
        *b = (xorshift(rng) & 0xFF) as u8;
    }
    k
}

fn random_nonce(rng: &mut u64) -> Nonce {
    let mut n = [0u8; NONCE_BYTES];
    for b in n.iter_mut() {
        *b = (xorshift(rng) & 0xFF) as u8;
    }
    n
}

#[inline]
fn out_bit(key: &Key, nonce: &Nonce, rounds: u32, o: usize, rate: &[usize]) -> u8 {
    let mut s = [0u8; CELLS];
    for i in 0..KEY_BYTES {
        s[rate[i]] = key[i];
    }
    for i in 0..NONCE_BYTES {
        s[rate[KEY_BYTES + i]] = nonce[i];
    }
    let y = permute_r(&s, rounds);
    (y[rate[o / 8]] >> (o % 8)) & 1
}

#[inline]
fn set_nonce_bit(n: &mut Nonce, bit: usize, v: u8) {
    let m = 1u8 << (bit % 8);
    if v == 1 {
        n[bit / 8] |= m;
    } else {
        n[bit / 8] &= !m;
    }
}

/// Sum output bit o over all 2^d assignments of the cube, base nonce elsewhere.
fn cube_sum(key: &Key, base: &Nonce, cube: &[usize], rounds: u32, o: usize, rate: &[usize]) -> u8 {
    let d = cube.len();
    let mut acc = 0u8;
    let mut n = *base;
    for mask in 0u64..(1u64 << d) {
        for (k, &cb) in cube.iter().enumerate() {
            set_nonce_bit(&mut n, cb, ((mask >> k) & 1) as u8);
        }
        acc ^= out_bit(key, &n, rounds, o, rate);
    }
    acc
}

fn main() {
    let mut rng = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;
    let rate = rate_cells();
    let out_total = rate.len() * 8;

    println!("cube3d_sponge — provable degree bounds via numeric mapping");
    println!("(bit-based division property MILP is infeasible at 4096 bits with no solver;");
    println!(" numeric mapping is looser but SOUND — every bound below is a real upper bound)\n");

    // -----------------------------------------------------------------
    // Phase 1: degree growth, all nonce bits as variables
    // -----------------------------------------------------------------
    println!("== Phase 1: degree growth (all {} nonce bits active) ==\n", NONCE_BITS);
    let all_vars: Vec<usize> = (0..NONCE_BITS).collect();
    let cap = NONCE_BITS as u32;

    println!("rounds | naive 4^R | proven bound (max over out-bits) | median | out-bits proven deg 0");
    println!("-------+-----------+---------------------------------+--------+----------------------");
    for r in 1..=8u32 {
        let d = propagate(&all_vars, r, &rate, cap);
        let mut degs: Vec<u32> = (0..out_total)
            .map(|o| d[bidx(rate[o / 8], o % 8)])
            .collect();
        degs.sort_unstable();
        let maxd = *degs.last().unwrap();
        let med = degs[degs.len() / 2];
        let zeros = degs.iter().filter(|&&x| x == 0).count();
        let naive = 4u64.saturating_pow(r).min(NONCE_BITS as u64);
        println!(
            "{:6} | {:9} | {:31} | {:6} | {:4} of {}",
            r, naive, maxd, med, zeros, out_total
        );
    }

    // -----------------------------------------------------------------
    // Phase 2: soundness cross-check against measured dependence
    // -----------------------------------------------------------------
    println!("\n== Phase 2: soundness cross-check ==");
    println!("the bound claims certain output bits have degree 0 — i.e. provably do NOT");
    println!("depend on ANY nonce bit. if measurement ever finds one that DOES move, the");
    println!("propagation is unsound and every number in this file is worthless.\n");

    let mut checked = 0usize;
    let mut violations = 0usize;
    for r in 1..=3u32 {
        let d = propagate(&all_vars, r, &rate, cap);
        let zero_bits: Vec<usize> = (0..out_total)
            .filter(|&o| d[bidx(rate[o / 8], o % 8)] == 0)
            .collect();
        let mut local_viol = 0usize;
        let sample: Vec<usize> = zero_bits
            .iter()
            .cloned()
            .take(60)
            .collect();
        for &o in &sample {
            let k = random_key(&mut rng);
            let base = random_nonce(&mut rng);
            let b0 = out_bit(&k, &base, r, o, &rate);
            for _ in 0..40 {
                let n2 = random_nonce(&mut rng);
                if out_bit(&k, &n2, r, o, &rate) != b0 {
                    local_viol += 1;
                    break;
                }
            }
            checked += 1;
        }
        violations += local_viol;
        println!(
            "  rounds {}: {:4} out-bits proven deg 0, {} sampled, {} violations",
            r,
            zero_bits.len(),
            sample.len(),
            local_viol
        );
    }
    println!(
        "\n  total: {} predictions checked, {} violations -> propagation {}",
        checked,
        violations,
        if violations == 0 { "SOUND so far" } else { "UNSOUND — BUG" }
    );

    // -----------------------------------------------------------------
    // Phase 3: deterministic zero-sum distinguishers
    // -----------------------------------------------------------------
    println!("\n== Phase 3: provable zero-sum distinguishers ==");
    println!("pick a cube of dimension d. any output bit with proven degree < d MUST sum");
    println!("to 0 over that cube, for every key, always. verified empirically below.\n");

    println!("rounds |  d | out-bits proven zero-sum | verified sums | all zero?");
    println!("-------+----+--------------------------+---------------+----------");

    let mut best_round = 0u32;
    for r in 1..=8u32 {
        for &d in &[8usize, 12, 16] {
            // Cube = d consecutive nonce bits (adjacent cells -> tightest cone).
            let cube: Vec<usize> = (0..d).collect();
            let dv = propagate(&cube, r, &rate, d as u32);
            let zs: Vec<usize> = (0..out_total)
                .filter(|&o| dv[bidx(rate[o / 8], o % 8)] < d as u32)
                .collect();

            if zs.is_empty() {
                println!("{:6} | {:2} | {:24} | {:13} | {}", r, d, 0, "-", "n/a");
                continue;
            }

            // Empirically verify a sample of the claimed zero-sums.
            let key = random_key(&mut rng);
            let base = random_nonce(&mut rng);
            let sample: Vec<usize> = zs.iter().cloned().take(12).collect();
            let mut all_zero = true;
            for &o in &sample {
                if cube_sum(&key, &base, &cube, r, o, &rate) != 0 {
                    all_zero = false;
                    break;
                }
            }
            if all_zero {
                best_round = best_round.max(r);
            }
            println!(
                "{:6} | {:2} | {:24} | {:13} | {}",
                r,
                d,
                zs.len(),
                sample.len(),
                if all_zero { "YES" } else { "NO — BUG!" }
            );
        }
    }

    // -----------------------------------------------------------------
    // Phase 4: cube shape sweep
    // -----------------------------------------------------------------
    println!("\n== Phase 4: cube shape sweep ==");
    println!("degree growth depends on the cube's SHAPE, not just its dimension. chi3 is");
    println!("bitwise, so bit k of a cell only meets bit k of its neighbours — rho is what");
    println!("couples planes. a cube stacked in few cells therefore grows degree SLOWER than");
    println!("one spread across many, and slower growth = deeper zero-sums.\n");

    let shapes: Vec<(&str, Vec<usize>)> = vec![
        ("1 cell, all 8 planes", (0..8).collect()),
        ("2 cells adjacent", (0..16).collect()),
        ("4 cells adjacent", (0..32).collect()),
        ("8 cells adjacent", (0..64).collect()),
        ("1 plane across 16 cells", (0..16).map(|i| i * 8).collect()),
        ("1 plane across 32 cells", (0..32).map(|i| i * 8).collect()),
        ("2 planes x 12 cells", (0..12).flat_map(|i| vec![i * 8, i * 8 + 1]).collect()),
        ("spread stride-37", (0..24).map(|i| (i * 37) % NONCE_BITS).collect()),
    ];

    println!("shape                       |  d | cost | R=4  | R=5  | R=6  | R=7");
    println!("----------------------------+----+------+------+------+------+------");
    let mut deepest_proven = best_round;
    for (name, cube) in &shapes {
        let d = cube.len();
        print!("{:27} | {:2} | 2^{:<2} ", name, d, d);
        for r in 4..=7u32 {
            let dv = propagate(cube, r, &rate, d as u32);
            let zs = (0..out_total)
                .filter(|&o| dv[bidx(rate[o / 8], o % 8)] < d as u32)
                .count();
            if zs > 0 {
                deepest_proven = deepest_proven.max(r);
            }
            print!("| {:4} ", zs);
        }
        println!();
    }
    println!("\n  (numbers = output bits with a PROVEN zero-sum. 0 = bound not tight enough.)");
    println!("  a 2^64 cube is unverifiable by us but is still a legitimate distinguisher:");
    println!("  2^64 < 2^128 brute force. that one is proven by the propagation, not measured.");

    println!("\nverdict:");
    println!(
        "  * deepest PROVABLE zero-sum, practical cube (<=2^16): round {}",
        best_round
    );
    println!(
        "  * deepest PROVABLE zero-sum, any cube up to 2^64:      round {}",
        deepest_proven
    );
    println!("  * compare: distinguish.rs found a STATISTICAL bias to round 6;");
    println!("    attack.rs recovered key bits only to round 2.");
    println!("  * a proven zero-sum needs no statistics: it is exact, holds for every key,");
    println!("    and 'verified sums = all zero' is the theory and the measurement agreeing.");
    println!("  * numeric mapping IGNORES cancellation, so the true degree may be lower and");
    println!("    more zero-sums may exist than found here. positive results are certain;");
    println!("    negative ones are only 'this bound wasn't tight enough to prove it'.");
}
