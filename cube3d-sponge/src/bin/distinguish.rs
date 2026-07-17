//! distinguish — reduced-round cryptanalysis harness for cube3d_sponge.
//!
//! IMPORTANT FRAMING: `permute()` is a bijection on the full 4096-bit state.
//! Uniform random input therefore produces EXACTLY uniform output in the limit,
//! by definition — testing "is any full-width output bit biased" measures only
//! sampling noise, never the permutation's actual quality. Don't waste cycles on it.
//!
//! The question that matters is the one an attacker actually faces: the sponge's
//! capacity starts at a KNOWN fixed value (all-zero, exactly as Sponge::new() does)
//! and only the rate is attacker-controlled and attacker-visible. Restricting to
//! that fixed-capacity slice of the input space is a real constraint — the
//! permutation is bijective overall, but the pushforward through one fixed-capacity
//! slice is NOT guaranteed uniform. That's what every three tests below measure.
//!
//! Three independent angles, each reported per reduced-round count:
//!   A. BIT BIAS       — with capacity=0, random rate input, is any single output
//!                        rate bit non-50/50?
//!   B. DIFFERENTIAL   — flip one fixed rate input bit; does any output rate bit
//!                        flip with probability far from 50%?
//!   C. LINEAR         — random small-weight input/output masks; is parity(in-mask)
//!                        XOR parity(out-mask) biased away from 50%? (Matsui-style
//!                        random search, not exhaustive — a miss here is much
//!                        weaker evidence than a hit.)
//!
//! z-scores use the normal approximation to the binomial. As a rough guide with
//! these trial counts, |z| > ~4.5 is the point where "probably real" starts to
//! outweigh "probably one of many comparisons landing high by chance" — multiple
//! masks/bits are being scanned per round, so treat any single flagged result as a
//! lead to re-run with more trials, not a proven break.

use cube3d_sponge::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn random_bytes(rng: &mut u64, n: usize) -> Vec<u8> {
    (0..n).map(|_| (xorshift(rng) & 0xFF) as u8).collect()
}

/// Build a full Cube exactly the way Sponge::new().absorb() would see it:
/// capacity cells fixed at 0, rate cells filled from `rate_bytes`.
fn make_state(rate: &[usize], rate_bytes: &[u8]) -> Cube {
    let mut s = [0u8; CELLS];
    for (n, &cell) in rate.iter().enumerate() {
        s[cell] = rate_bytes[n];
    }
    s
}

fn permute_rounds(state: &Cube, rounds: u32) -> Cube {
    let mut s = *state;
    for r in 0..rounds {
        s = round_forward(&s, r);
    }
    s
}

#[inline]
fn get_rate_bit(state: &Cube, rate: &[usize], bit: usize) -> u8 {
    (state[rate[bit / 8]] >> (bit % 8)) & 1
}

fn z_score(count_ones: u64, trials: u64) -> f64 {
    let mean = trials as f64 * 0.5;
    let sd = (trials as f64 * 0.25).sqrt();
    (count_ones as f64 - mean) / sd
}

// ---------------------------------------------------------------------------
// Test A: per-output-bit bias, fixed capacity, random rate input
// ---------------------------------------------------------------------------
fn bit_bias_scan(rate: &[usize], rate_bits: usize, rounds: u32, trials: usize, rng: &mut u64) -> (usize, f64) {
    let mut ones = vec![0u64; rate_bits];
    for _ in 0..trials {
        let rb = random_bytes(rng, rate.len());
        let x = make_state(rate, &rb);
        let y = permute_rounds(&x, rounds);
        for (b, slot) in ones.iter_mut().enumerate() {
            *slot += get_rate_bit(&y, rate, b) as u64;
        }
    }
    let mut best = (0usize, 0f64);
    for (b, &c) in ones.iter().enumerate() {
        let z = z_score(c, trials as u64);
        if z.abs() > best.1.abs() {
            best = (b, z);
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Test B: single-bit differential propagation, fixed capacity
// ---------------------------------------------------------------------------
fn differential_scan(
    rate: &[usize],
    rate_bits: usize,
    rounds: u32,
    input_bit: usize,
    trials: usize,
    rng: &mut u64,
) -> (usize, f64) {
    let mut flips = vec![0u64; rate_bits];
    for _ in 0..trials {
        let rb = random_bytes(rng, rate.len());
        let x0 = make_state(rate, &rb);
        let mut x1 = x0;
        x1[rate[input_bit / 8]] ^= 1u8 << (input_bit % 8);

        let y0 = permute_rounds(&x0, rounds);
        let y1 = permute_rounds(&x1, rounds);
        for (b, slot) in flips.iter_mut().enumerate() {
            *slot += (get_rate_bit(&y0, rate, b) ^ get_rate_bit(&y1, rate, b)) as u64;
        }
    }
    let mut best = (0usize, 0f64);
    for (b, &c) in flips.iter().enumerate() {
        let z = z_score(c, trials as u64);
        if z.abs() > best.1.abs() {
            best = (b, z);
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Test C: random small-weight linear approximations, fixed capacity
// ---------------------------------------------------------------------------
fn random_mask(rng: &mut u64, universe: usize, weight: usize) -> Vec<usize> {
    let mut m = Vec::with_capacity(weight);
    while m.len() < weight {
        let b = (xorshift(rng) % universe as u64) as usize;
        if !m.contains(&b) {
            m.push(b);
        }
    }
    m
}

fn parity_over_mask(state: &Cube, rate: &[usize], mask: &[usize]) -> u8 {
    mask.iter().fold(0u8, |acc, &b| acc ^ get_rate_bit(state, rate, b))
}

fn linear_scan(
    rate: &[usize],
    rate_bits: usize,
    rounds: u32,
    num_masks: usize,
    samples_per_mask: usize,
    rng: &mut u64,
) -> (Vec<usize>, Vec<usize>, f64) {
    let mut best = (Vec::new(), Vec::new(), 0f64);
    for _ in 0..num_masks {
        let w_in = 1 + (xorshift(rng) % 4) as usize;
        let w_out = 1 + (xorshift(rng) % 4) as usize;
        let mask_in = random_mask(rng, rate_bits, w_in);
        let mask_out = random_mask(rng, rate_bits, w_out);

        let mut ones = 0u64;
        for _ in 0..samples_per_mask {
            let rb = random_bytes(rng, rate.len());
            let x = make_state(rate, &rb);
            let y = permute_rounds(&x, rounds);
            let bit = parity_over_mask(&x, rate, &mask_in) ^ parity_over_mask(&y, rate, &mask_out);
            ones += bit as u64;
        }
        let z = z_score(ones, samples_per_mask as u64);
        if z.abs() > best.2.abs() {
            best = (mask_in, mask_out, z);
        }
    }
    best
}

fn main() {
    let mut rng = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;

    let rate = rate_cells();
    let rate_bits = rate.len() * 8;

    println!("cube3d_sponge reduced-round distinguisher harness");
    println!(
        "rate = {} cells ({} bits), capacity fixed at 0 (matches Sponge::new()), toroidal N={}\n",
        rate.len(),
        rate_bits,
        N
    );
    println!("goal: find ANY statistic that separates reduced-round output from random.");
    println!("full ROUNDS={} is the design target; the interesting question is how far", ROUNDS);
    println!("below that a distinguisher still works.\n");

    let round_counts = [1u32, 2, 3, 4, 5, 6, 7, 8];
    let bias_trials = 20_000usize;
    let diff_trials = 20_000usize;
    let linear_masks = 60usize;
    let linear_samples = 1_500usize;

    println!("== Test A: single-bit output bias (fixed capacity=0, random rate input) ==");
    println!("rounds | worst rate-output bit | z-score");
    println!("-------+------------------------+--------");
    for &r in &round_counts {
        let (bit, z) = bit_bias_scan(&rate, rate_bits, r, bias_trials, &mut rng);
        println!("{:6} | {:22} | {:+.2}", r, bit, z);
    }

    println!("\n== Test B: single-bit differential propagation (input bit 0 flipped) ==");
    println!("rounds | worst rate-output bit | z-score (deviation from 50% flip prob)");
    println!("-------+------------------------+----------------------------------------");
    for &r in &round_counts {
        let (bit, z) = differential_scan(&rate, rate_bits, r, 0, diff_trials, &mut rng);
        println!("{:6} | {:22} | {:+.2}", r, bit, z);
    }

    println!("\n== Test C: random small-weight linear approximations ==");
    println!("({} random masks/round, {} samples/mask, weight 1..4 bits each side)\n", linear_masks, linear_samples);
    println!("rounds | best |in-mask| | best |out-mask| | z-score");
    println!("-------+--------------+---------------+--------");
    for &r in &round_counts {
        let (min, mout, z) = linear_scan(&rate, rate_bits, r, linear_masks, linear_samples, &mut rng);
        println!("{:6} | {:12} | {:13} | {:+.2}", r, min.len(), mout.len(), z);
    }

    println!("\ninterpretation:");
    println!("  * |z| under ~3 across the board: no distinguisher found at these sample sizes.");
    println!("    that's a NEGATIVE result, not a proof — it means this cheap search didn't");
    println!("    find one, not that a smarter attacker with a real LAT/DDT couldn't.");
    println!("  * |z| creeping up as rounds decrease is expected and healthy — the question");
    println!("    is which round is the LAST one where it's still near zero. that round,");
    println!("    not round 12, is your actual security margin baseline.");
    println!("  * a single wildly high |z| at low rounds (say round 1-2) is expected and fine;");
    println!("    watch for it surviving past round 5-6, which is the number you asked about.");
}
