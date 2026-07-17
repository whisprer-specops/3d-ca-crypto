use cube3d_sponge::*;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_R: usize = 16;
const TRIALS: usize = 64;
const TOTAL_BITS: u32 = (CELLS * 8) as u32;

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn random_cube(rng: &mut u64) -> Cube {
    let mut c = [0u8; CELLS];
    for b in c.iter_mut() {
        *b = (xorshift(rng) & 0xFF) as u8;
    }
    c
}

fn hamming(a: &Cube, b: &Cube) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn shell_hamming(a: &Cube, b: &Cube, want_rate: bool) -> (u32, u32) {
    let mut diff = 0u32;
    let mut total = 0u32;
    for i in 0..CELLS {
        if is_rate(i) == want_rate {
            diff += (a[i] ^ b[i]).count_ones();
            total += 8;
        }
    }
    (diff, total)
}

/// OR of every difference byte. A set bit at position k means "bit-plane k has been
/// disturbed somewhere in the cube". Counting them tells you how many of the 8
/// planes the flipped bit has managed to reach.
fn planes_touched(a: &Cube, b: &Cube) -> u32 {
    let mut mask = 0u8;
    for i in 0..CELLS {
        mask |= a[i] ^ b[i];
    }
    mask.count_ones()
}

fn main() {
    let mut rng = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;

    println!("cube3d_sponge avalanche harness");
    println!(
        "cube {n}x{n}x{n} = {c} cells / {tb} bits, rate={r} bytes, capacity={cap} bytes",
        n = N,
        c = CELLS,
        tb = TOTAL_BITS,
        r = Sponge::rate_len(),
        cap = Sponge::capacity_len()
    );
    println!("round structure: feistel(chi3) -> rho(byte rotate) -> pi(shear transpose)\n");

    // ---------------------------------------------------------------
    // Part 1: strict avalanche ramp from a single flipped bit
    // ---------------------------------------------------------------
    println!("== Part 1: single-bit avalanche ramp ==");
    println!(
        "random state, flip exactly 1 of {} bits, step rounds. avg over {} trials.\n",
        TOTAL_BITS, TRIALS
    );

    let mut tot = [0u64; MAX_R + 1];
    let mut rat = [0u64; MAX_R + 1];
    let mut cap = [0u64; MAX_R + 1];
    let mut rat_den = [0u64; MAX_R + 1];
    let mut cap_den = [0u64; MAX_R + 1];
    let mut planes = [0u64; MAX_R + 1];

    for _ in 0..TRIALS {
        let s = random_cube(&mut rng);
        let bit = (xorshift(&mut rng) % TOTAL_BITS as u64) as usize;
        let mut t = s;
        t[bit / 8] ^= 1u8 << (bit % 8);

        let mut a = s;
        let mut b = t;
        for r in 0..=MAX_R {
            tot[r] += hamming(&a, &b) as u64;
            let (rd, rt) = shell_hamming(&a, &b, true);
            let (cd, ct) = shell_hamming(&a, &b, false);
            rat[r] += rd as u64;
            rat_den[r] += rt as u64;
            cap[r] += cd as u64;
            cap_den[r] += ct as u64;
            planes[r] += planes_touched(&a, &b) as u64;

            a = round_forward(&a, r as u32);
            b = round_forward(&b, r as u32);
        }
    }

    println!("rounds | total diff % | rate-shell % | capacity-shell % | bit-planes hit (of 8)");
    println!("-------+--------------+--------------+------------------+----------------------");
    for r in 0..=MAX_R {
        let denom = (TRIALS as u64 * TOTAL_BITS as u64) as f64;
        println!(
            "{:6} | {:11.2}% | {:11.2}% | {:15.2}% | {:.2}",
            r,
            100.0 * tot[r] as f64 / denom,
            100.0 * rat[r] as f64 / rat_den[r] as f64,
            100.0 * cap[r] as f64 / cap_den[r] as f64,
            planes[r] as f64 / TRIALS as f64
        );
    }

    println!("\nread this as:");
    println!("  * total diff % should climb from ~0.02% (1 bit) toward ~50%. the round where");
    println!("    it first settles at ~50%, roughly doubled, is a sane floor for ROUNDS.");
    println!("  * bit-planes hit MUST climb to 8.00. if it pins at 1.00, the byte-lanes are");
    println!("    uncoupled and 7/8 of the state is dead weight — the diffusion ceiling is");
    println!("    then 512/2/4096 = 6.25%, which is a plateau, not a slow ramp.");
    println!("  * capacity-shell % should track rate-shell %, not lag it permanently.");

    // ---------------------------------------------------------------
    // Part 2: does the real construction saturate after a key absorb?
    // ---------------------------------------------------------------
    println!("\n== Part 2: post-absorb saturation ==");
    println!("flip 1 key bit, absorb key+nonce through the full sponge, compare states.\n");

    let key = b"avalanche-test-key-0123456789ab";
    let nonce = b"fixed-nonce";

    let mut base = Sponge::new();
    base.absorb(key);
    base.absorb(nonce);

    let mut key2 = key.to_vec();
    key2[0] ^= 0x01;
    let mut flipped = Sponge::new();
    flipped.absorb(&key2);
    flipped.absorb(nonce);

    let d = hamming(&base.state, &flipped.state);
    let (rd, rt) = shell_hamming(&base.state, &flipped.state, true);
    let (cd, ct) = shell_hamming(&base.state, &flipped.state, false);
    let p = planes_touched(&base.state, &flipped.state);

    println!("  total state diff : {:.2}%", 100.0 * d as f64 / TOTAL_BITS as f64);
    println!("  rate shell diff  : {:.2}%", 100.0 * rd as f64 / rt as f64);
    println!("  capacity diff    : {:.2}%", 100.0 * cd as f64 / ct as f64);
    println!("  bit-planes hit   : {} of 8", p);

    // ---------------------------------------------------------------
    // Part 3: keystream sanity
    // ---------------------------------------------------------------
    println!("\n== Part 3: keystream bit balance ==");
    let ks = keystream(key, nonce, 4096);
    let ones: u32 = ks.iter().map(|b| b.count_ones()).sum();
    println!(
        "  {} bytes squeezed, {:.2}% ones (want ~50%)",
        ks.len(),
        100.0 * ones as f64 / (ks.len() * 8) as f64
    );
    println!("\n  (a balanced bit count is the weakest possible signal — it says nothing about");
    println!("   independence. run PractRand/TestU01 over a real squeeze if you want a verdict.)");
}
