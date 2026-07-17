//! attack — cube-attack KEY RECOVERY harness for cube3d_sponge.
//!
//! ============================ WHAT THIS IS ============================
//!
//! The distinguisher harness found a detectable differential bias out to round 6.
//! That is NOT a key-recovery attack, and the round-5 trail does not convert into
//! one. Distinguishing says "this output isn't random"; key recovery says "therefore
//! here are the key bits." The gap between the two is normally several rounds, and
//! measuring that gap honestly is the point of this file.
//!
//! The right tool for a sponge is the CUBE ATTACK (Dinur-Shamir 2009), the standard
//! weapon against Trivium / Ascon / Keccak-MAC-style constructions:
//!
//!   * every output bit is a polynomial over GF(2) in the key bits and nonce bits;
//!   * summing that output over ALL 2^d assignments of a chosen d-subset of nonce
//!     bits (the "cube") annihilates every monomial not containing the full cube,
//!     leaving the "superpoly" — the cofactor of the cube monomial;
//!   * if the polynomial's degree is <= d+1, that superpoly is LINEAR in the key
//!     bits: a free linear equation on the key.
//!
//! Collect enough independent linear superpolys, solve by Gaussian elimination.
//! Degree is the whole game: cube dimension d only linearises degree ~d+1, so as
//! rounds (and degree) climb, the required 2^d work explodes.
//!
//! ======================= CONE TARGETING (important) =======================
//!
//! A naive version of this harness draws random cubes from the whole nonce and
//! random output bits. That measures NOTHING at low rounds, because the permutation
//! is LOCAL: after 1-2 rounds an output bit depends on only a small neighbourhood,
//! so a random cube sits entirely outside its dependency cone and sums to zero —
//! not because the degree is low, but because those nonce bits don't reach that
//! output bit at all. The giveaway is a non-monotonic "degree" curve, which is
//! impossible and means the harness is broken.
//!
//! So this version first MEASURES the dependency cones:
//!   * key_influence(o)   = which key bits actually change output bit o
//!   * nonce_influence(o) = which nonce bits actually change output bit o
//! and only attacks output bits whose cone contains BOTH, drawing cube variables
//! exclusively from that bit's own nonce-influence set.
//!
//! ========================= THE ATTACK TARGET =========================
//!
//! This attacks a DELIBERATELY WEAKENED variant of the shipped construction:
//!
//!     shipped keystream():  absorb(key) -> permute -> absorb(nonce) -> permute -> squeeze
//!     attacked here:        state = key || nonce, ONE permute_r, read rate
//!
//! The shipped version puts a FULL permutation between the key and the attacker's
//! nonce, so the nonce never meets the raw key. The variant here lets them meet
//! immediately — exactly the Ascon/Keccak "init" model, and strictly EASIER to
//! attack. An attack that dies at round R against the weak variant means the
//! shipped construction survives AT LEAST R rounds: a lower bound on the real
//! thing's security, which is the useful direction for a defender. Claiming the
//! conservative result from a weakened variant is sound; claiming a strong result
//! from one would be cheating.
//!
//! ============================== HONESTY ==============================
//!
//! A negative result (no key bits at round R) means THIS attack, at THESE cube
//! dimensions, with THIS compute, found nothing. Not proof of security. Real cube
//! attacks use clever cube selection, division-property degree bounds, and orders
//! of magnitude more compute.

use cube3d_sponge::*;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const KEY_BYTES: usize = 16;
const KEY_BITS: usize = 128;
/// How many nonce bytes we actually use as attacker-controlled variables.
const NONCE_BYTES: usize = 64;
const NONCE_BITS: usize = NONCE_BYTES * 8;

type Key = [u8; KEY_BYTES];
type Nonce = [u8; NONCE_BYTES];

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

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

fn unit_key(bit: usize) -> Key {
    let mut k = [0u8; KEY_BYTES];
    k[bit / 8] = 1u8 << (bit % 8);
    k
}

fn xor_keys(a: &Key, b: &Key) -> Key {
    let mut o = [0u8; KEY_BYTES];
    for i in 0..KEY_BYTES {
        o[i] = a[i] ^ b[i];
    }
    o
}

fn key_bit(k: &Key, bit: usize) -> u8 {
    (k[bit / 8] >> (bit % 8)) & 1
}

#[inline]
fn toggle_nonce_bit(n: &mut Nonce, bit: usize) {
    n[bit / 8] ^= 1u8 << (bit % 8);
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

/// The attacked construction: key in the first KEY_BYTES rate cells, nonce in the
/// next NONCE_BYTES rate cells, capacity zero, one reduced-round permutation,
/// output is the rate.
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

/// Which key bits actually influence output bit `o` at this round count?
fn key_influence(o: usize, rounds: u32, rate: &[usize], probes: usize, rng: &mut u64) -> Vec<usize> {
    let mut infl = Vec::new();
    for j in 0..KEY_BITS {
        let mut moves = false;
        for _ in 0..probes {
            let k = random_key(rng);
            let n = random_nonce(rng);
            let k2 = xor_keys(&k, &unit_key(j));
            if out_bit(&k, &n, rounds, o, rate) != out_bit(&k2, &n, rounds, o, rate) {
                moves = true;
                break;
            }
        }
        if moves {
            infl.push(j);
        }
    }
    infl
}

/// Which nonce bits actually influence output bit `o` at this round count?
fn nonce_influence(o: usize, rounds: u32, rate: &[usize], probes: usize, rng: &mut u64) -> Vec<usize> {
    let mut infl = Vec::new();
    for b in 0..NONCE_BITS {
        let mut moves = false;
        for _ in 0..probes {
            let k = random_key(rng);
            let n = random_nonce(rng);
            let mut n2 = n;
            toggle_nonce_bit(&mut n2, b);
            if out_bit(&k, &n, rounds, o, rate) != out_bit(&k, &n2, rounds, o, rate) {
                moves = true;
                break;
            }
        }
        if moves {
            infl.push(b);
        }
    }
    infl
}

/// Sum the output bit over all 2^d assignments of the cube variables (all other
/// nonce bits held at zero). This is the superpoly evaluated at `key`.
fn cube_sum(key: &Key, cube: &[usize], rounds: u32, o: usize, rate: &[usize]) -> u8 {
    let d = cube.len();
    let mut acc = 0u8;
    let mut n: Nonce = [0u8; NONCE_BYTES];
    for mask in 0u64..(1u64 << d) {
        for (k, &cb) in cube.iter().enumerate() {
            set_nonce_bit(&mut n, cb, ((mask >> k) & 1) as u8);
        }
        acc ^= out_bit(key, &n, rounds, o, rate);
    }
    acc
}

fn pick_cube(pool: &[usize], d: usize, rng: &mut u64) -> Vec<usize> {
    let mut c: Vec<usize> = Vec::with_capacity(d);
    let mut guard = 0;
    while c.len() < d && guard < 10_000 {
        guard += 1;
        let b = pool[(xorshift(rng) % pool.len() as u64) as usize];
        if !c.contains(&b) {
            c.push(b);
        }
    }
    c
}

/// Blum-Luby-Rubinfeld linearity test: linear p satisfies p(x)^p(y)^p(0) == p(x^y).
/// Random sampling, so passing is evidence, not proof.
fn blr_linear(
    cube: &[usize],
    rounds: u32,
    o: usize,
    rate: &[usize],
    c0: u8,
    trials: usize,
    rng: &mut u64,
) -> bool {
    for _ in 0..trials {
        let x = random_key(rng);
        let y = random_key(rng);
        let xy = xor_keys(&x, &y);
        let px = cube_sum(&x, cube, rounds, o, rate);
        let py = cube_sum(&y, cube, rounds, o, rate);
        let pxy = cube_sum(&xy, cube, rounds, o, rate);
        if px ^ py ^ c0 != pxy {
            return false;
        }
    }
    true
}

/// Cheap pre-filter: is the superpoly non-constant in the key? A constant superpoly
/// passes the BLR test trivially (c^c^c == c) but carries zero information, so reject
/// it here for 3*2^d work rather than discovering it after a 128*2^d coefficient scan.
fn superpoly_nonconstant(
    cube: &[usize],
    rounds: u32,
    o: usize,
    rate: &[usize],
    c0: u8,
    trials: usize,
    rng: &mut u64,
) -> bool {
    for _ in 0..trials {
        let k = random_key(rng);
        if cube_sum(&k, cube, rounds, o, rate) != c0 {
            return true;
        }
    }
    false
}

/// Offline phase: superpoly linear coefficients, coeff_j = p(e_j)^p(0).
/// The expensive step (|key_pool| * 2^d), so it runs LAST, only on cubes that already
/// survived the constancy and linearity filters.
fn superpoly_coeffs(
    cube: &[usize],
    rounds: u32,
    o: usize,
    rate: &[usize],
    key_pool: &[usize],
    c0: u8,
) -> u128 {
    let mut mask: u128 = 0;
    for &j in key_pool {
        if cube_sum(&unit_key(j), cube, rounds, o, rate) ^ c0 == 1 {
            mask |= 1u128 << j;
        }
    }
    mask
}

/// GF(2) reduced row echelon form. Returns rank.
fn rref(rows: &mut Vec<(u128, u8)>) -> usize {
    let mut rank = 0usize;
    for col in 0..KEY_BITS {
        let mut pivot = None;
        for i in rank..rows.len() {
            if (rows[i].0 >> col) & 1 == 1 {
                pivot = Some(i);
                break;
            }
        }
        if let Some(p) = pivot {
            rows.swap(rank, p);
            let (prow, prhs) = rows[rank];
            for i in 0..rows.len() {
                if i != rank && (rows[i].0 >> col) & 1 == 1 {
                    rows[i].0 ^= prow;
                    rows[i].1 ^= prhs;
                }
            }
            rank += 1;
        }
    }
    rank
}

fn main() {
    let mut rng = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;

    let rate = rate_cells();
    let out_bits_total = rate.len() * 8;

    println!("cube3d_sponge — cube attack key-recovery harness");
    println!(
        "target: state = key({}B) || nonce({}B) || capacity(0) -> permute_r -> read rate",
        KEY_BYTES, NONCE_BYTES
    );
    println!("(weakened variant: key and nonce meet with NO permutation between them, unlike");
    println!(" the shipped keystream(). results here LOWER-BOUND the shipped construction.)\n");

    // -----------------------------------------------------------------
    // Phase A: dependency cone growth
    // -----------------------------------------------------------------
    println!("== Phase A: dependency cones ==");
    println!("for a sampled output bit: how many key bits and nonce bits actually reach it?");
    println!("a cube attack needs an output bit whose cone contains BOTH — otherwise the");
    println!("superpoly is constant in the key and carries no information.\n");

    // At low rounds the cones are TINY, so random sampling of output bits finds no
    // attackable target and reports a false negative. Scan every output bit instead,
    // using the cheaper key-cone test as a filter before the nonce-cone test. At high
    // rounds the cones saturate and sampling is fine (and a full scan is unaffordable).
    const MAX_TARGETS: usize = 32;

    println!("rounds | scan  | out-bits w/ key cone | avg |key cone| | avg |nonce cone| | targets");
    println!("-------+-------+----------------------+----------------+------------------+--------");

    let mut attackable: Vec<Vec<(usize, Vec<usize>, Vec<usize>)>> = vec![Vec::new(); 7];
    for r in 1..=5u32 {
        let full_scan = r <= 2;
        let scan_list: Vec<usize> = if full_scan {
            (0..out_bits_total).collect()
        } else {
            (0..48)
                .map(|_| (xorshift(&mut rng) % out_bits_total as u64) as usize)
                .collect()
        };

        let mut with_key = 0usize;
        let mut ksum = 0usize;
        let mut nsum = 0usize;
        let mut ncount = 0usize;

        for &o in &scan_list {
            let ki = key_influence(o, r, &rate, 6, &mut rng);
            if ki.is_empty() {
                continue; // no key dependence -> superpoly is constant in the key
            }
            with_key += 1;
            ksum += ki.len();

            if attackable[r as usize].len() >= MAX_TARGETS {
                continue; // cone stats only from here; Phase B budget is already full
            }
            let ni = nonce_influence(o, r, &rate, 6, &mut rng);
            nsum += ni.len();
            ncount += 1;
            if ni.len() >= 2 {
                attackable[r as usize].push((o, ki, ni));
            }
        }

        println!(
            "{:6} | {:5} | {:20} | {:14.1} | {:16.1} | {}",
            r,
            if full_scan { "full" } else { "sample" },
            format!("{} of {}", with_key, scan_list.len()),
            if with_key > 0 { ksum as f64 / with_key as f64 } else { 0.0 },
            if ncount > 0 { nsum as f64 / ncount as f64 } else { 0.0 },
            attackable[r as usize].len()
        );
    }

    // -----------------------------------------------------------------
    // Phase B: key recovery
    // -----------------------------------------------------------------
    println!("\n== Phase B: cube attack key recovery ==");
    let secret = random_key(&mut rng);
    print!("secret key (attack code touches it only via out_bit()): ");
    for b in secret.iter() {
        print!("{:02x}", b);
    }
    println!("\n");

    println!("rounds | cubes tried | linear superpolys | rank | keyspace | bits pinned | time");
    println!("-------+-------------+-------------------+------+----------+-------------+------");

    for r in 1..=5u32 {
        let t0 = Instant::now();
        let targets = &attackable[r as usize];
        if targets.is_empty() {
            println!(
                "{:6} | {:11} | {:17} | {:4} | 2^{:<6} | {:11} | {:.1}s",
                r, 0, 0, 0, KEY_BITS, "no target", t0.elapsed().as_secs_f64()
            );
            continue;
        }

        let mut equations: Vec<(u128, u8)> = Vec::new();
        let mut cubes_tried = 0usize;
        let mut linear_found = 0usize;

        // Cost of one cube is dominated by 2^d permutations, each costing ~4us*r.
        // Cube dimension d only linearises degree ~d+1, and degree grows ~4^r, so the
        // required d outruns any affordable budget almost immediately. These caps are
        // the honest compute ceiling, not a claim about what's cryptanalytically possible.
        let (d_lo, d_hi, budget) = match r {
            1 => (2usize, 6usize, 400usize),
            2 => (3, 12, 120),
            3 => (6, 12, 30),
            4 => (8, 12, 10),
            _ => (8, 12, 8),
        };

        'outer: for &(o, ref ki, ref ni) in targets.iter() {
            let hi = d_hi.min(ni.len());
            if hi < d_lo {
                continue;
            }
            for d in d_lo..=hi {
                let reps = (budget / targets.len().max(1) / (hi - d_lo + 1).max(1)) + 1;
                for _ in 0..reps {
                    if cubes_tried >= budget || equations.len() >= KEY_BITS + 8 {
                        break 'outer;
                    }
                    let cube = pick_cube(ni, d, &mut rng);
                    if cube.len() < d {
                        continue;
                    }
                    cubes_tried += 1;

                    // Cheap rejects first, expensive coefficient scan last.
                    let zero: Key = [0u8; KEY_BYTES];
                    let c0 = cube_sum(&zero, &cube, r, o, &rate);
                    if !superpoly_nonconstant(&cube, r, o, &rate, c0, 3, &mut rng) {
                        continue; // constant in the key -> no information
                    }
                    if !blr_linear(&cube, r, o, &rate, c0, 5, &mut rng) {
                        continue; // nonlinear superpoly -> unusable as a linear equation
                    }
                    let mask = superpoly_coeffs(&cube, r, o, &rate, ki, c0);
                    if mask == 0 {
                        continue;
                    }
                    linear_found += 1;

                    // ONLINE phase: query the real cipher with the secret key.
                    let observed = cube_sum(&secret, &cube, r, o, &rate);
                    equations.push((mask, observed ^ c0));
                }
            }
        }

        let mut rows = equations.clone();
        let rank = rref(&mut rows);

        let mut verified = 0usize;
        let mut wrong = 0usize;
        for &(m, rhs) in rows.iter() {
            if m.count_ones() == 1 {
                let j = m.trailing_zeros() as usize;
                if key_bit(&secret, j) == rhs {
                    verified += 1;
                } else {
                    wrong += 1;
                }
            }
        }

        println!(
            "{:6} | {:11} | {:17} | {:4} | 2^{:<6} | {:11} | {:.1}s",
            r,
            cubes_tried,
            linear_found,
            rank,
            KEY_BITS - rank,
            if wrong == 0 {
                format!("{} ok", verified)
            } else {
                format!("{} WRONG", wrong)
            },
            t0.elapsed().as_secs_f64()
        );
    }

    println!("\ninterpretation:");
    println!("  * 'rank' = independent linear equations on the key. keyspace drops from 2^128");
    println!("    to 2^(128-rank). rank 128 = full recovery. rank 0 = this attack found nothing.");
    println!("  * 'bits pinned' = RREF rows with a single set bit, checked against the real key.");
    println!("    any WRONG means BLR passed a nonlinear superpoly (it's probabilistic) — that's");
    println!("    a harness signal, not a cipher property.");
    println!("  * the cone columns in Phase A explain the ladder: once the nonce cone saturates,");
    println!("    the degree is too high for any affordable cube dimension and the attack dies.");
}
