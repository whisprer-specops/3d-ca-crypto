//! cube3d_sponge — a research permutation, NOT an audited cipher.
//!
//! Geometry: an 8x8x8 cube of bytes (512 cells / 4096 bits). N is deliberately EVEN:
//! a checkerboard 2-colouring of a torus only stays consistent across the wrap-around
//! edge when the side length is even (an odd-length cycle isn't 2-colourable at all).
//! N=7 silently breaks the invertibility proof below; N=8 doesn't.
//!
//! The cube's cells are classified two independent ways:
//!
//!   1. Distance-from-centre shell -> concentric cubic shells, radius 0..=3. The
//!      innermost shell (radius 0) is a literal 2x2x2 CENTRAL CUBE (8 cells) —
//!      the geometry the original idea described. Radius 3 (the outermost shell,
//!      296 cells) is the SPONGE RATE: the only cells absorb()/squeeze() ever
//!      touch. Radius 0..2 (216 cells) is the SPONGE CAPACITY: never written or
//!      read directly by the outside world. This is the legitimate use of
//!      "concentric shells" in a cryptographic construction — a rate/capacity
//!      split, not "more radiating = more mixing."
//!
//!   2. Parity of (x+y+z) -> a 3D checkerboard bipartition, colour A / colour B.
//!      Every face-adjacent neighbour of a cell has the OPPOSITE colour (true on
//!      an even-sided torus), which is exactly the property a Feistel network
//!      needs: "each half's update function reads only the other half."
//!
//! ROUND STRUCTURE (all three steps individually invertible, so the composition is):
//!
//!   1. FEISTEL: A ^= chi3(B); inject round constant; B ^= chi3(A').
//!      Provides NONLINEARITY (chi3's AND terms) and is invertible for ANY chi3.
//!   2. RHO: rotate each cell's byte left by a per-cell offset.
//!      Provides BIT-PLANE COUPLING. See the note below — this step is load-bearing.
//!   3. PI: transpose cell positions by a shear mod 8.
//!      Provides LONG-RANGE TRANSPOSITION and destroys the regular lattice adjacency
//!      structure that differential attacks feed on.
//!
//! WHY RHO EXISTS — the bug it fixes:
//!
//! chi3 operates on u8 cells with bitwise AND/NOT/XOR. Bitwise ops act on all 8 bits
//! of a byte in parallel but INDEPENDENTLY: bit k of the output depends only on bit k
//! of the inputs. Without rho, the 8x8x8 cube of BYTES is therefore not one 4096-bit
//! state at all — it is eight totally independent, non-interacting 512-bit binary CAs
//! stacked in the same memory. A single flipped bit can never leave its own bit-plane,
//! so avalanche saturates at 50% of 512 bits = 256 bits = 6.25% of 4096, and sits
//! there forever no matter how many rounds you run.
//!
//! That is exactly the ~6.3% flat plateau the first version of this code measured.
//! The reach was never the problem (an 8-torus has diameter 4 per axis and a Feistel
//! round moves information 2 hops, so chi3 alone floods the cube in ~3 rounds).
//! The problem was that 7/8 of the state was unreachable BY CONSTRUCTION.
//!
//! rho fixes it: neighbouring cells get different rotation offsets, so bit k of a cell
//! comes to depend on bit k-r(j) of neighbour j. The planes couple. This is the same
//! job Keccak's rho does — and it is why Keccak has a rho at all.

pub const N: usize = 8;
pub const CELLS: usize = N * N * N; // 512

pub type Cube = [u8; CELLS];

pub const ROUNDS: u32 = 12;
pub const OUTER_RADIUS: usize = 3;

#[inline]
pub fn idx(x: usize, y: usize, z: usize) -> usize {
    x + y * N + z * N * N
}

#[inline]
pub fn coords(i: usize) -> (usize, usize, usize) {
    let x = i % N;
    let y = (i / N) % N;
    let z = i / (N * N);
    (x, y, z)
}

/// Per-axis distance from the centre PAIR (3,4) — N is even, so there's no single
/// centre coordinate, only a centre pair. axis_shell(3)=axis_shell(4)=0, growing
/// outward to axis_shell(0)=axis_shell(7)=3.
#[inline]
fn axis_shell(v: usize) -> usize {
    let a = (v as isize - 3).unsigned_abs();
    let b = (v as isize - 4).unsigned_abs();
    a.min(b)
}

/// Concentric-cube shell index: 0 = the innermost 2x2x2 central cube, up to
/// OUTER_RADIUS = the outermost face shell.
#[inline]
pub fn radius(i: usize) -> usize {
    let (x, y, z) = coords(i);
    axis_shell(x).max(axis_shell(y)).max(axis_shell(z))
}

/// Checkerboard colour: 0 or 1. Face-adjacent cells always differ in colour.
#[inline]
pub fn color(i: usize) -> u8 {
    let (x, y, z) = coords(i);
    ((x + y + z) & 1) as u8
}

#[inline]
pub fn is_rate(i: usize) -> bool {
    radius(i) == OUTER_RADIUS
}

pub fn rate_cells() -> Vec<usize> {
    (0..CELLS).filter(|&i| is_rate(i)).collect()
}

pub fn capacity_cells() -> Vec<usize> {
    (0..CELLS).filter(|&i| !is_rate(i)).collect()
}

/// The 6 toroidal face-neighbours of a cell. Wrapping (rather than clamping at the
/// cube's physical edge) is what gives every cell an identical neighbourhood shape —
/// without it, shell-boundary cells would diffuse differently from interior cells.
#[inline]
fn neighbors6(i: usize) -> [usize; 6] {
    let (x, y, z) = coords(i);
    [
        idx((x + 1) % N, y, z),
        idx((x + N - 1) % N, y, z),
        idx(x, (y + 1) % N, z),
        idx(x, (y + N - 1) % N, z),
        idx(x, y, (z + 1) % N),
        idx(x, y, (z + N - 1) % N),
    ]
}

// ---------------------------------------------------------------------------
// Precomputed geometry tables.
//
// Pure speed, zero semantic change: coords() costs two integer divisions and gets
// called ~4000 times per round. The cube3d_sponge attack harness runs millions of
// permutations, so these tables are the difference between a 10-minute run and an
// hour. Every table below is just the eager form of the function above it, and the
// existing unit tests still pass unchanged — which is exactly how you check an
// optimisation didn't quietly alter behaviour.
// ---------------------------------------------------------------------------

pub struct Tables {
    pub nbrs: Vec<[usize; 6]>,
    pub rho_off: Vec<u32>,
    pub pi_fwd: Vec<usize>,
    pub a_cells: Vec<usize>,
    pub b_cells: Vec<usize>,
}

fn build_tables() -> Tables {
    Tables {
        nbrs: (0..CELLS).map(neighbors6).collect(),
        rho_off: (0..CELLS).map(rho_offset).collect(),
        pi_fwd: (0..CELLS).map(pi_map).collect(),
        a_cells: (0..CELLS).filter(|&i| color(i) == 0).collect(),
        b_cells: (0..CELLS).filter(|&i| color(i) == 1).collect(),
    }
}

pub fn tables() -> &'static Tables {
    static T: std::sync::OnceLock<Tables> = std::sync::OnceLock::new();
    T.get_or_init(build_tables)
}

/// Nonlinear per-cell mixing function: three independent Chi-style AND terms
/// (same family as Keccak's chi — the one nonlinear step that makes it secure)
/// over the cell's 6 toroidal neighbours. `round` rotates which neighbour pairs
/// get combined.
#[inline]
fn chi3(state: &Cube, i: usize, round: u32) -> u8 {
    let nbrs = tables().nbrs[i];
    let r = (round % 3) as usize;
    let a = nbrs[(2 * r) % 6];
    let b = nbrs[(1 + 2 * r) % 6];
    let c = nbrs[(2 + 2 * r) % 6];
    let d = nbrs[(3 + 2 * r) % 6];
    let e = nbrs[(4 + 2 * r) % 6];
    let f = nbrs[(5 + 2 * r) % 6];
    (!state[a] & state[b]) ^ (!state[c] & state[d]) ^ (!state[e] & state[f])
}

/// Round constant schedule. Not cryptographically special — just cheap, distinct
/// per round, and enough to guarantee round_forward(_, r) != round_forward(_, r')
/// for r != r'. See slide_test.rs.
pub fn round_constant(round: u32) -> u8 {
    let mut x = round.wrapping_mul(0x9E37_79B1) ^ 0xA5A5_A5A5;
    x ^= x >> 15;
    x = x.wrapping_mul(0x85EB_CA6B);
    x ^= x >> 13;
    (x & 0xFF) as u8
}

// ---------------------------------------------------------------------------
// RHO — per-cell byte rotation. The bit-plane coupling step.
// ---------------------------------------------------------------------------

/// Rotation offset for a cell, 0..=7. The coefficients are coprime-ish spreads so
/// that face-adjacent cells reliably get DIFFERENT offsets — which is the whole
/// point: equal offsets on neighbours would cancel out and leave the planes
/// uncoupled again.
#[inline]
pub fn rho_offset(i: usize) -> u32 {
    let (x, y, z) = coords(i);
    ((x + 3 * y + 5 * z) & 7) as u32
}

fn rho(state: &Cube) -> Cube {
    let t = tables();
    let mut out = [0u8; CELLS];
    for i in 0..CELLS {
        out[i] = state[i].rotate_left(t.rho_off[i]);
    }
    out
}

fn rho_inv(state: &Cube) -> Cube {
    let t = tables();
    let mut out = [0u8; CELLS];
    for i in 0..CELLS {
        out[i] = state[i].rotate_right(t.rho_off[i]);
    }
    out
}

// ---------------------------------------------------------------------------
// PI — cell transposition. A shear on coordinates mod 8.
// ---------------------------------------------------------------------------

/// Forward shear. Invertible by construction: the system is triangular, so it
/// unwinds in reverse order (see pi_unmap). Note this deliberately moves cells
/// ACROSS shells — the rate/capacity split is positional, exactly as Keccak's rate
/// is "the first r bits of the state" while pi shuffles bits through those positions.
#[inline]
pub fn pi_map(i: usize) -> usize {
    let (x, y, z) = coords(i);
    let x1 = (x + y) & 7;
    let y1 = (y + z) & 7;
    let z1 = (z + x1) & 7;
    idx(x1, y1, z1)
}

/// Inverse shear, unwound in reverse: z from z1 and x1, then y from y1 and z,
/// then x from x1 and y.
#[inline]
pub fn pi_unmap(i: usize) -> usize {
    let (x1, y1, z1) = coords(i);
    let z = (z1 + 8 - x1) & 7;
    let y = (y1 + 8 - z) & 7;
    let x = (x1 + 8 - y) & 7;
    idx(x, y, z)
}

fn pi(state: &Cube) -> Cube {
    let t = tables();
    let mut out = [0u8; CELLS];
    for i in 0..CELLS {
        out[t.pi_fwd[i]] = state[i];
    }
    out
}

fn pi_inv(state: &Cube) -> Cube {
    let t = tables();
    let mut out = [0u8; CELLS];
    for i in 0..CELLS {
        out[i] = state[t.pi_fwd[i]];
    }
    out
}

// ---------------------------------------------------------------------------
// Feistel core + full round
// ---------------------------------------------------------------------------

/// The Feistel half of a round, with constant injection optionally disabled (used
/// only by slide_test.rs to demonstrate why the constant is load-bearing).
///
///   1. A1[i]  = A0[i] XOR chi3(B0, i)              for every colour-A cell i
///   2. A1c    = A1, with round_constant XORed into cell 0 only
///   3. B1[i]  = B0[i] XOR chi3(A1c, i)              for every colour-B cell i
pub fn feistel_variant(state: &Cube, round: u32, use_constant: bool) -> Cube {
    let mut out = *state;
    for i in 0..CELLS {
        if color(i) == 0 {
            out[i] = state[i] ^ chi3(state, i, round);
        }
    }
    if use_constant {
        out[0] ^= round_constant(round); // cell 0 is colour A
    }
    let a1c_snapshot = out;
    for i in 0..CELLS {
        if color(i) == 1 {
            out[i] = state[i] ^ chi3(&a1c_snapshot, i, round);
        }
    }
    out
}

/// Exact inverse of feistel_variant(_, round, true).
pub fn feistel_inverse(state: &Cube, round: u32) -> Cube {
    let mut cur = *state; // colour-A cells hold A1c, colour-B cells hold B1
    let a1c_snapshot = cur;
    for i in 0..CELLS {
        if color(i) == 1 {
            cur[i] = state[i] ^ chi3(&a1c_snapshot, i, round); // recover B0
        }
    }
    cur[0] ^= round_constant(round); // undo constant -> colour-A cells now hold A1
    let b0_snapshot = cur;
    for i in 0..CELLS {
        if color(i) == 0 {
            cur[i] ^= chi3(&b0_snapshot, i, round); // recover A0
        }
    }
    cur
}

/// Full round: feistel -> rho -> pi.
pub fn round_forward_variant(state: &Cube, round: u32, use_constant: bool) -> Cube {
    let s = feistel_variant(state, round, use_constant);
    let s = rho(&s);
    pi(&s)
}

#[inline]
pub fn round_forward(state: &Cube, round: u32) -> Cube {
    round_forward_variant(state, round, true)
}

/// Full round inverse: pi_inv -> rho_inv -> feistel_inverse.
pub fn round_inverse(state: &Cube, round: u32) -> Cube {
    let s = pi_inv(state);
    let s = rho_inv(&s);
    feistel_inverse(&s, round)
}

/// Reduced-round permutation. `permute` is exactly `permute_r(state, ROUNDS)`.
/// Exposed so the cryptanalysis harnesses can climb the round ladder.
pub fn permute_r(state: &Cube, rounds: u32) -> Cube {
    let mut s = *state;
    for r in 0..rounds {
        s = round_forward(&s, r);
    }
    s
}

pub fn permute_inverse_r(state: &Cube, rounds: u32) -> Cube {
    let mut s = *state;
    for r in (0..rounds).rev() {
        s = round_inverse(&s, r);
    }
    s
}

pub fn permute(state: &Cube) -> Cube {
    permute_r(state, ROUNDS)
}

pub fn permute_inverse(state: &Cube) -> Cube {
    permute_inverse_r(state, ROUNDS)
}

// ---------------------------------------------------------------------------
// Sponge
// ---------------------------------------------------------------------------

/// A duplex sponge over the cube. absorb()/squeeze() only ever touch rate cells
/// (radius == OUTER_RADIUS); the capacity (radius < OUTER_RADIUS) is only ever
/// touched indirectly, through the permutation's mixing.
///
/// NOTE: this gives you a keystream generator (XOR stream cipher), nothing more.
/// There is no authentication tag / MAC here. Do not use this for anything that
/// needs integrity — pair it with a real MAC, or better, don't use it for anything
/// real at all. It exists to be measured and attacked.
pub struct Sponge {
    pub state: Cube,
}

impl Sponge {
    pub fn new() -> Self {
        Sponge { state: [0u8; CELLS] }
    }

    pub fn rate_len() -> usize {
        rate_cells().len()
    }

    pub fn capacity_len() -> usize {
        capacity_cells().len()
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let rate = rate_cells();
        assert!(
            data.len() <= rate.len(),
            "absorb() block ({} bytes) exceeds rate ({} bytes) — chunk it first",
            data.len(),
            rate.len()
        );
        for (n, &cell) in rate.iter().enumerate() {
            if n < data.len() {
                self.state[cell] ^= data[n];
            }
        }
        self.state = permute(&self.state);
    }

    pub fn squeeze(&mut self, out_len: usize) -> Vec<u8> {
        let rate = rate_cells();
        let mut out = Vec::with_capacity(out_len);
        loop {
            for &cell in &rate {
                if out.len() >= out_len {
                    return out;
                }
                out.push(self.state[cell]);
            }
            self.state = permute(&self.state);
        }
    }
}

impl Default for Sponge {
    fn default() -> Self {
        Self::new()
    }
}

pub fn keystream(key: &[u8], nonce: &[u8], len: usize) -> Vec<u8> {
    let mut sp = Sponge::new();
    let rate = Sponge::rate_len();
    for chunk in key.chunks(rate) {
        sp.absorb(chunk);
    }
    for chunk in nonce.chunks(rate) {
        sp.absorb(chunk);
    }
    sp.squeeze(len)
}

pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let ks = keystream(key, nonce, plaintext.len());
    plaintext.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect()
}

pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    encrypt(key, nonce, ciphertext) // XOR keystream cipher is its own inverse
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn sample_cube(mul: usize, add: usize) -> Cube {
        let mut s = [0u8; CELLS];
        for (i, b) in s.iter_mut().enumerate() {
            *b = ((i * mul + add) % 256) as u8;
        }
        s
    }

    #[test]
    fn pi_is_a_bijection() {
        let images: HashSet<usize> = (0..CELLS).map(pi_map).collect();
        assert_eq!(images.len(), CELLS, "pi_map collides — not a permutation");
    }

    #[test]
    fn pi_unmap_inverts_pi_map() {
        for i in 0..CELLS {
            assert_eq!(pi_unmap(pi_map(i)), i, "pi_unmap failed at cell {}", i);
        }
    }

    #[test]
    fn rho_roundtrips() {
        let s = sample_cube(53, 9);
        assert_eq!(rho_inv(&rho(&s)), s);
    }

    #[test]
    fn pi_roundtrips() {
        let s = sample_cube(29, 3);
        assert_eq!(pi_inv(&pi(&s)), s);
    }

    #[test]
    fn single_round_invertible() {
        let s = sample_cube(37, 11);
        for r in 0..5 {
            let s1 = round_forward(&s, r);
            let s0 = round_inverse(&s1, r);
            assert_eq!(s, s0, "round {} not invertible", r);
        }
    }

    #[test]
    fn full_permutation_invertible() {
        let s = sample_cube(71, 5);
        let p = permute(&s);
        let back = permute_inverse(&p);
        assert_eq!(s, back);
    }

    #[test]
    fn stream_cipher_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef";
        let nonce = b"a-test-nonce-value";
        let pt = b"the quick brown fox jumps over the lazy dog, repeatedly, \
                   to fill more than one single rate block of keystream output";
        let ct = encrypt(key, nonce, pt);
        let back = decrypt(key, nonce, &ct);
        assert_eq!(&back[..], &pt[..]);
        assert_ne!(&ct[..], &pt[..]);
    }

    #[test]
    fn shell_partition_sizes() {
        assert_eq!(rate_cells().len() + capacity_cells().len(), CELLS);
        assert_eq!(rate_cells().len(), 296);
        assert_eq!(capacity_cells().len(), 216);
    }

    #[test]
    fn checkerboard_neighbors_always_opposite_colour() {
        for i in 0..CELLS {
            let ci = color(i);
            for n in neighbors6(i) {
                assert_ne!(ci, color(n), "cell {} and neighbour {} share a colour", i, n);
            }
        }
    }

    /// Regression test for the bit-plane independence bug: without rho, a flipped
    /// bit can never leave its own bit-plane, and this asserts >1 plane is touched.
    #[test]
    fn bitplanes_are_coupled() {
        let s = sample_cube(97, 13);
        let mut t = s;
        t[100] ^= 0x01; // flip bit 0 of one cell, and nothing else

        let mut a = s;
        let mut b = t;
        for r in 0..4 {
            a = round_forward(&a, r);
            b = round_forward(&b, r);
        }

        let mut mask = 0u8;
        for i in 0..CELLS {
            mask |= a[i] ^ b[i];
        }
        assert!(
            mask.count_ones() >= 2,
            "difference confined to {} bit-plane(s) (mask {:08b}) — rho isn't coupling planes",
            mask.count_ones(),
            mask
        );
    }
}
