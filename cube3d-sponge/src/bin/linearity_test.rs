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

fn random_cube(rng: &mut u64) -> Cube {
    let mut c = [0u8; CELLS];
    for b in c.iter_mut() {
        *b = (xorshift(rng) & 0xFF) as u8;
    }
    c
}

fn xor_cube(a: &Cube, b: &Cube) -> Cube {
    let mut o = [0u8; CELLS];
    for i in 0..CELLS {
        o[i] = a[i] ^ b[i];
    }
    o
}

fn weight(c: &Cube) -> u32 {
    c.iter().map(|b| b.count_ones()).sum()
}

fn apply_rounds(state: &Cube, rounds: u32) -> Cube {
    let mut s = *state;
    for r in 0..rounds {
        s = round_forward(&s, r);
    }
    s
}

fn main() {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;
    let mut rng = seed;
    let zero = [0u8; CELLS];

    println!("Superposition / affinity test.\n");
    println!("For a genuinely affine map L: L(a) xor L(b) xor L(0) xor L(a xor b) == 0 always.");
    println!("A nonzero residual on every trial is necessary (not sufficient) evidence against");
    println!("the crudest form of linear cryptanalysis. This does NOT measure algebraic degree");
    println!("or resistance to real differential/linear/cube attacks — treat it as a smoke test,");
    println!("the first thing that should fail loudly if the design is broken, not the last.\n");

    println!(
        "rounds | trials | min residual weight | mean residual weight (out of {} bits)",
        CELLS * 8
    );
    println!("-------+--------+----------------------+----------------------------------------");

    for rounds in [1u32, 2, 4, 8, 12] {
        let mut min_w = u32::MAX;
        let mut sum_w = 0u64;
        let trials = 200;
        for _ in 0..trials {
            let a = random_cube(&mut rng);
            let b = random_cube(&mut rng);
            let ab = xor_cube(&a, &b);

            let pa = apply_rounds(&a, rounds);
            let pb = apply_rounds(&b, rounds);
            let p0 = apply_rounds(&zero, rounds);
            let pab = apply_rounds(&ab, rounds);

            let mut residual = xor_cube(&pa, &pb);
            residual = xor_cube(&residual, &p0);
            residual = xor_cube(&residual, &pab);
            let w = weight(&residual);
            min_w = min_w.min(w);
            sum_w += w as u64;
        }
        println!(
            "{:6} | {:6} | {:20} | {:.1}",
            rounds,
            trials,
            min_w,
            sum_w as f64 / trials as f64
        );
    }

    println!("\nif min residual weight is EVER 0, that trial found an exact affine relation —");
    println!("stop and investigate, that's a break, not a curiosity. it should stay comfortably");
    println!("nonzero from round 1 onward, since chi3's AND terms are nonlinear per cell.");
}
