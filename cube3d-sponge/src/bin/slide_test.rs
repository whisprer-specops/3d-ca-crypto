use cube3d_sponge::*;

fn main() {
    println!("Round constant / slide-symmetry check.\n");

    print!("round constants (first 12): ");
    for r in 0..12u32 {
        print!("{:02x} ", round_constant(r));
    }
    println!("\n");

    let mut probe = [0u8; CELLS];
    for (i, b) in probe.iter_mut().enumerate() {
        *b = ((i * 13 + 7) % 256) as u8;
    }

    // The chi3 tap rotation alone repeats every 3 rounds (round % 3), so with
    // round constants disabled, round_forward_variant(_, 0, false) and (_, 3, false)
    // are the literal same function applied to the same input -> identical output.
    // That repeat is exactly the kind of self-similarity a slide attack exploits.
    let no_const_r0 = round_forward_variant(&probe, 0, false);
    let no_const_r3 = round_forward_variant(&probe, 3, false);
    let same_without_const = no_const_r0 == no_const_r3;

    let with_const_r0 = round_forward_variant(&probe, 0, true);
    let with_const_r3 = round_forward_variant(&probe, 3, true);
    let same_with_const = with_const_r0 == with_const_r3;

    println!(
        "identical input, round 0 vs round 3, constants DISABLED -> outputs equal: {}",
        same_without_const
    );
    println!(
        "identical input, round 0 vs round 3, constants ENABLED  -> outputs equal: {}",
        same_with_const
    );

    if same_without_const && !same_with_const {
        println!("\nconfirmed: the tap-rotation alone gives a period-3 self-similar round");
        println!("function — a slide-attack foothold — and the round constant is exactly");
        println!("what breaks that symmetry. This is the role iota plays in Keccak; skipping");
        println!("it to keep the CA 'pure' would be a real weakness, not a stylistic choice.");
    } else {
        println!("\nunexpected result — re-check the round constant schedule before trusting");
        println!("anything else this project reports.");
    }
}
