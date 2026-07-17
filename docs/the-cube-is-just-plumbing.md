# The Cube Is Just Plumbing

### Cellular automata, the third dimension, and the forty-year habit of mistaking complexity for security

*by Claudia G. Petersen*

---

There is a particular species of idea that arrives at two in the morning, feels self-evidently correct, and turns out to have been disproven in 1991.

The one I want to talk about goes like this: *take your data, arrange it in a grid, and let a cellular automaton churn over it. The output looks like static. Static is unpredictable. Unpredictable is secure.* And then the ambitious version: *do it in three dimensions. A cube. Shells of cubes around a central cube, the rule radiating outward in all directions. Vastly more complex. Therefore vastly more secure.*

It is a beautiful idea. It is also, in its second clause, wrong — and wrong in a way that has been publicly, repeatedly, and somewhat impolitely demonstrated for four decades.

What follows is the story of why, and what happened when we built the thing anyway and then spent considerably more effort trying to break it than we spent making it.

---

## Part One: The Static That Wasn't

A **cellular automaton** is the simplest interesting machine anyone has thought of. You have a row of cells. Each cell holds a value — say, a 0 or a 1. You have a rule that says: *to compute a cell's next value, look at the cell and its immediate neighbours, and consult this small table.* Apply the rule to every cell simultaneously. Repeat.

That is the whole apparatus. No arithmetic beyond looking at your neighbours. And yet if you print each successive row underneath the last, certain rules produce something that looks less like a machine and more like a photograph of turbulence — intricate, non-repeating, apparently structureless.

Stephen Wolfram was sufficiently taken with one of these — **Rule 30** — that in 1985 he proposed it as the basis of a cipher. The scheme is elegant. Your secret key is the starting row. You run the automaton, read off the values of one particular cell as it evolves, and use that stream of bits to mask your message. Wolfram tested it extensively. It passed. Rule 30 was good enough to ship as a random number generator inside Mathematica, where it lived for years.

In 1991, Willi Meier and Othmar Staffelbach reconstructed the seed.

The attack is a correlation attack, and the details are less important than the shape of the thing. Rule 30 has structure. That structure is invisible to statistical tests and completely visible to someone who sits down and does the algebra. The output was never random. It was merely *unfamiliar*.

This is the single most important idea in the field, and I want to be precise about it, because it is routinely misunderstood by people who are otherwise extremely clever.

**A statistical test asks: does this look like noise?**
**Cryptanalysis asks: can an adversary who knows everything except the key predict it?**

These are not the same question. They are barely related. Consider the decimal digits of π. They pass essentially every randomness test ever devised — uniform distribution, no correlations, no discernible pattern. They are also completely, trivially predictable, because they are *the digits of π*. Anyone who knows what they are looking at can produce the next million of them.

Rule 30 passed the tests. Rule 30 was π.

The field did not take the hint. The subsequent decades produced a steady output of repaired schemes: bigger neighbourhoods, hybrid rules, nonlinear variants, combinations of rules. A candid 2024 survey by Mariot and Leporati, looking back on a decade of this work, notes that most of it rests on ad-hoc arguments tailored to individual rules that generalise poorly. Which is a very polite way of describing a field that keeps rebuilding the same house on the same sinkhole.

### The one that worked

I should be fair, because there is a genuine success story, and it is a good one.

In 1994, Joan Daemen and colleagues described a transformation called **χ** (chi) — a shift-invariant nonlinear operation on binary arrays. Which is to say: a cellular automaton rule. It computes each output bit from a handful of neighbours using AND and NOT.

χ is the nonlinear heart of **Keccak**, which won NIST's competition and became **SHA-3**, which is currently protecting a great deal of the world's infrastructure. An affine relative of it sits inside **Ascon**, which NIST standardised in 2025 for lightweight cryptography.

So the cellular automata people were right. They were right about *one layer*, deployed inside a round function that was engineered with great care and then subjected to a decade of hostile scrutiny by people whose professional joy is finding cracks. They were never right about the CA being the cipher.

Hold that thought. It comes back.

---

## Part Two: The Third Dimension

Now the ambitious version. If a two-dimensional grid is good, surely a three-dimensional lattice is better? A cube. Concentric shells radiating outward. More neighbours, more interactions, more complexity.

Here is the problem, stated as plainly as I can manage.

**Complexity is not security.** Security is the measured work an adversary must do when they know your entire construction and lack only the key. That principle is called **Kerckhoffs's principle**, it dates to 1883, and it is not optional. Apparent complexity that has not survived analysis is not security — it is decoration. Worse, it is decoration that mostly conceals flaws *from the designer*, since the designer is the one person guaranteed not to attack the thing seriously.

Consider what "more dimensions" actually buys you. Most attractive CA rules are built from XOR. XOR is **linear** over the two-element field — which means that running the automaton for T steps is equivalent to multiplying by a single matrix. You do not need to run the automaton to invert it. You need to solve a system of linear equations, which is a first-year exercise and which computers find restful.

Making the grid three-dimensional makes the matrix bigger. Gaussian elimination does not care. Adding concentric shells makes it bigger still. Gaussian elimination continues not to care. You have bought yourself cost and paid for it in nothing.

And there is a second, subtler cost. A cube with shells has *different kinds of cell*: corners have fewer neighbours than edges, edges fewer than faces, faces fewer than the interior. Different neighbourhoods mean different mixing rates. Some regions of your state churn beautifully and some barely move — and an attacker will simply go and stand in the region that barely moves. "Radiating outward from the centre" sounds powerful. Structurally, it is an invitation.

### The graveyard

None of this is hypothetical. There is an enormous literature applying chaotic maps and cellular automata to image encryption, and its cryptanalytic record is genuinely something to behold.

The founding architecture is due to Jiri Fridrich in 1998: a permutation stage scrambles pixel positions, a diffusion stage alters pixel values, repeat. It is a clean instantiation of Shannon's confusion-and-diffusion principle and it launched a thousand papers.

In 2010, Solak and colleagues broke it. Fridrich's own scheme. And the attack generalises to structurally similar designs, which — given that the whole point of a founding architecture is that everyone copies it — was less a single casualty than a diagnosis.

Chengqing Li and various collaborators have since broken so many of these schemes that the citation lists read like a war memorial. Most are broken with a handful of chosen plaintexts. Some are broken with one. And there is a result from Li, Chen and Lo that should have ended the genre outright: **all permutation-only multimedia ciphers are practically insecure** against chosen-plaintext attack, generically, requiring only about log(*MN*) chosen images to recover half the plaintext. Not "the ones we looked at." All of them. It is a theorem.

Meanwhile, three-dimensional CA cryptography specifically is a real and populated sub-literature — Chen and colleagues did 3D chaotic cat maps in 2004; Ángel Martín del Rey encrypted 3D solid objects in 2015 using a chaotic cat map for confusion and a second-order reversible 3D cellular automaton for diffusion; there is a comprehensive review of the whole business from earlier this year. The third dimension has been thoroughly visited. It is mostly used as extra scrambling volume, and the scrambling volume mostly does not help.

### The joke at the centre

Here is the part I find genuinely funny, in the dry way that good jokes in mathematics tend to be funny.

**Keccak is already three-dimensional.**

SHA-3's state is a 5 × 5 × 64 array of bits. A cube. Its round function applies local operations that ripple through that cube, iterated 24 times. The intuition — *run a local nonlinear rule repeatedly over a three-dimensional block of data* — is not merely defensible. It is standardised. It is in your browser.

So the instinct was right and arrived roughly fifteen years late. What separates Keccak from a naive radiating cube is not the geometry, because they *share* the geometry. It is a short, enumerable list of properties, each of which had to be put there deliberately:

- **Nonlinearity** (χ), so the algebra doesn't collapse into a solvable matrix.
- **Symmetry-breaking** (a per-round constant, ι), so that round 3 isn't literally the same function as round 0 — a self-similarity attackers exploit with something charmingly named a *slide attack*.
- **Transposition** (ρ and π), which moves bits around so influence spreads faster than one cell per step.
- **Diffusion uniformity**, so no region of the state is a soft spot.
- And *decades of people trying to break it*.

The geometry contributed nothing. The geometry is the pipe. What matters is what you run through it.

---

## Part Three: Building It Anyway

Knowing all of the above, we built the cube. Not because we expected a competitive cipher — we did not, and I will be blunt about that below — but because the interesting question is what a disciplined process actually *reports* when you point it at a design whose lineage is "geometric intuition, corrected."

The result is called **cube3d-sponge**: an 8 × 8 × 8 lattice of bytes. 512 cells, 4096 bits.

Two design decisions matter for the story.

**The shells got a real job.** Concentric layers are not used for diffusion — that would reintroduce the anisotropy problem. Instead they became the **rate/capacity split** of a *sponge construction*. The outer shell is the "rate": the only part the outside world touches, where data goes in and keystream comes out. The inner shells are the "capacity": never read, never written directly, mixed only indirectly. In a sponge, security comes from the capacity — the part the attacker cannot see. This is a legitimate, analysed, load-bearing role for concentric layers, and it is the one thing the original geometric intuition genuinely earned.

**Invertibility came from structure, not from the rule.** You have to be able to decrypt, which means the permutation must be reversible — and most attractive CA rules are not. The standard fix is a second-order or partitioning CA. We used a **Feistel network** over a three-dimensional checkerboard instead: colour every cell by whether *x+y+z* is even or odd, and note that on a cubic lattice, every neighbour of a cell has the opposite colour. So you can update the black cells using only the white ones, then the white using only the (updated) black — and *that is reversible no matter how vicious the rule is*. It buys invertibility for free and lets you make the nonlinear part as nasty as you like without ever endangering decryption.

### Two bugs, and the numbers that caught them

Neither of the following was caught by reading the code. Both were caught by a measurement returning a number that was not merely surprising but *impossible*.

**The odd cube.** The first version used a 7 × 7 × 7 lattice, because 7 is odd and gives you a single centre cell — pleasingly close to the original picture of a cube at the heart of the thing. This is mathematically broken, and a unit test said so within seconds of existing. The checkerboard colouring only works if opposite edges of the lattice wrap around consistently, and on an odd-length loop they don't — an odd cycle is not two-colourable. Cells at position 0 and position 6 are wrap-around neighbours and share a colour. The entire invertibility argument silently evaporates. Switching to 8 fixed it, and as a small mercy, gave a literal 2 × 2 × 2 cube at the centre — closer to the original vision than a single point had been.

**The plateau.** This one is my favourite thing in the whole project.

The avalanche test asks: flip one input bit, and how much of the output changes? The answer should climb toward 50%. Ours climbed to about 6.3% and stopped. Flat. Sixteen rounds, no movement.

I diagnosed it immediately and confidently: insufficient long-range mixing, the influence can't travel far enough, add a transposition step.

I was wrong, and the number was the tell. A reach problem produces a *slow ramp*. We had a *hard ceiling* at a suspiciously tidy value. So: what would 6.25% have to mean?

512 ÷ 2 ÷ 4096 = 6.25%.

That is what perfect, complete, textbook-ideal diffusion looks like — *if it is confined to one-eighth of the state*. And there it was. χ operates on bytes with bitwise AND and NOT, and bitwise operations work on all eight bits of a byte in parallel but **independently**: bit 3 of the output depends only on bit 3 of the inputs. Without a step to rotate bits *within* each byte, our elegant 8 × 8 × 8 cube of bytes was never a 4096-bit state at all. It was **eight completely separate 512-bit automata, stacked in the same memory, that had never once spoken to each other.** A flipped bit could not leave its own layer. Seven-eighths of the state was decorative.

The fix is a per-cell byte rotation, which couples the layers. It is called ρ. It is, of course, exactly why Keccak has a ρ. We had built χ and ι and skipped the one step whose entire job is the thing we were missing.

The moral is worth more than the bug: **when a measurement lands on an exact number, stop and work out what that number would have to mean.** It is telling you something. It is usually not what you assumed.

### The ladder

With ρ in place, avalanche reaches 50% by round six. The design uses twelve. Then we spent the real effort attacking it — four independent harnesses, cross-checked on two operating systems with different keys.

| What | How deep it reaches | What kind of claim |
|---|---|---|
| Key recovery (cube attack) | **round 2** | Actual key bits, verified against the secret |
| Provable zero-sum, practical cube | **round 4** | Deterministic. No statistics. |
| Provable zero-sum, 2⁶⁴ cube | **round 5** | Deterministic, proof-only |
| Statistical differential bias | **round 6** | Evidence, not proof |
| **The design** | **round 12** | ~2× margin over the best distinguisher |

A few things in there are worth unpacking.

A **cube attack** treats every output bit as a polynomial in the key and the nonce, then sums the output over every combination of a chosen set of nonce bits. That summation annihilates most of the polynomial and leaves a small remainder — and if the polynomial isn't too tangled, that remainder is *linear in the key*, which is a free equation. Collect enough and you solve for the key. It works beautifully at round 1, sporadically at round 2, and dies at round 3, because the polynomial's degree roughly quadruples per round and the attack's cost doubles for every extra nonce bit you need. It doesn't fail because we lost interest. It fails because the arithmetic runs away.

The **four-round gap** between key recovery (2) and mere distinguishing (6) is not an anomaly. Distinguishers always reach further than key recovery. This is why "I found a statistical bias at round 5" never, ever means "the key falls at round 5" — a fact that would improve a great deal of the literature discussed in Part Two.

The **provable zero-sums** are the nicest result. Rather than measuring a bias and computing a z-score, you prove an upper bound on the polynomial's degree, and then: if the degree is provably lower than the number of nonce bits you're summing over, the sum *must* be zero. Always. For every key. No statistics attached, because there is nothing to be uncertain about. Theory says zero; we checked; it was zero.

And a small elegant finding fell out: the *shape* of the cube matters more than its size. Sixteen nonce bits stacked into two adjacent cells reach 2.5× further than sixteen bits spread across sixteen cells. The reason traces straight back to the plateau bug — χ is bitwise, so bits only meet their own layer, and ρ is the only thing coupling layers. Concentrate your bits and the degree grows slower. It is the same fact, wearing a different hat.

### The number that puts it all in perspective

Here is the finding I'd hand to anyone inclined to panic at "we found a distinguisher at round 4 of 12."

**Ascon has a zero-sum distinguisher on its full twelve rounds, at cost 2⁵⁵. It is a NIST standard.**

That is from Ascon's own published analysis. Not a reduced version. The whole permutation. And it is standardised, deployed, and entirely respectable, because a distinguisher on the bare permutation does not break the *mode* built around it — the mode never grants an attacker the freedoms the distinguisher assumes.

By that yardstick our round-4 zero-sums are unremarkable, and the thing that would genuinely alarm is key recovery near full rounds. Ours expires at two.

---

## What Any of This Was Worth

Let me be unambiguous, since under-qualification is the characteristic vice of this genre: **do not use cube3d-sponge for anything.** It has no authentication tag. It has had no independent scrutiny — the person who designed it is the person who attacked it, which is the weakest sentence in this article. Use Ascon. Use ChaCha20-Poly1305. Use the thing that a thousand hostile strangers have already failed to break.

There is also an honest correction owed. Partway through, I was reasonably confident the concentric-shell geometry was structurally novel. A proper literature search for the write-up turned up Martín del Rey's 2015 paper, which does 3D cellular automata with second-order reversibility and a chaotic map for confusion — which is, very nearly point for point, the "principled path" I had independently and rather pleased with myself reasoned my way toward. The lesson there is free and universally applicable: **search the literature before, not after.**

What survives is smaller and, I think, more useful than a cipher.

The geometry contributed nothing to security. Every property that mattered — nonlinearity, invertibility, symmetry-breaking, layer coupling, transposition — had to be added deliberately, and each one came from the same list Keccak's designers wrote down twenty years ago. The cube was plumbing. Good plumbing. Still plumbing.

And the measurement was the whole point. Four harnesses caught four bugs — two in the design, two in the attacks — and not one was caught by inspection. Every single one announced itself as a number that could not possibly be true: a plateau at exactly 6.25%, an algebraic degree that went 0, 1, 0, 4 and thereby claimed to *decrease* with more rounds, which is a bit like a river running uphill and should be treated with the same suspicion.

Build the falsifier before you trust the design. Then, when the falsifier hands you an exact number, do not explain it away.

Work out what it would have to mean.

---

*The full implementation, all six harnesses, and a considerably drier technical write-up with proper citations are available for anyone who wants to check the arithmetic. Please do. That is rather the point.*
