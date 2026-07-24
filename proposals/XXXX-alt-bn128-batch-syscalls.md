---
simd: 'XXXX'
title: BN254 Batch-Verification Syscalls
authors:
  - Alexander Atamanov (Helios), alexander@helios.xyz
  - Jorrit Palfner (Helios), jorrit@helios.xyz
category: Standard
type: Core
status: Idea
created: 2026-07-15
feature: (fill in with feature tracking issues once accepted)
---

## Summary

This proposal introduces four BN254 (`alt_bn128`) syscalls that complete the
on-chain verifier surface for pairing-based cryptography. These syscalls will
expose:

1. **G1 multi-scalar multiplication** (`alt_bn128_g1_msm`)
2. **Multi-pair pairing check** (`alt_bn128_pairing_check`)
3. **Scalar-field linear combination** (`alt_bn128_fr_lincomb`)
4. **Scalar-field batch inversion** (`alt_bn128_fr_batch_invert`)

These are the primitives behind any BN254 pairing-product check with a G1 fold
and Fr arithmetic in between. The primary targets are batched Groth16 and PLONK
(KZG) verification. A normative SDK reference over these primitives specifies
the randomized batch check and its Fiat-Shamir challenge. All four reuse the
existing pairing syscall's big-endian encoding, share one feature gate, and
activate independently of SIMD-0302.

## Motivation

Zero-knowledge proofs on Solana are verified one at a time, and verification
dominates the cost of every ZK application. A single Groth16 verification
measures about 96k CU on the uncommitted rail (one public input) and 231k
CU on the committed rail against the current syscalls. Real transactions
carry more than one proof, composed like CPI depth: in the authors' privacy
pool deployment a swap's rule proof calls into the pool's transact proof,
and a policy ring inserts a third hop; two or three proofs per transaction
is the common case, five the composability ceiling. Independent
verification scales linearly and hits the compute ceiling fast: five proofs
burn a third of the 1.4M CU transaction cap before any state effect runs,
and fifteen exceed it outright. Operators with sustained same-circuit
volume (relayers, delegated provers, tree-maintenance services) may hold 50
or more same-key proofs before broadcast and today can only pay the full
price 50 times, avoidable load on every validator.
High compute cost has already been an underlying problem for the network
at least once.

Almost none of that cost is cryptographically necessary. Batch verification
is a standard technique (Bellare-Garay-Rabin 1998): weight each verification
equation by a random 128-bit scalar and check the product of the weighted
equations at once, with soundness error $2^{-128}$ per equation. The
randomizers fold into the G1 side by bilinearity, so the fold itself is G1
MSMs and scalar multiples. For $n$ Groth16 proofs under one verifying key
the whole batch collapses to $n+3$ pairing terms under a single final
exponentiation: one MSM per fixed-G2 term ($\beta$, $\gamma$, $\delta$)
plus one $[r_i]A_i$ multiple per proof term. A PLONK/KZG batch collapses
to two pairing terms for any $n$, fed by two MSMs. The per-proof marginal
cost falls from a full verification to at most one pairing term plus a few
MSM points.

The current syscall surface cannot express this. Two pieces are missing:

1. **No G1 MSM.** The batch fold is multi-scalar multiplication; today it
   costs $n$ separate `alt_bn128_multiplication` calls at 3,840 CU each plus
   sBPF additions, forfeiting the Pippenger speedup that makes folding cheap.
2. **No scalar-field arithmetic.** PLONK's verifier is dominated by Fr work:
   150 to 300 multiplications and several inversions per proof for challenge
   derivation, Lagrange evaluation, and opening folds. One Fr multiply is
   about 1 CU native but 150 to 250 CU in sBPF, which has no 64x64 to 128
   multiply; one inversion is hundreds of multiplies.

Closing two gaps effectively takes four syscalls. The MSM is the main one.
The Fr work is two orthogonal primitives, an inner product and a batch
inverse, the narrowest surface covering the verifier's whole field cost (a
programmable field VM was considered and rejected as unpriceable; see
Alternatives Considered). The fourth, `sol_alt_bn128_pairing_check`, is a
new syscall computing the same boolean pairing-product check the chain
already has as the `ALT_BN128_PAIRING` operation of
`sol_alt_bn128_group_op`. Three facts about that operation disqualify it as
the anchor of a batch verifier. It accepts an empty input vacuously: zero
pairs parse to an empty multi-pairing, whose product is the identity, so it
returns true, a soundness landmine when the input is a folded batch. Its
byte-buffer length handling is the bug SIMD-0334 fixed. And it is priced
`36,364 + 12,121 * (n - 1)` CU, constants fitted to an older backend:
666,656 CU for the 53 pairs of a 50-proof batch, where this proposal's
model charges 508k. Each could be patched behind its own feature gate, as
SIMD-0334 was, but the batch path also needs the typed count-based ABI and
the pair cap of the Detailed Design; one new syscall delivers all of it on
the same feature gate as the MSM, and the activated operation keeps its
semantics.

The design is implementation-tested. The four syscalls plus the reference
Groth16 and PLONK batch verifiers were built five times over interchangeable
backends on one wire contract: stock arkworks, an optimized arkworks, mcl,
and a pure-Rust backend with and without an 8-wide AVX-512 IFMA pairing path.
All five were benchmarked in one pinned campaign on validator-class x86, and
each backend's fit of the cost model (linear bases, a log2-bucketed MSM
discount) upper-bounds its measured CU at every grid size. For any client
implementation the constants are a re-fit, not a redesign.

## Dependencies

This proposal has no dependency on any pending proposal. The four syscalls
are new symbols that layer on the long-activated alt_bn128 family only
through its byte encoding and test vectors, and they activate alone under
one feature gate.

Relationship to adjacent proposals:

- **[SIMD-0129] (activated):** the new syscalls follow its error convention,
  a single non-fatal `Ok(1)` for any domain error, hard aborts reserved for
  memory faults and budget exhaustion. This is conformance to the
  established convention, not a dependency.
- **[SIMD-0284] (little-endian encoding, proposed):** orthogonal. These
  syscalls are big-endian only, matching the existing pairing and the proof
  toolchain (gnark, snarkjs, circom, arkworks); 0284's little-endian
  variants live on the group-op syscall and neither proposal constrains the
  other.
- **SIMD-0302 (G2 arithmetic): explicitly not required.** By bilinearity
  every randomizer folds into the G1 side, so the batch fold is a G1 MSM and
  the only G2 elements a verifier touches are the fixed verifying-key
  constants and the per-proof B points, both consumed directly by the
  pairing. The two proposals activate in either order.

[SIMD-0129]: https://github.com/solana-foundation/solana-improvement-documents/pull/129
[SIMD-0284]: https://github.com/solana-foundation/solana-improvement-documents/pull/284

## New Terminology

- **Batch verification.** Checking $n$ independent proofs together with less
  than $n$ times the work of checking each alone, while verifier work stays
  linear in $n$. Distinct from aggregation (Snarkpack, recursion), which
  produces one short proof at the cost of new setup material or a proving
  service.
- **Randomizer.** A per-equation scalar $r_k$ drawn from the batch's
  Fiat-Shamir challenge, uniform on $[1, 2^{128}]$. The batch accepts iff the
  randomized product of per-proof error terms is the group identity.
- **Small-exponents test.** The Bellare-Garay-Rabin (1998) construction:
  accept iff $\prod_k E_k^{r_k} = 1$. A failed equation survives with
  probability at most $2^{-128}$ per equation, information-theoretic given a
  uniform challenge.
- **Fold.** Rewriting a randomized pairing product so each randomizer becomes
  a 128-bit G1 scalar multiplication, $e(P, Q)^r = e([r]P, Q)$, and every
  fixed-G2 term collapses across the batch into one MSM feeding one pairing
  term.
- **Scalar-field fold.** The verifier's arithmetic between the group
  operations: deriving challenges, evaluating the Lagrange basis (a batch
  inversion), and combining commitment openings (an inner product), all in the
  prime scalar field of order $q$. Dominant for PLONK, minor for Groth16.

## Detailed Design

Four syscalls in two groups: two group operations feeding the pairing check,
and two scalar-field helpers for the arithmetic between them. Validation is a
function of the argument type, never a caller flag. Every G2 argument is raw
and fully validated.

```text
alt_bn128_g1_msm(points: &[G1], scalars: &[Scalar]) -> G1
alt_bn128_pairing_check(pairs: &[(G1, G2)]) -> bool
alt_bn128_fr_lincomb(a: &[Scalar], b: &[Scalar]) -> Scalar
alt_bn128_fr_batch_invert(a: &[Scalar]) -> [Scalar]
```

`pairing_check` runs one multi-Miller loop and one final exponentiation, keeps
the Fq12 internal, compares to the identity, and returns a boolean word.
`g1_msm` returns one G1 point. `fr_lincomb` returns
$\sum_i a_i b_i \bmod q$, reduced once at the end, the linearization fold
and the batched-opening combination in one call over two equal-length
scalar arrays.
`fr_batch_invert` returns the inverse of every input scalar with Montgomery's
trick, one field inversion and $3(n-1)$ muls for $n$ inputs, covering
Lagrange-basis evaluation and every division. Both scalar-field syscalls touch
no curve point.

### Wire Types

Each syscall takes an element count plus pointers to typed fixed-size
records, the convention of the curve25519 `PodRistrettoPoint` family: 64-byte
G1, 128-byte G2, 32-byte scalar, 192-byte G1-then-G2 pair, byte-aligned
arrays throughout. The runtime translates every array as count times element
size with checked arithmetic and charges compute from the same count, so the
size charged, the size translated, and the size parsed are one number.
Results are typed records of exact size (a G1 point, the 32-byte verdict
word, or count scalars); no byte length appears anywhere in the interface.
This departs from `sol_alt_bn128_group_op`, which takes an opaque buffer
plus an operation ID and re-derives per-operation sizes internally, the
design SIMD-0222 and SIMD-0334 had to correct: with typed counts a truncated
element or a charged-versus-parsed size mismatch cannot be expressed. The
types carry layout only; the validation below is the sole path from bytes to
a group element or scalar.

### Encoding

Byte-for-byte the encoding of the existing pairing syscall: big-endian,
including the Fq2 limb order. G1 is 64 bytes (x then y), G2 is 128 bytes
(x.c1, x.c0, y.c1, y.c0), a pair is 192 bytes, a scalar is 32 bytes.
All-zeros is the point at infinity. An implementation MUST reuse the existing
alt_bn128 test vectors to pin the layout, so proofs from gnark, snarkjs,
circom, and arkworks need no conversion. The syscall MUST NOT accept or return a
compressed point, a prepared (line-coefficient) G2, or an Fq12 target-group
element. The scalar-field syscalls consume and produce the same 32-byte
big-endian canonical scalars (value $< q$).

### Validation

Before any arithmetic, in a fixed order per input, left to right across the
inputs, first failure returning its error:

| Input  | Checks, in order                                            |
|--------|-------------------------------------------------------------|
| G1     | length 64, coordinates canonical ($< p$), on-curve          |
| G2     | length 128, Fq2 limbs canonical, on-curve, subgroup member  |
| Scalar | length 32, value $< q$                                      |

G1 has cofactor 1, so on-curve implies subgroup membership; G2's cofactor is
near $2^{254}$, so its subgroup membership MUST be checked per point, via
the fast endomorphism test. `fr_batch_invert` additionally rejects a zero scalar
(`ZeroInput`), since its inverse is undefined; `fr_lincomb` accepts zeros and
rejects unequal-length arrays (`LengthMismatch`). Compute is charged up front
from the declared input sizes, so malformed input consumes the same CU as
valid input and validation order leaks nothing through the meter.

### Errors

One stable enum, returned as a single non-fatal code per SIMD-0129:
`InvalidLength`, `NonCanonical`, `NotOnCurve`, `NotInSubgroup`, `ZeroInput`,
`CapExceeded`, `LengthMismatch`. A domain error returns `Ok(1)` and leaves the
result buffer untouched. Hard `Err` is reserved for memory-translation faults
and compute-budget exhaustion.

### Caps

`pairing_check` accepts at most 256 pairs per call, `g1_msm` at most 2048
points, and each scalar-field syscall at most 2048 scalars per array. All are
memory and griefing bounds; the compute budget binds first in practice.

### Pricing

Compute is charged up front from the declared sizes. `pairing_check` is
priced `base + n * (per_pair + g2_subgroup)`, with an explicit G2 subgroup
component so the surcharge is auditable and reusable by future G2-input
syscalls. `g1_msm` is priced
`base + per_point * n * DISCOUNT[floor(log2 n)] / 1000`: Pippenger is
sublinear, so a flat per-point price would either undercharge mid-range $n$
(a DoS vector) or overcharge large batches. The discount table has one
entry per log2 bucket over $n = 1$ to $2048$, each fitted as an upper bound
of measured CU plus margin, so the model never undercharges a measured
size.

The model is backend-independent; the constants are not. Every client
charges the same CU regardless of which arithmetic backend it runs, so the
constants MUST be fitted as an upper bound to the slowest backend any
conforming client ships at activation, and a faster backend lowers charges
only through a subsequent re-pricing feature gate. The backend that ships
at activation is the tuned arkworks, so the reference constants below are
its fit at the x86-64-v2 shipping profile (Zen 4, 33 ns per CU); the
authors' pure-Rust backend is audit-gated and, once audited, lowers these
charges through that re-pricing path (last table row):

```text
MSM base 100, per_point 1790
MSM DISCOUNT = [1000, 626, 482, 409, 371, 352, 343, 291, 250, 216, 199, 176]
pairing base 18549, per_pair 4742, g2_subgroup 4496
fr_lincomb base 100, per_term 1
fr_batch_invert base 100, per_term 3
```

All five candidate backends were fitted in one pinned campaign on
validator-class x86 (AMD EPYC 9354, identical harness and seeds).
Kernel-level cross-checks on Intel Granite Rapids run the same pairing
kernels about 24% faster than Zen 4, so constants fitted on the AMD box
upper-bound current Intel validator silicon as well. The fit
spread, and what it does to batched Groth16 verification, is tabulated
below. All values are CU at the 33 ns per CU convention: `per_pair` and
`per_point` are that backend's fitted constants (the charged pair cost
adds the `g2_subgroup` component on top of `per_pair`). The 5- and
50-proof columns are the exact totals the reference fold is charged for a
vanilla (uncommitted) Groth16 batch of that size, same verifying key, one
public input: one $(n+3)$-pair check, $n$ one-point $[r_i]A_i$
multiplications, the three fixed-G2-term MSMs, and the input-folding
`fr_lincomb`. Parenthesized is the multiple against $n$ individual Groth16
verifies at 96k CU each. PLONK
batches, whose cost is dominated by one MSM rather than the pair count,
are costed in Impact:

| Backend fit    | per_pair | per_point | 5-proof CU     | 50-proof CU     |
|----------------|----------|-----------|----------------|-----------------|
| arkworks stock | 7,230    | 4,273     | 153,544 (3.1x) | 913,032 (5.3x)  |
| arkworks tuned | 4,742    | 1,790     | 110,652 (4.3x) | 638,648 (7.5x)  |
| mcl            | 3,357    | 1,225     | 84,695 (5.7x)  | 519,517 (9.2x)  |
| helios (gated) | 1,567    | 1,126     | 64,024 (7.5x)  | 366,317 (13.1x) |

The tuned-arkworks row is the shipped default; the helios row is what the
post-audit re-pricing gate reaches without any change to this design.

The scalar-field syscalls are priced linearly in the array length,
`base + per_term * n`; `fr_batch_invert`'s base also covers the single
field inversion the whole batch shares. Each constant is a strict upper
bound of measured CU at every grid point
$n \in \{1, 16, 64, 256, 1024, 2048\}$. Native Fr
arithmetic is cheap on every backend, so these sit far below the pairing and
MSM costs. Final constants MUST be re-fitted and reported with the pinned
commit, hardware, and batch sizes of the backend that ships.

### The Batch Check

Each verification equation $k$ defines a target-group element $E_k$ that
equals $1$ iff the equation holds. The naive batch, accept iff
$\prod_k E_k = 1$, is broken: two invalid proofs whose error terms are
$g^a$ and $g^{-a}$ both pass. The fix is a challenge: draw randomizers
$r_k$ and accept iff $\prod_k E_k^{r_k} = 1$. If some $E_j$ is not $1$, a
uniform $r_j$ from $2^{128}$ values satisfies the resulting linear
equation with probability at most $2^{-128}$ (Bellare-Garay-Rabin).
Randomizers attach to equations, not proofs: a committed proof's Groth16
relation and its Pedersen proof of knowledge each get their own randomizer.

For one verifying key, proofs $i = 1..n$,
$L_i = IC_0 + \sum_j x_{ij} \, IC_j$:

$$
\prod_i e([r_i]A_i, B_i) \cdot e(-[\sum_i r_i]\alpha, \beta) \cdot
e(-\sum_i [r_i]L_i, \gamma) \cdot e(-\sum_i [r_i]C_i, \delta) = 1
$$

That is $n+3$ pairing terms in one `pairing_check`, with three MSMs feeding
it. The BSB22 committed rail folds the commitment into $L_i$ and appends
its proof of knowledge under its own randomizers $s_i$, costing two more
MSM-fed terms per key ($n+5$ total). Only the per-proof $B_i$ resist
folding, so a batch with $d$ distinct keys is $n$ pairing terms plus the
sum of the per-key constants.

The challenge MUST be derived by hashing the frozen batch and everything the
verdict depends on, keccak256 throughout:

```text
seed = keccak256( domain_tag || be16(m) || vkd_1 || ... || vkd_m || be64(n)
                  || [ be16(vk_i) || A_i || B_i || C_i
                       || com_i || pok_i || x_i ]_{i=1..n} )
r_k  = 1 + lo128( keccak256( seed || be64(k) ) )   for k = 1..N
```

`com_i` and `pok_i` are present iff key `vk_i` is committed. `vkd_j` is
keccak256 over key j's canonical bytes. $N$ is the number of verification
equations, $n$ plus one more per committed proof. `lo128` takes the digest's
last 16 bytes big-endian, and `1 + lo128(.)` is uniform on $[1, 2^{128}]$,
no zero and no bias. The per-record key index binds each proof to its
circuit and fixes the record layout. Omitting any field reopens a
weak-Fiat-Shamir attack.
`domain_tag` is a versioned ASCII constant carrying the protocol name,
transcript version, and randomizer mode, distinct per scheme.

### Edge Cases

- Zero pairs: `pairing_check` MUST error, not return the empty product (which
  would vacuously accept). Zero points, or unequal point and scalar counts:
  `g1_msm` MUST error.
- Point at infinity in a pair: contributes 1 and the pair is skipped,
  matching what the existing pairing does. The SDK verifier MUST reject
  infinity in proof positions.
- Infinity MSM result: encoded as all-zeros, the existing pairing
  convention.
- Non-canonical $x = y = p$ (which reduces to infinity): rejected as
  NonCanonical, never reduced.
- Batch size 1: a batch of one, checked like any other, and pinned against
  the individual verifier byte for byte in the conformance suite.
- Empty scalar array: both scalar-field syscalls MUST error, matching the
  zero-input rule of the group operations.
- Unequal `fr_lincomb` arrays: `LengthMismatch`, no partial result.
- Zero in `fr_batch_invert`: `ZeroInput`, and the output buffer is left
  untouched.
- Totality: all four syscalls are total functions from bytes to a defined
  result or error on every input, with no panic, no unbounded allocation, and
  no platform-dependent result.

### Validator Components Affected

| Validator Component             | Impact                                     |
|---------------------------------|--------------------------------------------|
| Transaction Execution (Runtime) | Four new feature-gated syscalls registered |
| Virtual Machine                 | New syscall symbols resolved at load       |
| Block Packing                   | New CU cost constants                      |
| Consensus                       | Bit-identical results required (gated)     |
| Gossip                          | None                                       |
| Turbine                         | None                                       |
| Snapshots                       | None                                       |
| On-Chain Core BPF Programs      | None                                       |
| Other (please describe)         | Feature-set, compute-budget cost tables    |

## Alternatives Considered

- **A monolithic precompile** shaped like SIMD-0075: a native
  `bn254_groth16_batch_verify` taking the verifying key, proofs, and inputs as
  instruction data. Safe by construction but rigid: one proof system and one
  encoding are frozen, so the committed rail and PLONK each need a separate
  precompile and SIMD, and it cannot bind the challenge to a calling program's
  own transcript. Rejected in favor of four general primitives.
- **Returning the target-group element** (as the starting-point
  prepared-pairing syscall did) instead of a boolean. Every batch input is
  public, so an attacker can compute the pre-final-exponentiation product
  $M$ and inject $M^{-1}$; the check computes identity and accepts, with
  no hard problem. Returning a boolean removes this codomain value from
  the boundary.
- **Accepting prepared (line-coefficient) G2** from instruction data.
  Coefficients that correspond to no real point make the pairing evaluate to
  an attacker-chosen value. Preparation happens inside the runtime, after
  validation, from raw bytes; nothing prepared crosses the boundary.
- **Powers of one challenge** ($r_k = r^{k-1}$) instead of independent
  randomizers. Powers need one draw but give an $N-1$ factor in the soundness
  error. Independent randomizers are the default; the powers variant is
  allowed where a caller wants the cheaper derivation.
- **A generic curve-ID family** in the SIMD-0388 style
  (`sol_curve_pairing_map` with a curve ID) instead of a dedicated
  `alt_bn128_*` pair. This design follows the existing dedicated family for
  encoding and pricing continuity, but stays curve-generic so a BLS12-381
  instantiation is additive under either convention.
- **A general field-arithmetic VM** (a syscall executing an arbitrary opcode
  stream over the scalar field) instead of the two fixed scalar-field
  primitives. It would cover more but is hard to price honestly and hard to
  make total, and the two Fr primitives already capture the verifier's whole
  scalar-field cost (the linearization fold and the batch inversion). Rejected
  for the same reason the pairing returns a boolean, not a programmable
  target: a narrow priceable surface over a wide one.

## Impact

For programs that verify Groth16 or PLONK proofs, per-proof cost drops
severalfold at the shipped constants and reaches an order of magnitude
after the audit-gated re-pricing. Under the shipped (tuned-arkworks)
constants five same-key Groth16 proofs charge about 111k CU against 480k
for five independent verifies (4.3x), and 50 charge about 639k against
4.8M (7.5x, rising to 13.1x under the helios fit; see Pricing); the
committed (BSB22) rail starts from 231k CU per individual verify and
batches at $n+5$ pairing terms, so its multiple is larger still. A 50-proof
PLONK batch draws about 310k CU in syscall charges, 6.2k per proof: all of
a PLONK proof's per-proof data is G1 and Fr and folds into the two batch
MSMs with no per-proof pairing term. That syscall figure is not the whole
cost. Each proof also pays five to six per-proof Fiat-Shamir derivations
and the reduction's chained products, some fifty Fr multiplications that no
inner-product syscall can absorb, roughly 8 to 14k CU of sBPF arithmetic;
and a PLONK proof is near three times a Groth16 proof's bytes (about 800
against 288 uncompressed, with one input) against the 1,232-byte
transaction. End to end, a batched PLONK proof therefore lands at parity
with or above a batched Groth16 proof. The syscalls' effect on PLONK is
different in kind:
without `fr_lincomb` and `fr_batch_invert` the reduction alone would carry
roughly 25k CU per proof of sBPF field arithmetic, which is what makes
batched PLONK impractical today. Batch sizes are bounded by compute before
they hit the syscall caps: the 1.4M CU transaction limit admits roughly
110 to 130 batched proofs of either system, inside the 253-proof vanilla
Groth16 ceiling of the 256-pair check and the 226-proof PLONK ceiling of
the 2048-point MSM. All of this requires no new trusted setup and no
assumption beyond the hash as a random oracle. Shielded pools, rollups,
and any high-volume prover-submitting operator benefit directly.

Validators gain four syscalls with up-front, size-based pricing. Because
the batch layer is a normative SDK reference over these primitives rather
than a runtime feature, integrators bind the challenge to their own
transcript and are never dependent on an SDK function for soundness.

## Security Considerations

Every requirement below is either consensus behavior of the four syscalls
or a normative requirement on the batch reference, and each carries a
REQUIRED negative vector in the Conformance suite.

Enforced by the syscalls, independent of the caller:

- **G2 subgroup membership, per point.** G2's cofactor is near $2^{254}$,
  so on-curve says nothing about subgroup membership, and one non-subgroup
  element voids the prime-order hypothesis the $2^{-128}$ bound rests on.
  Checked and priced per point; skipping or batching the check is unsound
  by default.
- **Canonical encodings.** A limb at or above $p$ or a scalar at or above
  $q$ gives two byte strings for one value, handing any byte-keyed
  transcript free grinding bits. Rejected before any arithmetic.
- **A boolean verdict and nothing else.** No Fq12 crosses the boundary in
  either direction and nothing prepared is accepted: a returned target
  element invites the $M^{-1}$ injection, and prepared line coefficients
  can encode no real point (see Alternatives Considered). The ABI test
  asserts the absence of both.
- **No vacuous accept.** Zero pairs, zero points, and empty scalar arrays
  are errors, never the empty product; the deployed pairing operation
  returns true on empty input, and these syscalls MUST NOT.
  `fr_batch_invert` likewise rejects a zero scalar rather than return a
  bogus inverse that would corrupt a Lagrange evaluation an attacker
  steering a public input could reach.
- **Up-front pricing.** An underpriced pairing is the cheapest
  CPU-exhaustion primitive on the chain, and a meter that varies with
  content is an oracle. Compute is charged from declared counts before any
  work, and the MSM discount never undercharges a measured size.
- **Totality.** Any input on which a client panics, loops, or diverges is
  a consensus fault. All four syscalls are total, with bit-exact results
  across clients; the scalar-field pair carries no soundness weight of its
  own, only the requirement of exact agreement with a reference field
  implementation.

Specified normatively for the batch layer, where the runtime cannot check
the caller:

- **The challenge is the soundness.** Without randomizers, $+D$ / $-D$
  error terms on two proofs' C points cancel and the batch accepts two
  invalid proofs. The challenge MUST hash the complete frozen batch in
  canonical bytes with fixed-width framing; omitting proof bytes, public
  inputs, VK digests, counts, order, the per-record key index, or the
  domain tag each reopens a weak-Fiat-Shamir attack.
- **128-bit randomizers, never zero.** $\ell = 64$ is grindable offline
  once the random-oracle query factor multiplies in, and a zero randomizer
  silently drops an equation; `1 + lo128(.)` makes both unreachable.
  Randomizers attach to verification equations, not proofs.

## Drawbacks

- **Curve margin.** BN254 sits near 100-bit security after exTNFS, below
  the 128-bit target the ecosystem is moving toward (SIMD-0388 proposes
  BLS12-381 partly for this reason). It remains the compatibility choice,
  the curve snarkjs, circom, and gnark target and the deployed syscalls
  speak, and the interface stays curve-generic so a stronger instantiation
  is additive, not a redesign.
- **The batch layer is a specification, not a runtime check.** The
  syscalls enforce everything caller-independent; the challenge derivation
  is the caller's, and a program that ignores the normative reference can
  build an unsound batch from sound primitives. That is the deliberate
  price of four general primitives over a monolithic precompile
  (Alternatives Considered), paid once in the reference and its vectors.
- **All-or-nothing verdict.** One invalid proof fails the whole batch. In
  open submission the operator needs attribution, bisection or a deposit
  scheme, and that machinery is the integrator's, not this proposal's.
- **Random-oracle soundness.** The $2^{-128}$ bound is a random-oracle
  statement and inherits the grinding-query factor stated in Detailed
  Design; at 128-bit randomizers the factor is academic.
- **Governance surface.** Four new syscalls, their cost constants, and a
  re-pricing path: constants are fitted to the shipping backend and move
  only by feature gate, so a faster audited backend pays a governance
  round-trip before charges drop.

## Backwards Compatibility

Additive and feature-gated. The four syscalls are unavailable until the
feature is active, so pre-activation behavior is unchanged and no existing
program is affected. The design replaces an unmerged placeholder syscall
(`sol_alt_bn128_pairing_prepared`) that never activated on any cluster, so
there is no deployed behavior to preserve there. The encoding reuses the
existing alt_bn128 byte layout, so no on-chain data or client format changes.

## Conformance

Clients verify correctness against a shared vector suite. The change is
accompanied by a localnet ledger demonstrating behavior before activation, the
feature activation, and the four syscalls executing after activation. The
suite MUST include: the existing alt_bn128 test vectors (pinning the byte
layout), a positive vector per rail (uncommitted and committed) checked
against the individual verifier byte for byte, scalar-field vectors (a
`fr_lincomb` cross-checked against a reference inner product, a
`fr_batch_invert` cross-checked against per-element inversion, an
unequal-length pair, and a zero fed to `fr_batch_invert`), and one
negative vector per Security
Considerations item (off-curve, non-subgroup G2 at every position, the
cancelling out-of-subgroup pair, non-canonical limbs and scalars, infinity
handling, zero and cap errors, and the absence of any Fq12 or prepared slot).
Cross-client bit-level agreement on every vector is required.
