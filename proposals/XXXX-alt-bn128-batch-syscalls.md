---
simd: 'XXXX'
title: BN254 Batch Verification Syscalls
authors:
  - Alexander Atamanov (Helius), alexander@helius.xyz
  - Jorrit Palfner (Helius), jorrit@helius.xyz
category: Standard
type: Core
status: Idea
created: 2026-07-15
feature: (fill in with feature tracking issues once accepted)
---

## Summary

This proposal adds typed BN254 (`alt_bn128`) syscalls for:

1. **Composable pairing operations** (G2 preparation, Miller loops over raw or
   prepared inputs, Fp12 multiplication, and final exponentiation)
2. **G1 multi-scalar multiplication**
3. **Scalar-field inner product and batch inversion**

Each syscall reads and writes either the deployed big-endian encoding or a
little-endian variant, selected per call. The existing group and compression
syscalls remain unchanged.

## Motivation

Solana programs verify Groth16 proofs with the deployed BN254 syscalls, one
proof at a time. Batch verification shares work across proofs. Linear
combinations become multi-scalar multiplications, and several pairing equations
become one pairing product with one final exponentiation. The deployed interface
does not expose those units of work. Its pairing operation returns only a
boolean, so a program cannot cache a fixed pairing term or combine partial
products, and every call re-derives the Miller line coefficients of G2 points
that never change. Scalar-field arithmetic still often runs in sBPF.

This proposal exposes the shared work directly. G1 MSM performs the linear
folds, the pairing pipeline prepares fixed G2 points once and combines Miller
results before one final exponentiation, and the Fr helpers cover the field work
that dominates polynomial-opening verifiers. This benefits proof relayers,
privacy protocols, and compressed-state systems that verify the same circuit
many times.

The new operations avoid the opaque-buffer pattern of `sol_alt_bn128_group_op`,
whose byte-length contract required two later fixes ([SIMD-0222], [SIMD-0334]).
Like the Edwards and Ristretto APIs, they use typed point and scalar pointers
with an element count.

[SIMD-0222]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0222-fix-alt-bn128-multiplication-length-check.md
[SIMD-0334]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0334-fix-alt-bn128-pairing-length-check.md

## New Terminology

- Batch verification: Checking several proofs while sharing verifier work.

- Miller result: An Fp12 value produced before final exponentiation.

- GT element: A value in the target group, the order-`r` multiplicative subgroup
  of Fp12 and the image of final exponentiation.

- Prepared G2: The fixed sequence of Miller-loop line coefficients derived from
  a G2 point, computed once and reused across pairing calls.

## Detailed Design

The operations expose arithmetic, not a proof format or transcript. Programs
construct their own verification equations.

### Syscall Interface

The proposal adds eight syscalls. Every argument is an unsigned 64-bit value in
the standard syscall argument registers, in the listed order. Address arguments
are virtual-machine addresses of the typed values defined below. The first
argument of every syscall, `encoding`, accepts exactly two values:

```text
ALT_BN128_BE = 0x00   big-endian, the deployed byte order
ALT_BN128_LE = 0x80   little-endian
```

Any other value is misuse.

| Symbol | Arguments after `encoding` | Result bytes |
| --- | --- | ---: |
| `sol_alt_bn128_g1_msm` | `points, scalars, count, result` | 64 |
| `sol_alt_bn128_g2_prepare` | `point, result` | 16704 |
| `sol_alt_bn128_pairing_miller` | `pairs, count, result` | 384 |
| `sol_alt_bn128_pairing_miller_prepared` | `g1s, preps, count, result` | 384 |
| `sol_alt_bn128_fp12_mul` | `a, b, result` | 384 |
| `sol_alt_bn128_pairing_final_exp` | `f, result` | 384 |
| `sol_alt_bn128_fr_lincomb` | `a, b, count, result` | 32 |
| `sol_alt_bn128_fr_batch_invert` | `elems, count, result` | `32 * count` |

`sol_alt_bn128_g1_msm`, `sol_alt_bn128_fr_lincomb`, and
`sol_alt_bn128_pairing_miller_prepared` take one count for both input arrays, so
that a length mismatch cannot exist at the syscall boundary. Argument registers
beyond those listed are ignored.

Each syscall returns 0 on success and 1 on any rejected input value, without
distinguishing causes. Per [SIMD-0129], interface misuse is not a rejected
value. An undefined `encoding`, and a count of zero or above the operation's
cap, abort execution with `SyscallError::InvalidAttribute`, the variant the
deployed curve syscalls throw for an invalid identifier.

[SIMD-0129]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0129-alt-bn128-simplified-error-code.md

### Memory Semantics

Each input region must be readable and each result region writable for the full
byte length implied by its type and `count`. Regions carry no alignment
requirement beyond byte alignment. Execution order:

1. Consume the compute charge of the Compute Cost section, computed from the
   declared arguments before any check. A charge above the remaining budget
   exhausts it and aborts.
2. Abort on interface misuse as defined above, before any memory access.
3. Translate every region. An unmapped or mispermissioned region aborts the
   virtual machine, as with other syscalls.
4. Validate values. A rejected value returns 1 and leaves the result region
   unmodified.
5. Compute and write the result.

Every abort and rejection after step 1 leaves the charge consumed.
Implementations must behave as if all input bytes were read before any result
byte is written, so a result region may overlap an input region.

### SDK Interface

The SDK exposes safe, typed wrappers. Only the type table below binds
validators, because it fixes the byte layouts behind the syscall region lengths.
The rest of this section binds the SDK. Programs pass slices and receive typed
results. Two wrappers write through caller-provided references:
`alt_bn128_g2_prepare` (16,704 bytes exceeds an SBF stack frame) and
`alt_bn128_fr_batch_invert` (65,536 bytes at the cap exceeds the default heap).
A single prepared value fits the default 32 KiB program heap. A prepared array
at the pairing cap is 1,069,056 bytes, beyond the 256 KiB maximum heap, so
programs store prepared bytes in account data and pass them to the syscall in
place. The types are 1-byte-aligned, so an account-data slice casts directly.

```rust
pub enum Endianness {
    Le,
    Be,
}

pub fn alt_bn128_g1_msm(
    enc: Endianness,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128Error>;

pub fn alt_bn128_g2_prepare(
    enc: Endianness,
    point: &PodG2Point,
    out: &mut PodPreparedG2,
) -> Result<(), AltBn128Error>;

pub fn alt_bn128_pairing_miller(
    enc: Endianness,
    pairs: &[PodG1G2Pair],
) -> Result<PodFp12, AltBn128Error>;

pub fn alt_bn128_pairing_miller_prepared(
    enc: Endianness,
    g1_points: &[PodG1Point],
    prepared: &[PodPreparedG2],
) -> Result<PodFp12, AltBn128Error>;

pub fn alt_bn128_fp12_mul(
    enc: Endianness,
    a: &PodFp12,
    b: &PodFp12,
) -> Result<PodFp12, AltBn128Error>;

pub fn alt_bn128_pairing_final_exp(
    enc: Endianness,
    f: &PodFp12,
) -> Result<PodGtElement, AltBn128Error>;

pub fn alt_bn128_fr_lincomb(
    enc: Endianness,
    a: &[PodScalar],
    b: &[PodScalar],
) -> Result<PodScalar, AltBn128Error>;

pub fn alt_bn128_fr_batch_invert(
    enc: Endianness,
    elems: &[PodScalar],
    out: &mut [PodScalar],
) -> Result<(), AltBn128Error>;

pub fn alt_bn128_pairing_check(
    enc: Endianness,
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128Error>;
```

All wrappers return `AltBn128Error::InvalidInputData` for empty input, input
over a limit, mismatched slice lengths (including `out` versus `elems` in
`alt_bn128_fr_batch_invert`), a value rejected by the rules below, or a syscall
return of 1; `out` parameters are not modified on error. Wrappers derive counts
from slice lengths, check limits before invoking a syscall, and always pass a
defined `encoding`, so they cannot trigger the fatal aborts above. The SDK also
implements `From<PodGtElement> for PodFp12` and
`PodGtElement::identity(Endianness)`. `alt_bn128_pairing_check` is a wrapper
composition, not a ninth syscall. It issues the Miller and final-exponentiation
syscalls and compares the result with the encoded identity.

The SDK types are 1-byte-aligned byte arrays:

```rust
#[repr(C)]
pub struct PodG1G2Pair {
    pub g1: PodG1Point,
    pub g2: PodG2Point,
}
```

| Type | Representation |
| --- | --- |
| `PodG1Point` | `#[repr(transparent)] [u8; 64]` |
| `PodG2Point` | `#[repr(transparent)] [u8; 128]` |
| `PodScalar` | `#[repr(transparent)] [u8; 32]` |
| `PodFp12` | `#[repr(transparent)] [u8; 384]` |
| `PodGtElement` | `#[repr(transparent)] [u8; 384]` |
| `PodPreparedG2` | `#[repr(transparent)] [u8; 16704]` |

`PodG1G2Pair` is 192 bytes with no padding. Every type implements the byte-cast
(`Pod`) traits except `PodGtElement`, which keeps its field private, so safe
code obtains one only from `alt_bn128_pairing_final_exp` or
`PodGtElement::identity`, and each source yields a value in GT. This is API
guidance, not a security boundary. The syscall sees only bytes, and any 384
bytes can be submitted as `PodFp12`. The types carry no endianness of their own.

### Encoding

Two encodings are defined, selected by the `encoding` values of the Syscall
Interface section. Point and scalar bytes match deployed behavior and are not
redefined here: `ALT_BN128_BE` is the deployed big-endian alt_bn128 encoding,
and `ALT_BN128_LE` is the deployed [SIMD-0284] little-endian variant, the byte
reversal of each 32-byte scalar and each point coordinate, so an Fq2 coordinate
reads `c1 || c0` under BE and `c0 || c1` under LE. Points are `x || y` and
all-zero point bytes encode infinity under both. `PodG1G2Pair` is a G1 point
followed by a G2 point.

Decoding rejects a coordinate or coefficient greater than or equal to `p` and a
scalar greater than or equal to `r`, the moduli of the deployed operations.
Values are never reduced. Every result is canonical, so byte equality is value
equality within one encoding. The two encodings of a value differ byte-wise, so
a program stores and compares bytes under one encoding.

[SIMD-0284]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0284-alt-bn128-little-endian.md
[SIMD-0388]: https://github.com/solana-foundation/solana-improvement-documents/pull/388

The Fp12, GT, and prepared-G2 layouts are new and specified here directly. `Fq`
is the base field of modulus `p`. Fp12 uses this tower and coefficient notation:

```text
Fq2  = Fq[u]  / (u^2 + 1),       a = c0 + c1*u
Fq6  = Fq2[v] / (v^3 - (9 + u)), b = c0 + c1*v + c2*v^2
Fq12 = Fq6[w] / (w^2 - v),       f = c0 + c1*w
```

`PodFp12` and `PodGtElement` hold twelve canonical 32-byte Fq coefficients.
Under LE they appear in tower order, lowest degree first, each Fq little-endian:

```text
c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1, c0.c2.c0, c0.c2.c1,
c1.c0.c0, c1.c0.c1, c1.c1.c0, c1.c1.c1, c1.c2.c0, c1.c2.c1
```

Under BE the order reverses and each Fq is big-endian: the BE encoding is the
byte reversal of the LE encoding, the rule [SIMD-0388] uses for its target
group. The identity is `0x01` then 383 zeros under LE, and the reverse under BE.
The coefficient order is part of the consensus interface.

The two types share a layout but differ semantically: `PodFp12` is any canonical
Fp12 value. `PodGtElement` is an opaque GT value that no syscall accepts
directly, so a program widens it to `PodFp12` first. The separation binds only
the SDK.

A `PodPreparedG2` holds exactly 87 line-coefficient triples `(c0, c1, c2)`, each
component an Fq2 under the selected encoding, in the evaluation order of the V0
Pairing Definition (see appendix). Triple and sequence order do not vary with
encoding, and each Fq2 component follows the point-coordinate rule, so a BE
triple is not the byte reversal of its LE form. The count follows the ate loop:
64 doubling steps, 21 addition steps for the nonzero loop digits below the top
one, and 2 final Frobenius steps. The prepared format is versioned by the
syscall symbols. A schedule or layout change requires new symbols behind a new
feature gate, and stored V0 bytes stay valid under the V0 symbols indefinitely.

### G1 Multi-Scalar Multiplication

`alt_bn128_g1_msm` computes:

```text
result = sum(scalars[i] * points[i])
```

The syscall validates every point and scalar before arithmetic. A G1 point is
either the all-zero infinity encoding or a canonical point on the curve. G1 has
cofactor 1, so no separate subgroup check is needed. Infinity and zero scalars
contribute the identity. An identity result is written as all-zero point bytes.

### Pairing Operations

The pairing pipeline is composable:

- `alt_bn128_g2_prepare` validates a G2 point and returns its Miller line
  coefficients.
- `alt_bn128_pairing_miller` returns the product of the Miller loops for all
  input pairs, before final exponentiation.
- `alt_bn128_pairing_miller_prepared` returns the same product for G1 points
  paired with prepared G2 values.
- `alt_bn128_fp12_mul` multiplies two canonical Fp12 values.
- `alt_bn128_pairing_final_exp` raises a nonzero Fp12 value to the BN254 final
  exponent `(p^12 - 1) / r` and returns a `PodGtElement`.

`alt_bn128_fp12_mul`, `alt_bn128_pairing_final_exp`, and
`alt_bn128_pairing_miller_prepared` are provenance-sensitive primitives that
accept any canonical bytes (see Security Considerations).

A pairing check is a composition: one Miller call,
`alt_bn128_pairing_final_exp`, and a byte comparison with
`PodGtElement::identity(enc)`. There is no fused check or map syscall (see
Alternatives Considered). The SDK ships the composition as
`alt_bn128_pairing_check`. Programs may widen a `PodGtElement` to `PodFp12`,
combine final-exponentiated terms with `alt_bn128_fp12_mul`, and compare with
the widened identity. Widened bytes can be stored as a cached fixed term.

For accepted inputs, the operations satisfy:

```text
miller_prepared(g1s, [prepare(q) for q in g2s]) = miller(pairs)
final_exp(fp12_mul(miller(A), miller(B)))
                     = final_exp(miller(A concatenated with B))
```

where `pairs` zips `g1s` with `g2s`. The first identity requires that no G2
point is infinity, because preparation rejects the infinity encoding. The second
requires the concatenated list to be within `ALT_BN128_PAIRING_MAX_PAIRS`.

Each raw pair is validated before arithmetic: G1 by the rules above, G2 as the
all-zero infinity encoding or a canonical point on the twist in the order-`r`
subgroup (`[r]Q` is infinity). A pair with an infinity member contributes the
Fp12 identity after validation.

`alt_bn128_g2_prepare` performs the same full G2 validation but rejects
infinity, which a program handles by dropping that pair. A fixed verifying key
is prepared once, stored, and reused.

`alt_bn128_pairing_miller_prepared` validates G1 points and checks every
prepared coefficient for canonicality, nothing else: the runtime treats prepared
bytes as opaque field elements and must not attempt to verify their provenance.
An infinity G1 contributes the identity for its pair.

Two correct Miller implementations can produce different intermediate Fp12 bytes
for the same pairs and still agree after final exponentiation. The deployed
boolean pairing needs only that agreement, so clients were free to differ
internally. These syscalls return the Miller result itself, making its bytes
consensus-observable, so every client must compute it identically. The V0
Pairing Definition in the appendix fixes the computation byte-exactly and is
normative.

The all-zero Fp12 value is valid input to `alt_bn128_fp12_mul` but rejected by
`alt_bn128_pairing_final_exp`. A Miller product over validated pairs is never
zero. Forged prepared coefficients can produce zero. For in-subgroup inputs, the
composed check matches the deployed pairing verdict, a claim testable under BE
only. The appendix governs if the two ever disagree. The new syscalls
additionally validate the G2 subgroup, which the deployed operation does not.

### Scalar-Field Operations

`alt_bn128_fr_lincomb` computes the inner product:

```text
result = sum(a[i] * b[i]) mod r
```

`alt_bn128_fr_batch_invert` returns `a[i]^-1` for each input. It rejects the
entire input if any element is zero. Both operations validate every scalar
before computing a result.

### Length Limits

```rust
pub const ALT_BN128_G1_MSM_MAX_POINTS: u64 = 2048;
pub const ALT_BN128_PAIRING_MAX_PAIRS: u64 = 64;
pub const ALT_BN128_FR_MAX_ELEMS: u64 = 2048;
```

Both Miller operations share `ALT_BN128_PAIRING_MAX_PAIRS`.
`ALT_BN128_G1_MSM_MAX_POINTS` caps `sol_alt_bn128_g1_msm`, and
`ALT_BN128_FR_MAX_ELEMS` caps both Fr operations. The other pairing operations
have fixed-size inputs. A count equal to a cap is valid. Zero and above-cap
counts abort as Memory Semantics specifies.

The pairing cap is set so a full-cap call is achievable: at the deployed Agave
schedule (`alt_bn128_pairing_one_pair_cost_first` at 36,364 CU,
`alt_bn128_pairing_one_pair_cost_other` at 12,121 CU), 64 pairs cost about
800,000 CU, within the 1,400,000 CU transaction budget, and prepared inputs at
the cap are 1,069,056 bytes, within one account and the loaded-account-data
limit. The MSM and Fr caps bound per-call memory and validation work. Whether a
full-cap call fits the compute budget depends on the fitted constants.

### Edge Cases

- **Zero count.** Aborts execution, because a vacuous result is a verification
hazard: an empty Miller product is the Fp12 identity, so a pairing check over an
accidentally empty list would pass. A zero count is a program bug, and aborting
fails closed. This deliberately departs from SIMD-0388, which returns the GT
identity for an empty pair list.
- **Infinity.** All-zero point bytes are infinity under both encodings. A raw
pair with an infinity member contributes the Fp12 identity.
`alt_bn128_g2_prepare` rejects infinity.
- **Field boundaries.** Coordinates and coefficients equal to `p` and scalars
equal to `r` are rejected; `p - 1` and `r - 1` are valid.
- **Zero Fp12.** Valid input to `alt_bn128_fp12_mul`, rejected by
`alt_bn128_pairing_final_exp`.
- **Overlap.** A result region may overlap an input region. Behavior is
read-all-then-write.
- **Mixed encodings.** Each call interprets bytes under its own `encoding`.
Passing LE bytes under `ALT_BN128_BE` yields a different value that can still be
canonical and accepted.

### Compute Cost

Each syscall consumes a deterministic charge of the form
`base + per_element * count`, where fixed-input operations charge `base`. The
charge is computed in saturating u64 arithmetic on the declared, unvalidated
count and consumed at step 1 of the Memory Semantics order, so an aborting call
consumes its full charge on every client. The constants are consensus-critical
and will be fixed by cross-client benchmarking before activation.

### Feature Activation

One feature gate registers all eight symbols; the operations ship and activate
as a single family.

### Validator Components Affected

| Component | Impact |
| --- | --- |
| Transaction execution (SVM) | Eight new stateless syscalls |
| Virtual machine | Syscall registration behind one gate |
| Compute budget | New per-operation charges |
| SDK | Pod types and safe wrappers |
| Consensus, gossip, Turbine, snapshots | None |

## Alternatives Considered

### Extend `sol_alt_bn128_group_op`

New operation identifiers could be added to the existing opaque-buffer syscall,
preserving one symbol but also the byte-length contract that required SIMD-0222
and SIMD-0334. Dedicated typed signatures make the count and shape contracts
explicit and leave the deployed operation unchanged.

### Fused Check and Map Syscalls

Earlier drafts included fused `pairing_check` and `pairing_map` syscalls. Both
are exact compositions of the retained calls. A fused form is misuse-resistant,
because the runtime knows its final-exponentiation input came directly from
validated pairs. The split form places that obligation on the program, and the
deployed boolean is no substitute: it skips the G2 subgroup check, so after
activation no syscall performs a fused check under the new validation rules.
This proposal accepts that deliberately. The composition is two syscalls and a
byte comparison with no data-dependent branching, the SDK ships it as the single
wrapper `alt_bn128_pairing_check`, and a fused syscall would re-enter the
runtime as a second way to express the same computation.

### A Proof-System-Specific Syscall

A Groth16 or PLONK verifier syscall could expose a smaller surface, but it would
fix the proof encoding, transcript, and variant in the runtime. Arithmetic
syscalls are reusable across verifiers and leave transcript construction in the
program.

### Extend the Generic `sol_curve_*` Interface

The existing `sol_curve_multiscalar_mul` could take a BN254 G1 curve identifier
instead of adding `sol_alt_bn128_g1_msm`. That precedent is weaker than it
looks: SIMD-0388 extends `sol_curve_group_op`, `sol_curve_validate_point`,
`sol_curve_pairing_map`, and `sol_curve_decompress` for BLS12-381, but leaves
the MSM syscall untouched, so no pairing curve goes through the generic MSM
today. Its shape also does not fit: it takes 32-byte compressed little-endian
curve25519 points, while BN254 G1 here is a 64-byte affine point under a
per-call BE/LE selector aligned with the deployed alt_bn128 encodings.

The rest of this family has no generic home at all: the `sol_curve_*` surface
defines no Miller results, Fp12 multiplication, prepared inputs, or scalar-field
helpers. Dedicated syscalls are needed regardless, and routing only the MSM
through the generic ABI would split one family across two ABIs with different
selectors, argument conventions, and feature gates. A later SIMD can still add
BN254 identifiers to the generic interface; this proposal does not block it.

### Raw G2 Inputs Only

Omitting prepared inputs would keep every pairing input a self-authenticating
group element, but would re-derive the line coefficients of fixed verifying-key
points in every verification. The prepared path stays. Pairing inversion is
expressed by negating G1 or G2, so Fp12 inversion is also omitted.

## Impact

Programs can batch BN254 proof verification without adopting a runtime-defined
proof format, and can amortize G2 preparation across verifications of a fixed
verifying key. Existing programs are unaffected.

Validator clients add eight stateless, feature-gated syscalls and byte-exact
consensus representations for Fp12 values and prepared G2 coefficients, each in
two encodings. SDKs add the corresponding Pod types and safe slice-based
wrappers.

## Security Considerations

The runtime validates canonical encodings, curve membership, and the G2 subgroup
before pairing arithmetic and preparation. This is stricter than the deployed
pairing operation, which skips the subgroup check, so a program mixing the two
over the same inputs can accept on one path and reject on the other. A
verification equation should migrate as a unit.

The composable interface accepts caller-supplied Fp12 values, and final
exponentiation proves nothing about their origin. A verifier that admits one
unauthenticated Fp12 factor is unsound. An attacker supplies the off-chain
inverse of the legitimate Miller output, the product becomes the identity, and
every canonicality check passes. A sound check feeds final exponentiation only
Miller output over validated pairs and trusted program-owned bytes.

Prepared G2 bytes carry the same trust model. Only canonicality is checked, so a
caller who forges coefficients chooses the Miller output freely, including a
value that makes the composed check accept. They must come from
`alt_bn128_g2_prepare` or trusted program-owned state.

Comparing a product of widened `PodGtElement` values with the encoded identity
is sound only under the same provenance rules, and GT membership never binds a
factor to a statement; the program's equation must. Batch soundness also depends
on the program's transcript and randomizers, which these syscalls do not define
or validate.

## Drawbacks

The prepared representation freezes one Miller schedule and one layout as a
permanent, program-stored ABI. A single feature gate means the family activates
or rolls back as a whole; no operation can ship separately.

## Backwards Compatibility

The change is consensus-breaking and requires the feature gate. Before
activation the symbols are unavailable and no deployed behavior changes.
Activation changes nothing for existing programs, `sol_alt_bn128_group_op`, or
`sol_alt_bn128_compression`.

## Conformance

Cross-client vectors must cover, under both encodings: counts of 1, the cap, and
the abort cases zero and cap plus one; coordinates and coefficients at `p - 1`
and `p`, scalars at `r - 1` and `r`, infinity encodings, non-subgroup G2 points,
the zero Fp12 value, forged prepared coefficients including triples that zero
the Miller product, overlapping input and result regions, no-write-on-error, the
precedence of aborts over value rejections, and the consumed-CU accounting of
aborting calls. Miller-result and prepared-coefficient vectors are generated
from the V0 Pairing Definition in the appendix.

## Appendix: V0 Pairing Definition

This definition is normative. The pairing is the optimal ate pairing on BN254
with curve parameter `x = 4965661367192848881`. The loop scalar is `6x + 2`,
processed in the signed-digit form below, least significant digit first:

```text
 0,  0,  0,  1,  0,  1,  0, -1,  0,  0, -1,  0,  0,  0,  1,  0,  0, -1,  0, -1,
 0,  0,  0,  1,  0, -1,  0,  0,  0,  0, -1,  0,  0,  1,  0, -1,  0,  0,  1,  0,
 0,  0,  0,  0, -1,  0,  0, -1,  0,  1,  0, -1,  0,  0,  0, -1,  0, -1,  0,  0,
 0,  1,  0,  1,  1
```

Libraries encode `6x + 2` in differing signed forms with differing step counts,
so only this listing is normative.

G2 points lie on the sextic D-twist `y^2 = x^3 + 3/(9 + u)` over Fq2. A
coefficient triple `(c0, c1, c2)` evaluated at a G1 point `(x_P, y_P)` is the
sparse Fp12 element `c0*y_P + (c1*x_P)*w + c2*v*w` in the tower notation of the
Encoding section.

Preparation tracks `R = (X, Y, Z)` in homogeneous projective coordinates over
Fq2, starting at `(x_Q, y_Q, 1)`. Scanning the digits from the second most
significant down to the least significant, each position emits one doubling
triple, and each nonzero digit emits one addition triple with `Q` for digit 1
and the negation `(x_Q, -y_Q)` for digit -1. Division by 2 is multiplication by
the inverse of 2 in Fq:

```text
double(R = (X, Y, Z)), with b' = 3/(9 + u):
  A = X*Y/2;  B = Y^2;  C = Z^2
  E = 3*b'*C;  F = 3*E;  G = (B + F)/2
  H = (Y + Z)^2 - (B + C);  I = E - B;  J = X^2
  X' = A*(B - F);  Y' = G^2 - 3*E^2;  Z' = B*H
  triple = (-H, 3*J, I)

add(R = (X, Y, Z), Q = (x_Q, y_Q)):
  T = Y - y_Q*Z;  L = X - x_Q*Z
  C = T^2;  D = L^2;  E = L*D;  F = Z*C;  G = X*D
  H = E + F - 2*G
  X' = L*H;  Y' = T*(G - H) - E*Y;  Z' = Z*E
  triple = (L, -T, T*x_Q - L*y_Q)
```

After the loop, two final addition triples are emitted with `Q1` and then `Q2`,
where `a^p` is the Fq2 Frobenius (conjugation) and `xi = 9 + u`:

```text
Q1 = (x_Q^p  * xi^((p-1)/3),    y_Q^p  * xi^((p-1)/2))
Q2 = (x_Q1^p * xi^((p-1)/3),  -(y_Q1^p * xi^((p-1)/2)))
```

The Miller loop starts at `f = 1` and consumes triples in emission order: at
each digit position `f` is squared (except at the first processed position),
then multiplied by every pair's doubling line and, for a nonzero digit, by every
pair's addition line. The two final triples are consumed the same way after the
loop, with no squaring before them. The loop scalar is positive, so no
conjugation follows the loop. The Miller result is `f`. The pairing map is
`f^((p^12 - 1) / r)`. Conformance vectors cover this definition but do not
replace it.

### GT Byte Order

Point and scalar byte order is settled, and this proposal only adds the per-call
selector: BE is the deployed alt_bn128 encoding, and LE is the deployed
[SIMD-0284] reversal of each coordinate, which turns the `c1 || c0` G2
coordinate into `c0 || c1`.

The Fp12 and GT layout is new consensus surface. The deployed pairing operation
returns a boolean, so no GT byte layout exists on-chain to inherit. The ordering
rule of the Encoding section makes each encoding coincide with an existing
library serialization:

- LE, ascending tower order with each Fq little-endian, is byte-for-byte the
  arkworks canonical Fp12 serialization.
- BE, its full byte reversal (descending order, each Fq big-endian), is
  byte-for-byte the gnark-crypto GT marshaling, which writes `C1.B2.A1` first
  down to `C0.B0.A0`.

A verifier on either stack produces and compares GT bytes without
re-serialization, and the two encodings remain mutual byte reversals, the rule
that [SIMD-0388] applies to its target group.
