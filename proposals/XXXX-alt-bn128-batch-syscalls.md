---
simd: 'XXXX'
title: BN254 Batch Verification Syscalls
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

This proposal adds typed BN254 (`alt_bn128`) syscalls for:

1. **G1 multi-scalar multiplication**
2. **Pairing operations** (Miller loop, Fp12 multiplication, final
   exponentiation, pairing map, and pairing check)
3. **Scalar-field inner product and batch inversion**

The existing group and compression syscalls remain unchanged.

## Motivation

Solana programs already verify Groth16 proofs with the deployed BN254
syscalls. The current interface is effective for a single Groth16 proof.
It is not effective for workloads that collect many proofs and need to
settle them together or PLONK.

Batch verification shares work across proofs. Linear combinations become
multi-scalar multiplications, and several pairing equations become one
pairing product with one final exponentiation. The deployed interface does
not expose those units of work. Programs must issue one scalar
multiplication per term, and the pairing operation returns only a boolean.
The boolean discards the target-group value, so a program cannot cache a
fixed pairing term or combine partial products produced by separate calls.

The result is that proof verification is available, but its throughput is
bounded by repeated work that batch verification is designed to remove.
This affects proof relayers, privacy protocols, and compressed-state
systems that verify the same circuit many times. Scalar-field arithmetic
is also still implemented in sBPF. This makes the field-heavy parts of
polynomial-opening verifiers a separate bottleneck even when pairing
support is available.

This proposal exposes the shared work directly. G1 MSM performs the linear
folds. The pairing pipeline lets programs choose a fused check or assemble
one product from several Miller results before paying for final
exponentiation. The Fr helpers cover the field operations that dominate
polynomial-opening verifiers.

The proposal also avoids the opaque-buffer pattern for these new
operations. `sol_alt_bn128_group_op` accepts bytes plus a byte length.
Two length checks in that interface required later fixes ([SIMD-0222],
[SIMD-0334]). The Edwards and Ristretto APIs instead use typed point and
scalar pointers with an element count. This proposal uses the same shape
for BN254, including typed result pointers.

[SIMD-0222]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0222-fix-alt-bn128-multiplication-length-check.md
[SIMD-0334]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0334-fix-alt-bn128-pairing-length-check.md

## New Terminology

- Batch verification: Checking several proofs while sharing verifier work.

- Miller result: An Fp12 value produced before final exponentiation.

- GT element: A nonzero Fp12 value in the pairing target group.

## Detailed Design

The new operations expose arithmetic rather than a proof format or
transcript. Programs remain responsible for constructing their own
verification equations.

The current Agave experiment implements the typed G1 MSM, pairing check,
pairing map, Fr inner product, and Fr batch inversion. This proposal
exposes those operations through safe SDK functions and adds the Miller,
Fp12 multiplication, and final exponentiation calls needed for partial
pairing products. The proof-system-specific reducers on the experimental
branch are not part of this proposal.

### SDK Interface

The SDK exposes safe, typed wrappers. Programs pass slices and receive typed
results; they do not provide element counts, output buffers, or syscall status
codes.

```rust
pub fn alt_bn128_g1_msm(
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128Error>;

pub fn alt_bn128_pairing_miller(
    pairs: &[PodG1G2Pair],
) -> Result<PodFp12, AltBn128Error>;

pub fn alt_bn128_fp12_mul(
    a: &PodFp12,
    b: &PodFp12,
) -> Result<PodFp12, AltBn128Error>;

pub fn alt_bn128_pairing_final_exp(
    f: &PodFp12,
) -> Result<PodGtElement, AltBn128Error>;

pub fn alt_bn128_pairing_check(
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128Error>;

pub fn alt_bn128_pairing_map(
    pairs: &[PodG1G2Pair],
) -> Result<PodGtElement, AltBn128Error>;

pub fn alt_bn128_fr_lincomb(
    a: &[PodScalar],
    b: &[PodScalar],
) -> Result<PodScalar, AltBn128Error>;

pub fn alt_bn128_fr_batch_invert(
    a: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128Error>;
```

`alt_bn128_g1_msm` and `alt_bn128_fr_lincomb` return
`AltBn128Error::InvalidInputData` when their input slices have different
lengths. Every slice-taking wrapper returns the same error for an empty input,
an input over the operation's limit, or a value rejected by the validation
rules below. The fixed-size wrappers return that error for a rejected value.

The SDK types are byte-aligned Pod values:

```rust
#[repr(C)]
pub struct PodG1G2Pair {
    pub g1: PodG1Point,
    pub g2: PodG2Point,
}
```

| Pod type | Representation |
| --- | --- |
| `PodG1Point` | `#[repr(transparent)] [u8; 64]` |
| `PodG2Point` | `#[repr(transparent)] [u8; 128]` |
| `PodScalar` | `#[repr(transparent)] [u8; 32]` |
| `PodFp12` | `#[repr(transparent)] [u8; 384]` |
| `PodGtElement` | `#[repr(transparent)] [u8; 384]` |

`PodG1G2Pair` is 192 bytes with no padding.

The wrappers derive element counts from slice lengths. They return `Ok(false)`
for a false pairing verdict; a false verdict is not an error.
The runtime reads all input values before writing a result.

### Encoding

G1, G2, pairs, and scalars use the existing big-endian alt_bn128
encoding:

| Type | Size | Encoding |
| --- | ---: | --- |
| `PodG1Point` | 64 | `x || y` |
| `PodG2Point` | 128 | `x.c1 || x.c0 || y.c1 || y.c0` |
| `PodScalar` | 32 | canonical scalar below `r` |
| `PodG1G2Pair` | 192 | G1 followed by G2 |

All-zero point bytes encode infinity. Other coordinates are canonical
base-field elements and are not reduced modulo `p`. Scalars are
canonical scalar-field elements and are not reduced modulo `r`.
`p` and `r` are the fields used by the deployed alt_bn128 operations.

`alt_bn128_pairing_check` returns a Rust `bool`.

Fp12 uses this tower and coefficient notation:

```text
Fq2  = Fq[u]  / (u^2 + 1),       a = c0 + c1*u
Fq6  = Fq2[v] / (v^3 - (9 + u)), b = c0 + c1*v + c2*v^2
Fq12 = Fq6[w] / (w^2 - v),       f = c0 + c1*w
```

`PodFp12` and `PodGtElement` are exactly 384 bytes. They contain twelve
canonical, big-endian, 32-byte Fq coefficients in this order:

```text
c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1, c0.c2.c0, c0.c2.c1,
c1.c0.c0, c1.c0.c1, c1.c1.c0, c1.c1.c1, c1.c2.c0, c1.c2.c1
```

The encoding follows the tower order: Fq12 `c0` then `c1`, each Fq6
`c0`, `c1`, then `c2`, and each Fq2 `c0` then `c1`. 

Programs can pass these bytes from `alt_bn128_pairing_miller` to
`alt_bn128_fp12_mul` and `alt_bn128_pairing_final_exp`. The coefficient
order is therefore part of the consensus interface: every validator must
interpret the same 384 bytes as the same Fp12 value.

Decoding rejects any coefficient greater than or equal to `p`; coefficients
are not reduced modulo `p`.

The Fp12 identity has `c0.c0.c0 = 1` and every other coefficient equal
to zero. `PodFp12` and `PodGtElement` have the same byte layout but
different semantic domains. `PodFp12` is a general canonical Fp12 value.
`PodGtElement` is a nonzero value in the GT subgroup. No operation accepts
it as input. An SDK conversion from untrusted bytes validates that the value
is nonzero and belongs to GT.

### G1 Multi-Scalar Multiplication

`alt_bn128_g1_msm` computes:

```text
result = sum(scalars[i] * points[i])
```

The syscall validates every point and scalar before arithmetic. A G1
point is either the all-zero infinity encoding or a canonical point on
the curve. G1 has cofactor 1, so no separate subgroup check is needed.
Infinity and zero scalars contribute the identity. An identity result is
written as all-zero point bytes.

### Pairing Operations

The pairing operations expose both fused and composable forms:

- `alt_bn128_pairing_miller` returns the product of the Miller loops
  for all input pairs, before final exponentiation.
- `alt_bn128_fp12_mul` multiplies two canonical Fp12 values.
- `alt_bn128_pairing_final_exp` applies the BN254 final exponent to a
  nonzero Fp12 value and returns a `PodGtElement`.
- `alt_bn128_pairing_map` performs the Miller loops and final
  exponentiation in one call.
- `alt_bn128_pairing_check` performs the map and returns whether the
  result is the GT identity.

For accepted inputs, the operations satisfy:

```text
pairing_map(pairs)   = final_exp(miller(pairs))
pairing_check(pairs) = true  iff  pairing_map(pairs) is GT identity
final_exp(fp12_mul(miller(A), miller(B)))
                     = pairing_map(A concatenated with B)
```

The last identity applies when the concatenated pair list is within the
map limit.

Each pair is validated before arithmetic. G1 uses the rules above. G2 is
either the all-zero infinity encoding or a canonical point on the twist
in the order-`r` subgroup. Subgroup membership means `[r]Q` is infinity.
A pair with an infinity member contributes the Fp12 identity after both
members have been validated.

The Miller result is observable and therefore requires a single
byte-exact definition. Before this proposal advances from Idea, its V0
definition will pin the pairing orientation, loop schedule, twist
embedding, line normalization, and final steps to immutable reference
source. Conformance vectors will cover the reference source but will not
replace it. Agreement only after final exponentiation is not sufficient
for this syscall.

The all-zero Fp12 value is valid input to `alt_bn128_fp12_mul`.
`alt_bn128_pairing_final_exp` rejects it because zero is not in the
multiplicative group mapped to GT. The fused map and check never accept an
Fp12 value from the caller.

For non-empty, in-subgroup inputs,
`alt_bn128_pairing_check` returns the same verdict as the deployed
pairing operation. The new syscall also validates G2 subgroup membership,
which the deployed operation does not. Empty input is rejected instead of
returning a vacuous true result.

### Scalar-Field Operations

`alt_bn128_fr_lincomb` computes:

```text
result = sum(a[i] * b[i]) mod r
```

`alt_bn128_fr_batch_invert` returns `a[i]^-1` for each input. It
rejects the entire input if any element is zero. Both operations validate
all canonical scalars before returning a result.

### Length Limits

```rust
pub const ALT_BN128_G1_MSM_MAX_POINTS: u64 = 2048;
pub const ALT_BN128_PAIRING_MAX_PAIRS: u64 = 256;
pub const ALT_BN128_PAIRING_MAP_MAX_PAIRS: u64 = 16;
pub const ALT_BN128_FR_MAX_ELEMS: u64 = 2048;
```

The check and Miller syscalls use `ALT_BN128_PAIRING_MAX_PAIRS`. The map
uses the range calibrated by the current batch-syscall experiment.
Fp12 multiplication and final exponentiation have fixed-size inputs. The
map limit is provisional until the final pricing sweep.

All counted operations reject a count of zero. A count equal to the cap
is valid. A count above the cap returns 1 if the compute charge succeeds.

### Compute Metering

Memory translation failure and compute budget exhaustion abort the virtual
machine instead of returning `AltBn128Error`.

Counted syscalls execute in this order:

1. Compute and consume the charge from the declared count.
2. Return 1 if the count is zero or above the cap.
3. Translate and copy each input region in signature order.
4. Validate the copied values.
5. Compute the result.
6. Translate the result region and write the result.

If the charge exceeds the remaining budget, step 1 aborts and saturates
the remaining budget to zero. Memory faults in steps 3 or 6 abort after
the charge. Domain errors after step 1 consume the charge and leave the
result unchanged.

Fp12 multiplication and final exponentiation use the same order without
the count check.

All cost arithmetic uses saturating `u64` operations. Integer division
rounds down.

The experimental implementation contains fitted schedules for G1 MSM,
pairing check, pairing map, inner product, and batch inversion. The
Miller, Fp12 multiplication, and final-exponentiation schedules will be
fitted with the same public harness before this proposal advances from
Idea. The accepted revision will include all constants and formulas.
Every validator charges the same amount regardless of its arithmetic
backend.

### Feature Activation

One feature gate registers all eight symbols. Before activation, the
symbols are unavailable. Activation does not change
`sol_alt_bn128_group_op` or `sol_alt_bn128_compression`.

## Alternatives Considered

### Extend `sol_alt_bn128_group_op`

New operation identifiers could be added to the existing opaque-buffer
syscall. That would preserve one symbol, but it would also preserve the
byte-length contract that required SIMD-0222 and SIMD-0334. MSM and
pairing already need counts, while the Fr and Fp12 operations have
different input and output shapes. Dedicated typed signatures make those
contracts explicit and leave the deployed operation unchanged.

### Fused Pairing Operations Only

A check and map are sufficient when all pairs fit in one call. They are
not sufficient when a program needs to combine independently produced
pairing terms before one final exponentiation. A GT-only design can
combine mapped chunks, but it pays final exponentiation for every chunk.
The Miller/Fp12 path keeps that fixed work shared.

The tradeoff is that Miller output becomes consensus-visible. This
proposal accepts that cost and requires a byte-exact V0 definition.

### A Proof-System-Specific Syscall

A Groth16 or a particular PLONK verifier syscall could expose a smaller
surface. It would also fix the proof encoding, transcript, and supported
variant in the runtime. Arithmetic syscalls can be reused by different
verifiers and leave transcript construction in the program.

### Prepared G2 Inputs

Prepared line coefficients would avoid repeated preparation of fixed G2
points, but they are not self-authenticating group elements. The runtime
prepares G2 only after validating a raw point. Pairing inversion is
expressed by negating G1 or G2, so this proposal also omits Fp12
inversion.

## Impact

Programs can batch BN254 proof verification without adopting a
runtime-defined proof format. Existing programs and existing alt_bn128
syscalls are unchanged.

Validator clients add eight stateless, feature-gated syscalls and a
byte-exact Fp12 consensus representation. SDKs add the corresponding Pod
types and safe slice-based wrappers.

## Security Considerations

The runtime validates canonical field encodings, curve membership, and
G2 subgroup membership before pairing arithmetic. This is stricter than
the deployed pairing operation, which does not check the G2 subgroup.

The composable pairing interface accepts caller-supplied Fp12 values.
Final exponentiation does not prove that a value, or every factor in a
product, came from a Miller loop. A verifier that includes an
unauthenticated Fp12 factor and checks only whether final exponentiation
produces the identity is unsound. Programs that do not need composition
should use `pairing_check`, which only accepts validated G1/G2 pairs.

Batch soundness also depends on the calling program's transcript and
randomizers. These syscalls perform arithmetic only. They do not define
or validate a batching transcript.
