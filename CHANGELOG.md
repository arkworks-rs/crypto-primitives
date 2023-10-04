# CHANGELOG

## Pending

- [\#120](https://github.com/arkworks-rs/crypto-primitives/pull/120) Add input size check to `bowe_hopwood::CRHGadget::evaluate`.

### Breaking changes

### Features

- [\#107](https://github.com/arkworks-rs/crypto-primitives/pull/107) Impl `CanonicalSerialize` and `CanonicalDeserialize` for `ark_crypto_primitives::crh::pedersen::Parameters`

### Improvements

### Bugfixes

## v0.4.0

### Breaking changes

- [\#56](https://github.com/arkworks-rs/crypto-primitives/pull/56) Compress the output of the Bowe-Hopwood-Pedersen CRH to a single field element, in line with the Zcash specification.
- [\#60](https://github.com/arkworks-rs/crypto-primitives/pull/60) Merkle tree's `Config` requires a user-defined converter to turn leaf hash output to inner hash output.
- [\#60](https://github.com/arkworks-rs/crypto-primitives/pull/60) Rename the CRH trait as `CRHScheme` and the CRHGadget trait to `CRHSchemeGadget`.
- [\#60](https://github.com/arkworks-rs/crypto-primitives/pull/60) Use `ark-sponge` to instantiate Poseidon.
- [\#76](https://github.com/arkworks-rs/crypto-primitives/pull/79) Fix Pedersen padding bug.
- [\#77](https://github.com/arkworks-rs/crypto-primitives/pull/77) Implement SHA-256 CRH.
- [\#86](https://github.com/arkworks-rs/crypto-primitives/pull/86)
    - Moves `ark-sponge` here.
    - Updates dependencies and version number to `0.4`.
    - Adds feature flags to enable downstream users to select exactly those components that they're interested in.
- [\#103](https://github.com/arkworks-rs/crypto-primitives/pull/103) Removes `cp-benches` and moves contents to `benches`
- [\#104](https://github.com/arkworks-rs/crypto-primitives/pull/104) Updates `digest`, `blake2`, `sha2` to `0.10`. Changes API for `Blake2sWithParameterBlock`.

### Features

- [\#59](https://github.com/arkworks-rs/crypto-primitives/pull/59) Implement `TwoToOneCRHScheme` for Bowe-Hopwood CRH.
- [\#60](https://github.com/arkworks-rs/crypto-primitives/pull/60) Merkle tree no longer requires CRH to input and output bytes. Leaf can be any raw input of CRH, such as field elements.
- [\#67](https://github.com/arkworks-rs/crypto-primitives/pull/67) User can access or replace leaf index variable in `PathVar`.

### Improvements

### Bugfixes

## v0.3.0

### Breaking changes

- [\#30](https://github.com/arkworks-rs/crypto-primitives/pull/30) Refactor the Merkle tree to separate the leaf hash and two-to-one hash.

### Features

- [\#38](https://github.com/arkworks-rs/crypto-primitives/pull/38) Add a signature verification trait `SigVerifyGadget`.
- [\#44](https://github.com/arkworks-rs/crypto-primitives/pull/44) Add basic ElGamal encryption gadgets.
- [\#48](https://github.com/arkworks-rs/crypto-primitives/pull/48) Add `CanonicalSerialize` and `CanonicalDeserialize` to `Path` and `CRH` outputs.

### Improvements

### Bugfixes

## v0.2.0

### Breaking changes

### Features

- [\#2](https://github.com/arkworks-rs/crypto-primitives/pull/2) Add the `SNARK` gadget traits.
- [\#3](https://github.com/arkworks-rs/crypto-primitives/pull/3) Add unchecked allocation for `ProofVar` and `VerifyingKeyVar`.  
- [\#4](https://github.com/arkworks-rs/crypto-primitives/pull/4) Add `verifier_size` to `SNARKGadget`.
- [\#6](https://github.com/arkworks-rs/crypto-primitives/pull/6) Add `IntoIterator` for SNARK input gadgets.
- [\#28](https://github.com/arkworks-rs/crypto-primitives/pull/28) Adds Poseidon CRH w/ constraints.

### Improvements

### Bugfixes

## v0.1.0 (Initial release of arkworks/crypto-primitives)
