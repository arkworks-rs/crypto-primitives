## Pending

### Breaking changes

- [\#30](https://github.com/arkworks-rs/crypto-primitives/pull/30) Refactor the Merkle tree to separate the leaf hash and two-to-one hash.

### Features

- [\#38](https://github.com/arkworks-rs/crypto-primitives/pull/38) Add a signature verification trait `SigVerifyGadget`.
- [\#44](https://github.com/arkworks-rs/crypto-primitives/pull/44) Add basic ElGamal encryption gadgets.
- [\#48](https://github.com/arkworks-rs/crypto-primitives/pull/48) Add `CanonicalSerialize` and `CanonicalDeserialize` to `Path` and `CRH` outputs.

### Improvements

### Bug fixes

## v0.2.0

### Breaking changes

### Features

- [\#2](https://github.com/arkworks-rs/crypto-primitives/pull/2) Add the `SNARK` gadget traits.
- [\#3](https://github.com/arkworks-rs/crypto-primitives/pull/3) Add unchecked allocation for `ProofVar` and `VerifyingKeyVar`.  
- [\#4](https://github.com/arkworks-rs/crypto-primitives/pull/4) Add `verifier_size` to `SNARKGadget`.
- [\#6](https://github.com/arkworks-rs/crypto-primitives/pull/6) Add `IntoIterator` for SNARK input gadgets.
- [\#28](https://github.com/arkworks-rs/crypto-primitives/pull/28) Adds Poseidon CRH w/ constraints.

### Improvements

### Bug fixes

## v0.1.0 (Initial release of arkworks/crypto-primitives)