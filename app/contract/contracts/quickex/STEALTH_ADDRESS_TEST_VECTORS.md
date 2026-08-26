# Stealth Address Test Vectors

These vectors define the current QuickEx stealth-address proof of concept. All
hex strings represent exactly 32 bytes. They were independently calculated as
`SHA-256(eph_pub || spend_pub)` and then
`SHA-256(spend_pub || shared_secret)` using a system SHA-256 implementation.

There are no length prefixes, text encoding, point serialization, or byte-order
conversions. `eph_pub` is the sender's ephemeral 32-byte public-key blob and
`spend_pub` is the recipient's 32-byte spend-key blob.

| Case | `eph_pub` | `spend_pub` | `shared_secret` | `stealth_address` |
| --- | --- | --- | --- | --- |
| All zero | `0000000000000000000000000000000000000000000000000000000000000000` | `0000000000000000000000000000000000000000000000000000000000000000` | `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b` | `b62c0bf36d7fee9a6ed49f7529e9fbf6ebc93268f43832b4033eef0ba335ba65` |
| Repeated bytes | `0101010101010101010101010101010101010101010101010101010101010101` | `0202020202020202020202020202020202020202020202020202020202020202` | `f818afd37a6dc3bc92fb44731011277006db4efa6e9023cd7468c02335d22a4d` | `bfa0acaa0093227a3db8129dae0c29d3170e71da62fb33fb359a868cb9d62dca` |
| Sequential/complement | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` | `fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0` | `cbd3aabe6d5a9125f0e086ced756cff43bcf46c307d73ec8c6bc5382c5640689` | `4c558a2315f7203bbbc905f09273a1a79c46cc8a6b8c8c8ded5b53d4d1e60e4b` |
| All `ff` | `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | `8667e718294e9e0df1d30600ba3eeb201f764aad2dad72748643e4a285e1d1f7` | `17023684a3df36c918953947ec42fcaa4d35050fb44c29597fb0920126565b37` |

## Security scope

This is not an EC stealth-address scheme and is not wire-compatible with
EIP-5564. The contract does not perform ECDH, validate curve points, or derive
a stealth private key. The vectors only guarantee interoperability with this
documented SHA-256 proof-of-concept derivation.