### bs255 - ristretto25519 Schnorr Signatures
#### Yawning Angel (yawning at schwanenlied dot me)

This is a [Schnorr signature][1] scheme largely inspired by [BIP-0340][2],
that uses the [ristretto25519][3] prime-order group.

Design goals:

- Drop-in (ish) replacement for Ed25519.
- Approximately 128-bits of classical security.
- As edge-case free as possible, with specified behavior when unavoidable.
- Mandatory domain separation (an empty domain separator is allowed).
- Determinstic or non-deterministic ("added entropy") nonce generation.
- "Easy" to implement given an existing ristretto25519 and scalar field
  library.

This scheme maintains the ability to do batch verification and to implement
various "hipster crypto" primitives such as DKG and MuSig, however the
specification of such is beyond the scope of this project.

#### Warning

This product can expose you to chemicals which are know to the State of
California to cause cancer.  For more information visit www.P65Warnings.ca.gov.

##### Main differences from BIP-0340

- The ristretto25519 prime-order group is used instead of secp256k1.  This
  simplifies the specification and implementation as "group elements" are
  easier to deal with than elliptic curve points.
- TupleHash(XOF)128 is used instead of an ad-hoc tagged SHA-256 construct.
- When scalars are sampled, instead of reducing 256-bit values mod n,
  512-bit values are reduced mod n instead.  As ristretto25519 shares the
  Ed25519 scalar field, this operation is widely available in existing
  libraries.

##### Notes

- No, the design has not been reviewed, nor has the code been audited.
- The author is aware that the BIP authors have included dire warnings
  regarding adopting the scheme to other groups.
- The choice of using a SHA-3 based primitive under the hood is a
  combination of:
    - Blessed by NIST.
    - TupleHash is the right fit for what needs to be done.
    - SHA-3/SHAKE is seeing increased hardware support and developers
      are incentivised to optimize implementations due to use in other
      primitives.
- [sr25519][5] is fine, but has a lot of extras, lacks (to my knowledge)
  formal specification, and requires a merlin transcript implementation.
- For convenience, Diffie-Hellman is also provided in this reference
  implementation.
- The `bs` stands for "Bitcoin Schnorr inspired".  Rumors to the contrary
  are malicious lies spread by my enemies.
- This design and implementation is brought to you by Suntory Strong
  Zero and Glenlivet.

##### TODO

- Write a specification.
- Add more test cases.

[1]: https://en.wikipedia.org/wiki/Schnorr_signature
[2]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[3]: https://www.rfc-editor.org/rfc/rfc9496
[4]: https://www.rfc-editor.org/rfc/rfc8032
[5]: https://github.com/w3f/schnorrkel
