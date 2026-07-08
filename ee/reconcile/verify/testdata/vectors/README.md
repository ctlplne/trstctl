<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# XREC Verifier Vectors

This corpus is the XREC-12 offline verifier profile for claim 20 and dependent
claims 21 and 22. Fixture files publish the observed-state source and expected
verified determination; tests build signed digests and witness evidence through
the signer-boundary artifact helper at runtime so no private signing material is
checked into the repository.

The verifier under test receives only signed digests, signed witness evidence,
public verification keys, and verifier policy. It does not receive authority
clients, stores, ledgers, reducers, or non-diverging records.
