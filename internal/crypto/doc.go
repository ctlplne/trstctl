// Package crypto is the AN-3 cryptography boundary: the single package in the
// tree permitted to import the standard library's crypto/* packages.
//
// It defines backend-agnostic interfaces (signing, key generation, and related
// types) behind which the software, HSM, KMS, and post-quantum backends plug
// in. Both X.509 and SSH signing route through this boundary, so adding an
// algorithm or a hardware backend is a single-package change. The architecture
// linter (tools/certctllint) enforces that no crypto/* import appears anywhere
// else.
//
// Implementation begins in sprint S1.1; this file reserves the package.
package crypto
