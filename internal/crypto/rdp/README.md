# Native RDP credential adapter

This optional Linux helper connects **from the gateway to an RDP server**. It is
not an operator-facing RDP server. Session approval, a stock viewer tunnel,
recording and account rotation are separate gateway integrations; this package
alone does not prove them.

Build on Linux with a security-maintained FreeRDP 2.11.x development package and
OpenSSL headers, then install the executable as an administrator-owned file with
no group/other write permission:

```sh
sh internal/crypto/rdp/native/build.sh /usr/local/libexec/trstctl-rdp
```

The tested Debian package is `freerdp2-dev=2.11.7+dfsg1-6~deb12u1` (Apache-2.0).
The adapter is a separate process. Neither the Go agent nor the signer links the
native library. There is no fallback when the helper is absent or cannot lock
its memory. Linux needs sufficient `RLIMIT_MEMLOCK` and, in a container,
`IPC_LOCK`; the process disables core dumps and `PR_SET_DUMPABLE` before reading
its private pipe. Its environment is replaced with a fixed small list.

The private request is magic `TRDP0001`, big-endian port/width/height (two bytes
each), a TLS-only byte, then two-byte-length fields for host, user, domain,
64-character DER certificate SHA-256 pin and password. Passwords are byte-backed
and bounded to 1024 bytes. The Go request is locked and erased after delivery;
the native process locks its address space and erases its owned password and
FreeRDP password settings after connect and on failure. No password is an
argument, environment variable or log field. FreeRDP owns additional transient
authentication allocations; complete third-party heap erasure has not been
measured. The process is killed and reaped on closure, with no reconnection.

Every upstream certificate, including one accepted by a system CA, must match
the configured pin and be currently valid. Windows uses NLA by default. Explicit
`TLSOnly` supports the tested xrdp server. A ready notice means an RDP transport
connected; an xrdp login screen is **not** proof that the account signed in.

The return wire is a four-byte big-endian packet length (including kind), kind
1/2 and two-byte width/height. Kind 1 has no pixels; kind 2 contains full BGRX32
pixels. Width is 320–1280 and height 200–1024. Kind 3 contains only a fixed native
failure category. Input is seven bytes: keyboard kind 3, Unicode kind 4 or pointer
kind 5, followed by flags, code/x and zero/y (two bytes each). There is no
clipboard, drive, printer, audio or arbitrary-channel message. The helper does
not load dynamic channels or reconnect after credential erasure.

Framebuffer content can contain personal or secret text visible on screen.
Regex transcript masking cannot redact arbitrary pixels. A replay integration
must state this limit and apply the existing recording access and retention
controls, rather than calling these frames a masked text recording.

The served lab test requires a real xrdp target on loopback, the native helper,
its public certificate pin and an ephemeral password at `/run/rdp-password`.
Set `TRSTCTL_REQUIRE_RDP_LAB=1`, `TRSTCTL_RDP_HELPER` and `TRSTCTL_RDP_PIN` when
running `TestNativeDesktop*` inside that isolated lab. It requires three rendered
frames, locked memory, no password in process arguments, and an input-driven
xterm task with independent target-file readback. A foreign pin is refused.
Windows/NLA interoperability and the whole gateway journey remain unverified by
this Linux-only proof.
