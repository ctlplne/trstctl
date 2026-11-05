# Desktop wire renderer

`Serve` accepts a connection **already admitted by the gateway's ticket and
mTLS path**, an upstream desktop backend, and an optional recording callback.
It opens no listener and performs no credential exchange. RFB security type
`None` is intentional inside that authenticated tunnel. Never expose it as a
public unauthenticated VNC endpoint.

The native backend is `internal/crypto/rdp`. A stock TigerVNC viewer can render
its RDP pixels and send keyboard/pointer input; the upstream password never
enters RFB. This package alone does not implement control-plane approvals,
vaulted-account routing, encrypted recordings or replay export.

The supported wire is RFB 3.8 with Raw updates. Viewers may select standard
32-bit RGB888 or 16-bit RGB565, in either byte order. Updates are clipped to the
requested rectangle. Desktop dimensions are fixed for the connection; arbitrary
encodings, clipboard messages, remote resize, drives, printers and other
channels are unavailable. BMP Unicode and common navigation/modifier keys are
supported; supplementary-plane Unicode is not yet supported.

The renderer retains one current frame, one queued native frame and one in-flight
native read. A separate
four-entry queue holds viewer update requests. More than 4096 messages in one
second, a full request queue, an invalid rectangle or a clipboard attempt ends
the connection. An initial handshake has 15 seconds and a frame write has 30
seconds, both bounded by session cancellation. A blocked recording callback must
observe its context. Each frame is offered to recording before it can reach the
viewer; storage backpressure propagates to the native pipe and RDP connection.
Closing either side cancels the renderer, closes the other side and waits for
both workers. Pixel buffers are erased when replaced or released.

Pixel recordings can contain personal data and on-screen secrets. Text regex
masking cannot inspect arbitrary pixels. This package does not claim automatic
pixel redaction. RDP disconnection ends interaction; it does not prove that the
target logged the account off or stopped its background applications.

The served lab uses FreeRDP 2.11.7, xrdp 0.9.21.1 and TigerVNC 1.12.0. Set
`TRSTCTL_REQUIRE_RDP_LAB=1`, `TRSTCTL_RDP_HELPER` and the public
`TRSTCTL_RDP_PIN` in the isolated Linux target lab and run
`TestDesktopStockViewerServed`. It drives the stock viewer through Xvfb, executes
an xterm command, independently reads its target file, checks viewer arguments,
environment and home files for the upstream password, and cancels the transport.
This is a transport proof; gateway admission and sealed replay remain separate
journey requirements.
