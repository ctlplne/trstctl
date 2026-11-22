# Demo drift watch

This directory is the demo control plane's only approved local drift root. The
seeded watch names `edge-gateway.crt` here. The file is absent so a manually run
drift scan can report a deleted credential without mounting production paths or
private material into the demo container.
