# Connector SDK

A *connector* deploys a renewed credential to a target through a
capability-gated `Sandbox` — one of the 24 shipped connectors in this package
(NGINX, Apache, HAProxy, F5, ACM, Key Vault, and more), outbox-delivered (AN-6)
and idempotent on `dep.Fingerprint`.

See [`docs/guides/connector-authoring.md`](../../docs/guides/connector-authoring.md)
for the interface, capability model, delivery, and conformance-testing guide.
