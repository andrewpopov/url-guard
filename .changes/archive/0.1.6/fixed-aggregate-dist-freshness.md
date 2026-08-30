---
kind: fixed
summary: the aggregate verification gate now rejects stale committed build output
---

The package's aggregate verification now checks that the security code shipped
from `dist/` exactly matches the reviewed TypeScript source.
