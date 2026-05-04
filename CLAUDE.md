# lacre — agent-facing canonical context

> **Read [`README.md`](./README.md) and
> [`cartorio/docs/COMPLIANCE-PROOF.md`](https://github.com/pleme-io/cartorio/blob/main/docs/COMPLIANCE-PROOF.md)**
> first.

## What lacre is

The OCI Distribution Spec gate. Reverse proxy that intercepts manifest
PUTs, hashes the body, asks cartorio if the digest is admitted +
Active + matches the org, and forwards iff yes. Non-compliant
artifacts are rejected at the wire — this is the runtime
enforcement layer that mirrors tabeliao's CI-time `--pack` gate.

## Architectural invariants — DO NOT BREAK

1. **Content-addressed gating.** Lacre hashes the actual manifest
   body bytes; it never trusts the URL reference. The
   `body_digest_not_url_reference_is_what_gates` test is the proof
   property — DO NOT cache the digest from the URL or accept it
   from headers.

2. **PUT-only gate, never GET/HEAD.** Manifest pulls (GET, HEAD) and
   blob ops (any verb) MUST pass through unchanged. Gating a GET
   would break image pulls and slow every consumer; gating a blob
   PUT would block the upload sequence before the manifest binds.

3. **No caching of cartorio responses.** Every manifest PUT consults
   cartorio fresh. Revocations must propagate at the next push.

4. **Fail closed on cartorio errors.** If cartorio is unreachable,
   lacre returns 503 — never silent-pass. The test
   `cartorio_unreachable_returns_503_not_silent_pass` enforces this.

5. **Org pinning is per-instance.** A lacre deployment serves
   exactly one org. Admitting another org's artifacts requires a
   separate lacre instance pointed at a separate registry namespace.

## The five rejection paths (each tested)

| Cartorio response | Lacre returns |
|---|---|
| 200 + `status: Active` + matching org | 201/202 (forwarded) |
| 200 + `status: Revoked` | 403 "revoked" |
| 200 + `status: Quarantined` | 403 "quarantined" |
| 200 + wrong org | 403 "registered under <org>" |
| 404 (no record at this digest) | 403 "no compliant listing" |
| Network error / timeout | 503 "cartorio unavailable" |

## Helm gating, free

Helm 3.7+ pushes charts via OCI Distribution Spec. Lacre gates them
identically — the manifest envelope is the same; what's inside
(`config.mediaType`) is helm-specific but lacre doesn't care. The
helm-content pack runs in tabeliao's pre-publish step; lacre just
ensures the digest cartorio approved is the digest pushed.

## Configuration surface

```bash
lacre \
  --listen        0.0.0.0:8083 \
  --cartorio-url  http://cartorio:8082 \
  --backend-url   http://zot.zot.svc:5000 \
  --org           pleme-io
```

Or env: `LACRE_LISTEN`, `LACRE_CARTORIO_URL`, `LACRE_BACKEND_URL`,
`LACRE_ORG`. Adding flags is back-compat additive.

## Testing rules

- **Every new gating path** gets:
  - Live integration test in `tests/cartorio_integration.rs` with
    real cartorio over TCP.
  - Negative assertion: if rejected, the backend MUST NOT have seen
    the manifest PUT.

- **Every new HTTP route** gets a passthrough or gating decision
  documented in the test name.

## Companion repos

The dep is `cartorio = { path = "../cartorio" }` — lacre tests
spin up a real cartorio instance over TCP. Bumping cartorio means
`cargo update` + re-run lacre tests. Lacre has no dep on tabeliao
or provas; the gate is a function of cartorio's stored state alone.
