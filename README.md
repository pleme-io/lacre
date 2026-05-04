# lacre

Compliant OCI registry seal. Reverse proxy that gates `PUT
/v2/{name}/manifests/{ref}` through cartorio. Sits in front of any
backing registry that speaks the OCI Distribution Spec — Zot, ECR,
GHCR mirror, distribution.

## What lacre does

```
docker push 127.0.0.1:8083/myorg/myimage:v1
   ↓
lacre PUT /v2/myorg/myimage/manifests/v1
   ↓ sha256(manifest body) = sha256:abc…
   ↓ GET cartorio:8082/api/v1/artifacts/by-digest/sha256:abc…
   ↓
   ↓ 200 + status=Active + org match  →  forward to backend
   ↓ 404                              →  403 "no compliant listing"
   ↓ status=Revoked|Quarantined|…    →  403 "<reason>"
   ↓ wrong org                        →  403 "registered under X"
```

The gate is **content-addressed**, not URL-addressed: lacre hashes the
actual manifest body and asks cartorio about that digest, never trusting
the URL reference. Tag-spoofing attacks where a client claims a
known-good digest in the URL but ships evil bytes are blocked by
construction.

## What lacre does NOT do

- Does **not** gate `GET`, `HEAD`, blob ops, `/v2/`, `/_catalog`, tag
  listings — those pass through unchanged.
- Does **not** cache cartorio responses. Every manifest PUT consults
  cartorio fresh, so revocations propagate at next push.
- Does **not** speak helm, npm, or any non-OCI distribution. Helm
  charts pushed via OCI Distribution work for free (same wire format).

## Relationship to the other components

| Component | Role |
|---|---|
| [`cartorio`](https://github.com/pleme-io/cartorio) | The ledger. Source of truth for "is this digest registered + Active + under what pack." Lacre's only data source. |
| [`provas`](https://github.com/pleme-io/provas) | Defines the compliance packs whose pack_hashes get baked into cartorio's records. Lacre doesn't run packs — it consumes their results via cartorio. |
| [`tabeliao`](https://github.com/pleme-io/tabeliao) | Publishes the artifact to cartorio + pushes through lacre. Lacre is the back half of the publish pipeline. |

## Compliance proof — see canonical doc

For the broader concept (transferable, mechanically-verifiable
compliance receipts that cartorio stores and lacre enforces at the
gate), read
[`cartorio/docs/COMPLIANCE-PROOF.md`](https://github.com/pleme-io/cartorio/blob/main/docs/COMPLIANCE-PROOF.md).

## Operate

```bash
# minimal three-arg invocation
lacre \
  --listen        0.0.0.0:8083 \
  --cartorio-url  http://cartorio:8082 \
  --backend-url   http://zot.zot.svc:5000 \
  --org           pleme-io
```

Or via env: `LACRE_LISTEN`, `LACRE_CARTORIO_URL`, `LACRE_BACKEND_URL`,
`LACRE_ORG`.

## Test corpus (39 tests, 0 clippy warnings)

- 15 lib tests: digest determinism, decision-logic per status,
  multi-segment path parsing.
- 11 router tests with fakes: gate paths, passthrough paths, oversized
  manifest, healthz.
- 13 live integration tests with a real cartorio binary spun up over
  TCP: compliant push → forward; revoked/quarantined/wrong-org → 403;
  cartorio unreachable → 503 (fail closed); body-digest gating
  (URL-spoof blocked); concurrent pushes; lifecycle flips.

## Status

Reference impl. v0.1.x.
