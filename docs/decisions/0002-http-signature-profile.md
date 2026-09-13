# 0002 — HTTP signature profile

- Status: **Accepted** (retain RFC 9421; implement a closed profile of it)
- Date: 2026-09-12
- Gate: brief §4.7, Milestone 2. Blocks freezing the sync API and writing any network code.
- Related: decision record 0001, constraint 1 (no registered post-quantum algorithm).

## Decision

Authenticate registered-device requests with **RFC 9421 HTTP Message Signatures**, restricted
to a single closed profile that our verifier accepts and everything else rejects. Do not
substitute a bespoke signed-canonical-request scheme.

"Closed profile" is the operative part. RFC 9421 is a toolkit: arbitrary covered-component
sets, optional parameters, multiple concurrent signatures, component parameters such as
`sf`, `bs`, `key`, `req`, and `tr`. We implement and accept exactly one shape. A request
whose `Signature-Input` differs from the profile in any respect is rejected without being
evaluated, rather than verified on its own terms.

## Why not a bespoke scheme

This was reconsidered on the merits rather than inherited from §4.7, because the usual reason
to adopt a standard — an existing library — does not apply here. Per decision record 0001,
no off-the-shelf RFC 9421 implementation supports ML-DSA, so we write the signer and the
verifier either way. Three arguments still decide it for RFC 9421:

**Signature size is not an argument for either side.** An ML-DSA-65 signature is 3309 bytes,
4430 base64 in a header, whichever envelope carries it. That is a property of the algorithm,
not of the message-signature format, and a bespoke scheme would not save a byte. Any framing
of the size problem as a reason to simplify the format is mistaken.

**The specification, not the library, is the reusable part.** The genuinely error-prone work
in request signing is canonicalizing what is signed: derived components, the authority in the
presence of a default port, percent-encoding in the path and query, absent versus empty
query, repeated field values, and the serialization of the signature parameters themselves.
RFC 9421 specifies all of it, with the failure modes already found by people who deployed it.
A bespoke format re-derives that specification and gets it wrong in ways nobody else has
catalogued.

**It is the only way to satisfy §4.7's interoperability requirement at all.** The published
RFC 9421 vectors exercise signature *base construction*, which is algorithm-independent — the
base is built, then signed. So the classical parts of our profile can be checked against
published vectors and cross-checked against an independent implementation, with our own
vectors covering only the ML-DSA step. A bespoke scheme has nothing to interoperate with,
which turns §4.7's exercise into a round trip through our own signer and verifier — the exact
thing §4.7 names as insufficient.

The cost is real and is accepted: a restricted RFC 8941 structured-field
serializer and parser, which we need regardless for `Content-Digest`.

## The profile

One signature per request, label `sshstate`.

**Covered components**, in this order, and no others:

```
"@method" "@authority" "@path" "@query" "content-digest" \
  "sshstate-vault" "sshstate-device" "idempotency-key"
```

`content-digest` is covered if and only if the request has a body; `idempotency-key` if and
only if the request is a mutation. The remaining six are always covered. A verifier computes
the expected component list from the request itself and compares it to `Signature-Input`
before doing any cryptography, so a signer cannot choose to leave a component uncovered.

`@query` is always covered, including when there is no query string, so that adding a query
to a signed request cannot go unnoticed.

**Signature parameters**: `created`, `expires`, `nonce`, `keyid`, `tag="sshstate.request.v1"`.

`alg` is omitted and the algorithm is derived from the key named by `keyid`, as RFC 9421
permits and as decision record 0001 requires. `keyid` is the 128-bit device ID in lowercase
hex; the verifier resolves it through the signed membership chain, never through a bare
device table. `tag` carries the profile identity inside the signed base. Separately, the
ML-DSA context string is `sshstate.request.v1`, so a request signature cannot verify as a
record or membership signature even if an attacker controls the base bytes.

**Freshness**: `expires - created` is at most 300 seconds; clock skew tolerance is 60 seconds
in both directions. `nonce` is 128 random bits, base64url unpadded. The relay stores
`(device, nonce)` until `expires` plus tolerance and rejects a repeat.

**Body binding**: `Content-Digest: sha-256=:…:` (RFC 9530) computed over the raw body bytes
as received, before any parsing. A request with a body and no `Content-Digest` is rejected.

**Retries** reuse the persisted mutation ID and the identical body with a *fresh* nonce,
`created`, `expires` and signature. Idempotency is keyed by mutation ID, not by signature.

**One serialization.** The verifier parses `Signature-Input`, re-serializes it, and rejects
the request if the result differs from what arrived. This is not belt-and-braces: the
signature base is rebuilt from the parsed values rather than copied from the received bytes,
so without the check a `Signature-Input` that parses equivalently but is spelled differently
— a space before the closing parenthesis is enough — would have the signer covering one
string and the verifier checking another. Fixing one spelling is what makes rebuilding
sound, and it removes every parser ambiguity a general RFC 9421 verifier has to reason
about.

## Header size

A 4430-byte `Signature` header is roughly 54% of the 8190-byte single-header limit Apache and
nginx commonly deploy. Measured on the implementation, the header value is **4423 bytes**
(`sshstate=:` + 4412 base64 characters + `:`), which `TestMLDSASignatureHeaderSize` asserts
stays clear of that limit. The policy is explicit rejection, never truncation:

- The relay rejects a `Signature` or `Signature-Input` header above a configured maximum with
  a distinct error code that names the size, so an operator sees a limit rather than a
  signature failure.
- The client checks the size it is about to send and fails locally with the same message,
  rather than emitting a request a proxy will mangle.
- The deployed reverse proxy's limit is a documented setup requirement, verified against the
  actual proxy rather than assumed from these figures.

## What is deliberately not implemented

Rejected rather than unsupported, so the verifier has no branch to attack:

- multiple signatures on one request, and any label other than `sshstate`
- the `alg` parameter, present in any form, including a correct-looking private-use value
- component parameters `sf`, `key`, `bs`, `req`, `tr`
- `@target-uri`, `@scheme`, `@request-target`, `@status`, and any component outside the list
- signatures on responses
- trailers

## Limits

The profile authenticates a request to the relay. It does not make the relay trustworthy: a
compromised relay still holds valid signed requests and can withhold, reorder within the
limits of §4.3, or deny service. Record signatures, not request signatures, are what bind a
writer to content after the request is gone.

Cross-checking against an independent implementation covers base construction and the
classical parts only. No second implementation of this profile exists, so "interoperable" here
means our base construction agrees with other RFC 9421 implementations, not that another
client can talk to our relay.

## Follow-up

Specify the exact wire schema and error codes in `docs/protocol.md` before implementation.
Carry the closed-profile rejection list into the verifier's tests as explicit cases, not as
an absence of support.
