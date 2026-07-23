# GCP CAS CA Plugin — Test Suite Reference

## Overview

The `GCPCAS.Tests` project contains the tests for the GCP CAS AnyCA Gateway REST plugin. It holds
two kinds of tests:

- **Pure unit tests** — no external services. They exercise the sync subject guard and the sync
  download loop in-process, using self-signed certificates generated at runtime and a fake
  `CertificateAuthorityServiceClient`. These run under a plain `dotnet test`.
- **Integration tests** — gated by `[IntegrationTestingFact]`. They hit a **real** GCP CAS project
  using Application Default Credentials and auto-skip unless the required environment variables are
  set (see below).

| Class | Layer under test | Isolation technique |
|---|---|---|
| `SubjectGuardTests` | `GCPCASClient.SubjectSurvivesGatewayRoundTrip` subject parse guard | Pure unit (in-memory strings + self-signed certs) |
| `SyncSkipContinuationTests` | `GCPCASClient.DownloadAllIssuedCertificates` skip-and-continue loop | Fake `CertificateAuthorityServiceClient` (no GCP) |
| `ClientTests` | `GCPCASClient` end-to-end against GCP CAS | `[IntegrationTestingFact]` (real GCP) |

If a test fails in `SubjectGuardTests`, the bug is in the subject-parse decision. If it fails in
`SyncSkipContinuationTests`, the bug is in how the download loop handles a bad certificate. If it
fails in `ClientTests`, the bug is in the real GCP interaction (or the environment).

---

## Running the Tests

**Prerequisites:**
- .NET 8 SDK (test project targets `net8.0`; the plugin targets net6.0/net8.0/net10.0)
- NuGet packages restored (`dotnet restore`)
- No external services required for the unit tests

**Run all tests** (integration tests skip automatically without credentials):
```bash
dotnet test GCPCAS.sln
```

**Run only the unit tests / a single class:**
```bash
dotnet test --filter "FullyQualifiedName~SubjectGuardTests"
dotnet test --filter "FullyQualifiedName~SyncSkipContinuationTests"
```

**Run a specific test by name:**
```bash
dotnet test --filter "DisplayName~DownloadAllIssuedCertificates_SkipsBadSubject_AndContinues"
```

The unit tests reach the plugin's `internal` members via `InternalsVisibleTo("GCPCAS.Tests")`
declared in `GCPCAS/GCPCAS.csproj`.

---

## Integration test gating

`ClientTests` are decorated with `[IntegrationTestingFact]` (`IntegrationTestingFact.cs`), which
skips the test unless **all** of these environment variables are set:

- `GCP_PROJECT_ID`
- `GCP_LOCATION_ID`
- `GCP_CAS_CAPOOL`
- `GCP_CAS_CAID`

When set, the tests authenticate with Application Default Credentials and operate against that real
Enterprise-tier CA pool. With no variables set, `dotnet test` passes trivially (everything skips).

---

## SubjectGuardTests

Regression tests for the sync subject guard (issue #30). GCP CAS will issue certificates whose
subject is not valid RFC 4514 (e.g. a CN ending in a dangling `\`). The AnyCA Gateway re-parses the
subject with BouncyCastle's `X509Name` on its `/v2/certificate/search` response; on such a subject
that parse throws `badly formatted directory string`, the response 500s, and Command's Full Scan
aborts. The 1.3.3 guard shipped against the lenient BouncyCastle 2.0.0, whose parse never threw on
these shapes, so they were admitted. The plugin now pins the same BouncyCastle build the gateway
uses, so `SubjectSurvivesGatewayRoundTrip` is a faithful reproduction of the gateway's accept/reject
decision — it rejects only what the gateway rejects and accepts everything it accepts.

Subject strings are in .NET's `X509Certificate2.Subject` form.

### SubjectSurvivesGatewayRoundTrip_ClassifiesSubjects (`[Theory]`)

| Subject | Expected | Why |
|---|---|---|
| `CN=baseline-app-01.lab.test` | accepted | well-formed |
| `CN=wellformed.lab.test` | accepted | well-formed |
| `CN=host.lab.test, OU=PKI, O=Keyfactor Labs, C=US` | accepted | well-formed multi-RDN |
| `CN=shape1.lab.test\` | **rejected** | CN ends in a dangling backslash — the regression shape |
| `CN=host.lab.test\, OU=PKI` | **rejected** | dangling backslash right before an RDN separator |
| `CN=shape2.lab.test\\` | accepted | two backslashes are a valid escaped pair |
| `CN=shape3.lab.test\\\\, OU=PKI, O=Keyfactor Labs` | accepted | four backslashes are valid escaped pairs |
| `CN=a\bc` | accepted | `\bc` is a valid RFC 4514 hex escape — **not** a false positive |
| `CN=a\,b` | accepted | escaped comma is a valid escaped special — **not** a false positive |
| `CN=a,b` | **rejected** | bare unescaped separator yields a malformed second RDN |

Rejected cases assert a non-empty `failureReason`; accepted cases assert `failureReason == null`.
The `CN=shape1.lab.test\` → rejected case also serves as a **BouncyCastle-version guard**: if a
future transitive change reverted to a lenient BouncyCastle, this case would flip and fail.

### RealCertificate_WithTrailingBackslashCn_IsRejected (`[Fact]`)

Builds a real self-signed certificate whose CN ends in a literal backslash byte (the exact shape
GCP CAS issues), then feeds its `.Subject` through the guard. Asserts .NET renders the backslash
verbatim (single, not doubled) and that the guard rejects it with a reason.

### RealCertificate_WithWellFormedCn_IsAccepted (`[Fact]`)

Same, with a well-formed CN — asserts the guard accepts it and `failureReason` is null.

### Helper

- `SelfSignedPemWithCommonName(cn)` — builds an in-memory self-signed RSA-2048 certificate with the
  given CN (via `X500DistinguishedNameBuilder`, so any raw byte including a backslash is accepted)
  and returns its PEM.

---

## SyncSkipContinuationTests

Regression test for the sync loop's skip-and-continue behaviour (issue #30). It verifies the
user-facing requirement directly: the download reads the certificates **before** an unparseable one,
logs and **skips** the bad one, and keeps reading the certificates **after** it, so a full sync
completes rather than aborting. A fake `CertificateAuthorityServiceClient` streams hand-built pages,
so no GCP access is required. The `GCPCASClient` is created through an `internal` test-only
constructor that injects the fake client and starts enabled.

### DownloadAllIssuedCertificates_SkipsBadSubject_AndContinues (`[Fact]`)

| Setup | Assertion |
|---|---|
| Page 1 = `good-1`, `good-2`, `bad-1` (CN `broken.lab.test\`); Page 2 = `good-3`, `good-4` | Returns `4`; buffer count `4`; buffered `CARequestID`s are exactly `good-1..good-4` in order; `bad-1` is absent; `buffer.IsAddingCompleted == true` (the `finally`'s `CompleteAdding()` ran) |

This proves the bad certificate is skipped mid-stream (not at the start or end), the surrounding
good certificates on both pages are still buffered, paging is honoured, and the sync terminates
cleanly.

### Helpers and fakes

- `FakeCert(certId, commonName)` — a `Certificate` proto with a resource `CertificateName` and a
  real self-signed PEM carrying the given CN.
- `Page(certs…)` — wraps certificates in a `ListCertificatesResponse`.
- `SelfSignedPem(cn)` — same generator as `SubjectGuardTests`.
- `FakeCasClient` — subclasses `CertificateAuthorityServiceClient` and overrides
  `ListCertificatesAsync` to return the supplied pages.
- `FakePagedAsyncEnumerable` — subclasses `PagedAsyncEnumerable<ListCertificatesResponse, Certificate>`
  and streams the in-memory pages via `AsRawResponses()` (the method the loop consumes).

---

## ClientTests (integration)

End-to-end tests against a real GCP CAS project. All are `[IntegrationTestingFact]` and skip without
the four `GCP_*` environment variables.

| Test | What it exercises |
|---|---|
| `GCPCASClient_Integration_GetTemplates_ReturnSuccess` | Lists certificate templates (product IDs) from the pool |
| `GCPCASClient_Integration_DownloadAllCertificates_ReturnSuccess` | Full download of issued certificates into a `BlockingCollection` |
| `GCPCASClient_Integration_DownloadAllCertificatesAfter_ReturnSuccess` | Incremental download with an `issuedAfter` filter |
| `GCPCASClient_Integration_EnrollGetRevoke_ReturnSuccess` | Enroll a certificate, fetch it, then revoke it |

---

## Adding New Tests

- **`SubjectGuardTests`** — when changing which subjects are considered parseable/skippable. Prefer
  a `[Theory]` `[InlineData]` row over a new method. Remember the assertions encode the pinned
  BouncyCastle's behaviour; if you bump BouncyCastle, re-verify the expected values.
- **`SyncSkipContinuationTests`** — when changing the download loop's filtering, counting, paging, or
  buffer-completion behaviour. Build pages with `Page(...)` and certificates with `FakeCert(...)`;
  do not call `buffer.CompleteAdding()` yourself (the loop does it in a `finally`).
- **`ClientTests`** — when adding real GCP behaviour that only a live project can validate. Gate it
  with `[IntegrationTestingFact]` so it skips cleanly in CI without credentials.
