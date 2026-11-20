// Copyright 2025 Keyfactor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Api.Gax;
using Google.Api.Gax.Grpc;
using Google.Cloud.Security.PrivateCA.V1;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.GCPCAS.Client;

namespace Keyfactor.Extensions.CAPlugin.GCPCASTests;

/// <summary>
/// Regression tests for the sync loop's skip-and-continue behaviour (issue #30): the download must read the
/// certificates before an unparseable one, log-and-skip the bad one, and keep reading the certificates after
/// it, so a full sync completes instead of aborting. Uses a fake <see cref="CertificateAuthorityServiceClient"/>
/// that streams hand-built pages, so no GCP access is needed.
/// </summary>
public class SyncSkipContinuationTests
{
    private const string Project = "test-project";
    private const string Location = "europe-west3";
    private const string Pool = "test-pool";

    [Fact]
    public async Task DownloadAllIssuedCertificates_SkipsBadSubject_AndContinues()
    {
        // Page 1: two good, then the bad (dangling-backslash CN). Page 2: two more good.
        // Expected: 4 good certs buffered, the bad one skipped, sync completes (does not throw).
        var client = new FakeCasClient(new[]
        {
            Page(CnCert("good-1", "app-01.lab.test"), CnCert("good-2", "app-02.lab.test"), CnCert("bad-1", @"broken.lab.test\")),
            Page(CnCert("good-3", "mq-01.lab.test"), CnCert("good-4", "web-01.lab.test")),
        });

        var gcpClient = new GCPCASClient(client, Project, Location, Pool);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        int added = await gcpClient.DownloadAllIssuedCertificates(buffer, CancellationToken.None);

        Assert.Equal(4, added);
        Assert.Equal(4, buffer.Count);
        Assert.True(buffer.IsAddingCompleted); // CompleteAdding() ran in the finally block

        var bufferedIds = buffer.Select(c => c.CARequestID).ToList();
        Assert.Equal(new[] { "good-1", "good-2", "good-3", "good-4" }, bufferedIds);
        Assert.DoesNotContain("bad-1", bufferedIds); // the unparseable cert was skipped, not buffered
    }

    /// <summary>
    /// Reproduces the exact fixture from the escalation (ZD 180923): four well-formed baselines +
    /// wellformed.lab.test + four malformation shapes issued directly on GCP CAS. Under the fixed guard the
    /// only certificate whose subject the AnyCA Gateway cannot parse - shape1 (CN ending in one literal
    /// backslash, the customer's row-301651 shape) - is skipped, while the eight parseable certificates
    /// (including shape2/shape3/shape4, which the gateway accepts) are handed to the buffer and the sync
    /// completes. Before the fix all nine were admitted and Command's Full Scan then aborted on shape1.
    /// </summary>
    [Fact]
    public async Task DownloadAllIssuedCertificates_TicketFixture_SkipsOnlyShape1()
    {
        (string Id, Certificate Cert, bool ExpectBuffered)[] fixture =
        {
            // Four well-formed baselines.
            ("baseline-app-01", CnCert("baseline-app-01", "baseline-app-01.lab.test"), true),
            ("baseline-app-02", CnCert("baseline-app-02", "baseline-app-02.lab.test"), true),
            ("baseline-mq-01",  CnCert("baseline-mq-01",  "baseline-mq-01.lab.test"),  true),
            ("baseline-web-01", CnCert("baseline-web-01", "baseline-web-01.lab.test"), true),
            // Plus one more well-formed.
            ("wellformed", CnCert("wellformed", "wellformed.lab.test"), true),
            // shape1: CN ending in ONE literal backslash -> gateway cannot parse -> the ONLY one skipped.
            ("shape1", CnCert("shape1", "shape1.lab.test\\"), false),
            // shape2: CN ending in TWO literal backslashes (valid escaped pair) -> accepted.
            ("shape2", CnCert("shape2", "shape2.lab.test\\\\"), true),
            // shape3: FOUR literal backslashes at the end of the CN value, ahead of OU/O RDNs -> accepted.
            ("shape3", Cert("shape3", Dn(b =>
            {
                b.AddCommonName("shape3.lab.test\\\\\\\\");
                b.AddOrganizationalUnitName("PKI");
                b.AddOrganizationName("Keyfactor Labs");
            })), true),
            // shape4: nested DN embedded in the outer CN, plus O and two C RDNs -> accepted (.NET quotes the CN).
            ("shape4", Cert("shape4", Dn(b =>
            {
                b.AddCommonName("CN=shape4.lab.test:oracle_wallet");
                b.AddOrganizationName("Keyfactor Labs");
                b.AddCountryOrRegion("US");
                b.AddCountryOrRegion("US");
            })), true),
        };

        // Split across two pages, with shape1 in the middle of page 2 to prove the loop skips it and keeps
        // reading the shapes after it.
        var client = new FakeCasClient(new[]
        {
            Page(fixture.Take(5).Select(f => f.Cert).ToArray()),
            Page(fixture.Skip(5).Select(f => f.Cert).ToArray()),
        });

        // Empty pattern turns the backslash skip off so this test isolates the BouncyCastle parse guard.
        var gcpClient = new GCPCASClient(client, Project, Location, Pool, "", subjectSkipPattern: "");
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        int added = await gcpClient.DownloadAllIssuedCertificates(buffer, CancellationToken.None);

        string[] expectedBuffered = fixture.Where(f => f.ExpectBuffered).Select(f => f.Id).ToArray();
        var bufferedIds = buffer.Select(c => c.CARequestID).ToList();

        Assert.Equal(8, added);                                   // 9 issued, 1 unparseable skipped
        Assert.Equal(expectedBuffered, bufferedIds);              // exactly the 8 parseable, in order
        Assert.DoesNotContain("shape1", bufferedIds);             // the only skipped shape
        Assert.True(buffer.IsAddingCompleted);                    // sync completed cleanly
    }

    [Fact]
    public async Task DownloadAllIssuedCertificates_DefaultPattern_SkipsAnySubjectWithBackslash()
    {
        // shape2/shape3 are validly escaped and parse fine in BouncyCastle, but contain backslashes.
        var client = new FakeCasClient(new[]
        {
            Page(CnCert("good", "ok.lab.test"), CnCert("shape2", "shape2.lab.test\\\\"),
                 CnCert("plain", "x.lab.test"), CnCert("good-2", "ok2.lab.test")),
        });
        var gcpClient = new GCPCASClient(client, Project, Location, Pool); // default pattern
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await gcpClient.DownloadAllIssuedCertificates(buffer, CancellationToken.None);

        Assert.Equal(new[] { "good", "plain", "good-2" }, buffer.Select(c => c.CARequestID).ToArray());
    }

    [Fact]
    public async Task DownloadAllIssuedCertificates_NarrowedPattern_OnlySkipsMatches()
    {
        // Narrowed to "backslash at end of the subject": the validly escaped shape2 mid-DN is now allowed.
        var client = new FakeCasClient(new[]
        {
            Page(Cert("mid", Dn(b => { b.AddCommonName("mid.lab.test\\\\"); b.AddOrganizationName("Org"); })),
                 CnCert("plain", "plain.lab.test")),
        });
        var gcpClient = new GCPCASClient(client, Project, Location, Pool, "", subjectSkipPattern: @"\\$");
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await gcpClient.DownloadAllIssuedCertificates(buffer, CancellationToken.None);

        Assert.Equal(new[] { "mid", "plain" }, buffer.Select(c => c.CARequestID).ToArray());
    }

    [Fact]
    public async Task DownloadCertificate_DefaultPattern_RefusesBackslashSubject()
    {
        var client = new FakeCasClient(Array.Empty<ListCertificatesResponse>()) { Single = CnCert("s2", "s2.lab.test\\\\") };
        var gcpClient = new GCPCASClient(client, Project, Location, Pool);

        await Assert.ThrowsAsync<InvalidOperationException>(() => gcpClient.DownloadCertificate("s2"));
    }

    [Theory]
    [InlineData(null, @"\\")]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData(@"\\$", @"\\$")]
    public void BuildSubjectSkipRegex_NullDefaults_EmptyDisables(string? configured, string? expectedPattern)
    {
        var regex = GCPCASClient.BuildSubjectSkipRegex(configured!);
        Assert.Equal(expectedPattern, regex?.ToString());
    }

    [Fact]
    public void BuildSubjectSkipRegex_InvalidPattern_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => GCPCASClient.BuildSubjectSkipRegex("(unclosed"));
    }

    [Fact]
    public async Task DownloadCertificate_BadSubject_IsRefused_NotReturnedToGateway()
    {
        var client = new FakeCasClient(Array.Empty<ListCertificatesResponse>()) { Single = CnCert("bad-1", @"broken.lab.test\") };
        var gcpClient = new GCPCASClient(client, Project, Location, Pool);

        await Assert.ThrowsAsync<InvalidOperationException>(() => gcpClient.DownloadCertificate("bad-1"));
    }

    [Fact]
    public async Task DownloadCertificate_GoodSubject_IsReturned()
    {
        var client = new FakeCasClient(Array.Empty<ListCertificatesResponse>()) { Single = CnCert("good-1", "app-01.lab.test") };
        var gcpClient = new GCPCASClient(client, Project, Location, Pool);

        AnyCAPluginCertificate result = await gcpClient.DownloadCertificate("good-1");

        Assert.Equal("good-1", result.CARequestID);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a pem")]
    public async Task DownloadCertificate_UnparseablePem_IsStillReturned(string pem)
    {
        var cert = new Certificate { CertificateName = new CertificateName(Project, Location, Pool, "weird"), PemCertificate = pem };
        var client = new FakeCasClient(Array.Empty<ListCertificatesResponse>()) { Single = cert };
        var gcpClient = new GCPCASClient(client, Project, Location, Pool);

        AnyCAPluginCertificate result = await gcpClient.DownloadCertificate("weird");

        Assert.Equal("weird", result.CARequestID);
    }

    private static ListCertificatesResponse Page(params Certificate[] certs)
    {
        var response = new ListCertificatesResponse();
        response.Certificates.AddRange(certs);
        return response;
    }

    private static Certificate CnCert(string certId, string commonName) =>
        Cert(certId, Dn(b => b.AddCommonName(commonName)));

    private static Certificate Cert(string certId, X500DistinguishedName subject)
    {
        return new Certificate
        {
            CertificateName = new CertificateName(Project, Location, Pool, certId),
            PemCertificate = SelfSignedPem(subject),
        };
    }

    private static X500DistinguishedName Dn(Action<X500DistinguishedNameBuilder> configure)
    {
        var builder = new X500DistinguishedNameBuilder();
        configure(builder);
        return builder.Build();
    }

    private static string SelfSignedPem(X500DistinguishedName subject)
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return cert.ExportCertificatePem();
    }

    /// <summary>Fake gRPC client that returns the supplied pages from ListCertificatesAsync.</summary>
    private sealed class FakeCasClient : CertificateAuthorityServiceClient
    {
        private readonly IReadOnlyList<ListCertificatesResponse> _pages;
        public FakeCasClient(IReadOnlyList<ListCertificatesResponse> pages) => _pages = pages;

        /// <summary>The certificate returned by GetCertificateAsync.</summary>
        public Certificate? Single { get; init; }

        public override Task<Certificate> GetCertificateAsync(GetCertificateRequest request, CallSettings callSettings = null!)
            => Task.FromResult(Single!);

        public override PagedAsyncEnumerable<ListCertificatesResponse, Certificate> ListCertificatesAsync(
            ListCertificatesRequest request, CallSettings callSettings = null!)
            => new FakePagedAsyncEnumerable(_pages);
    }

    private sealed class FakePagedAsyncEnumerable : PagedAsyncEnumerable<ListCertificatesResponse, Certificate>
    {
        private readonly IReadOnlyList<ListCertificatesResponse> _pages;
        public FakePagedAsyncEnumerable(IReadOnlyList<ListCertificatesResponse> pages) => _pages = pages;

#pragma warning disable CS1998 // async method without await - the fake streams in-memory pages
        public override async IAsyncEnumerable<ListCertificatesResponse> AsRawResponses()
        {
            foreach (ListCertificatesResponse page in _pages)
            {
                yield return page;
            }
        }

        public override async IAsyncEnumerator<Certificate> GetAsyncEnumerator(
            CancellationToken cancellationToken = default)
        {
            foreach (ListCertificatesResponse page in _pages)
            {
                foreach (Certificate cert in page.Certificates)
                {
                    yield return cert;
                }
            }
        }
#pragma warning restore CS1998
    }
}
