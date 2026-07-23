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
/// Regression test for the sync loop's skip-and-continue behaviour (issue #30): the download must read the
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
        Certificate good1 = FakeCert("good-1", "app-01.lab.test");
        Certificate good2 = FakeCert("good-2", "app-02.lab.test");
        Certificate bad = FakeCert("bad-1", @"broken.lab.test\");
        Certificate good3 = FakeCert("good-3", "mq-01.lab.test");
        Certificate good4 = FakeCert("good-4", "web-01.lab.test");

        var client = new FakeCasClient(new[]
        {
            Page(good1, good2, bad),
            Page(good3, good4),
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

    private static ListCertificatesResponse Page(params Certificate[] certs)
    {
        var response = new ListCertificatesResponse();
        response.Certificates.AddRange(certs);
        return response;
    }

    private static Certificate FakeCert(string certId, string commonName)
    {
        return new Certificate
        {
            CertificateName = new CertificateName(Project, Location, Pool, certId),
            PemCertificate = SelfSignedPem(commonName),
        };
    }

    private static string SelfSignedPem(string commonName)
    {
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(commonName);
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(builder.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return cert.ExportCertificatePem();
    }

    /// <summary>Fake gRPC client that returns the supplied pages from ListCertificatesAsync.</summary>
    private sealed class FakeCasClient : CertificateAuthorityServiceClient
    {
        private readonly IReadOnlyList<ListCertificatesResponse> _pages;
        public FakeCasClient(IReadOnlyList<ListCertificatesResponse> pages) => _pages = pages;

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
