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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Api.Gax;
using Google.Api.Gax.Grpc;
using Google.Cloud.Security.PrivateCA.V1;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.GCPCASTests;

internal static class TestData
{
    public const string Project = "test-project";
    public const string Location = "europe-west3";
    public const string Pool = "test-pool";

    public static string SelfSignedPem(string commonName = "test.lab.test")
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return cert.ExportCertificatePem();
    }

    public static Certificate Cert(string id, string? pem = null, string? template = null, string? issuerCa = null)
    {
        var cert = new Certificate
        {
            CertificateName = new CertificateName(Project, Location, Pool, id),
            PemCertificate = pem ?? SelfSignedPem(id + ".lab.test"),
        };
        if (template != null)
            cert.CertificateTemplate = new CertificateTemplateName(Project, Location, template).ToString();
        if (issuerCa != null)
            cert.IssuerCertificateAuthority = new CertificateAuthorityName(Project, Location, Pool, issuerCa).ToString();
        return cert;
    }
}

/// <summary>Logger that records rendered messages so tests can assert on log output.</summary>
internal sealed class CapturingLogger : ILogger
{
    public List<string> Messages { get; } = new();
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => Messages.Add(formatter(state, exception));
}

/// <summary>Configurable fake of the Google client; each RPC can be replaced by a delegate.</summary>
internal sealed class ConfigurableFakeCasClient : CertificateAuthorityServiceClient
{
    public Func<GetCaPoolRequest, Task<CaPool>>? OnGetCaPool { get; set; }
    public Func<GetCertificateAuthorityRequest, Task<CertificateAuthority>>? OnGetCa { get; set; }
    public Func<GetCertificateRequest, Task<Certificate>>? OnGetCertificate { get; set; }
    public Func<CreateCertificateRequest, Task<Certificate>>? OnCreateCertificate { get; set; }
    public Func<RevokeCertificateRequest, Task<Certificate>>? OnRevoke { get; set; }
    public Func<ListCertificatesRequest, PagedAsyncEnumerable<ListCertificatesResponse, Certificate>>? OnListCertificates { get; set; }
    public Func<ListCertificateTemplatesRequest, PagedEnumerable<ListCertificateTemplatesResponse, CertificateTemplate>>? OnListTemplates { get; set; }

    public List<ListCertificatesRequest> ListRequests { get; } = new();

    public override Task<CaPool> GetCaPoolAsync(GetCaPoolRequest request, CallSettings? callSettings = null)
        => OnGetCaPool!(request);

    public override Task<CertificateAuthority> GetCertificateAuthorityAsync(GetCertificateAuthorityRequest request, CallSettings? callSettings = null)
        => OnGetCa!(request);

    public override Task<Certificate> GetCertificateAsync(GetCertificateRequest request, CallSettings? callSettings = null)
        => OnGetCertificate!(request);

    public override Task<Certificate> CreateCertificateAsync(CreateCertificateRequest request, CallSettings? callSettings = null)
        => OnCreateCertificate!(request);

    public override Task<Certificate> RevokeCertificateAsync(RevokeCertificateRequest request, CallSettings? callSettings = null)
        => OnRevoke!(request);

    public override PagedAsyncEnumerable<ListCertificatesResponse, Certificate> ListCertificatesAsync(ListCertificatesRequest request, CallSettings? callSettings = null)
    {
        ListRequests.Add(request);
        return OnListCertificates!(request);
    }

    public override PagedEnumerable<ListCertificateTemplatesResponse, CertificateTemplate> ListCertificateTemplates(ListCertificateTemplatesRequest request, CallSettings? callSettings = null)
        => OnListTemplates!(request);
}

/// <summary>Async pages where each page is either a response or a failure to throw while streaming.</summary>
internal sealed class FakePages : PagedAsyncEnumerable<ListCertificatesResponse, Certificate>
{
    private readonly IReadOnlyList<object> _items; // ListCertificatesResponse | Exception
    public FakePages(params object[] items) => _items = items;

    public static ListCertificatesResponse Page(params Certificate[] certs)
    {
        var r = new ListCertificatesResponse();
        r.Certificates.AddRange(certs);
        return r;
    }

#pragma warning disable CS1998
    public override async IAsyncEnumerable<ListCertificatesResponse> AsRawResponses()
    {
        foreach (object item in _items)
        {
            if (item is Exception ex) throw ex;
            yield return (ListCertificatesResponse)item;
        }
    }

    public override async IAsyncEnumerator<Certificate> GetAsyncEnumerator(CancellationToken cancellationToken = default)
    {
        foreach (object item in _items)
        {
            if (item is Exception ex) throw ex;
            foreach (Certificate c in ((ListCertificatesResponse)item).Certificates)
                yield return c;
        }
    }
#pragma warning restore CS1998
}

internal sealed class FakeTemplatePages : PagedEnumerable<ListCertificateTemplatesResponse, CertificateTemplate>
{
    private readonly IReadOnlyList<ListCertificateTemplatesResponse> _pages;
    public FakeTemplatePages(params ListCertificateTemplatesResponse[] pages) => _pages = pages;

    public static ListCertificateTemplatesResponse Page(params string[] templateIds)
    {
        var r = new ListCertificateTemplatesResponse();
        foreach (string id in templateIds)
            r.CertificateTemplates.Add(new CertificateTemplate
            {
                CertificateTemplateName = new CertificateTemplateName(TestData.Project, TestData.Location, id)
            });
        return r;
    }

    public override IEnumerable<ListCertificateTemplatesResponse> AsRawResponses() => _pages;

    public override IEnumerator<CertificateTemplate> GetEnumerator()
        => _pages.SelectMany(p => p.CertificateTemplates).GetEnumerator();
}
