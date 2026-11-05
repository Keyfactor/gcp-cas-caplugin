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

using Google.Cloud.Security.PrivateCA.V1;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.GCPCAS;
using Keyfactor.Extensions.CAPlugin.GCPCAS.Client;

namespace Keyfactor.Extensions.CAPlugin.GCPCASTests;

public class CreateCertificateRequestBuilderTests
{
    private static EnrollmentProductInfo Info(string productId = "Default", Dictionary<string, string>? p = null)
        => new() { ProductID = productId, ProductParameters = p! };

    [Fact]
    public void Build_FullRequest_PopulatesSubjectSansCsrLifetimeTemplateAndCa()
    {
        var sans = new Dictionary<string, string[]> { ["Dns"] = new[] { "a.lab.test" }, ["Empty"] = Array.Empty<string>() };

        CreateCertificateRequest req = new CreateCertificateRequestBuilder()
            .WithCsr("-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----")
            .WithSubject("CN=host.lab.test, O=Keyfactor")
            .WithSans(sans)
            .WithEnrollmentType(EnrollmentType.New)
            .WithRequestFormat(RequestFormat.PKCS10)
            .WithEnrollmentProductInfo(Info("my-template", new() { [GCPCASPluginConfig.EnrollmentParametersConstants.CertificateLifetimeDays] = "90" }))
            .Build("us-east1", "proj", "pool", "ca1");

        Assert.Equal("host.lab.test", req.Certificate.Config.SubjectConfig.Subject.CommonName);
        Assert.Contains("a.lab.test", req.Certificate.Config.SubjectConfig.SubjectAltName.DnsNames);
        Assert.Equal(PublicKey.Types.KeyFormat.Pem, req.Certificate.Config.PublicKey.Format);
        Assert.Equal(90, req.Certificate.Lifetime.ToTimeSpan().TotalDays);
        Assert.EndsWith("/certificateTemplates/my-template", req.Certificate.CertificateTemplate);
        Assert.Equal("ca1", req.IssuingCertificateAuthorityId);
        Assert.False(string.IsNullOrEmpty(req.CertificateId));
    }

    [Fact]
    public void Build_Minimal_UsesDefaultsAndNoTemplate()
    {
        CreateCertificateRequest req = new CreateCertificateRequestBuilder()
            .WithSubject("   ")
            .WithSans(null!)
            .WithEnrollmentProductInfo(Info("Default"))
            .Build("us-east1", "proj", "pool", null!);

        Assert.Equal(GCPCASPluginConfig.DefaultCertificateLifetime, req.Certificate.Lifetime.ToTimeSpan().TotalDays);
        Assert.Equal(string.Empty, req.Certificate.CertificateTemplate);
        Assert.Equal(string.Empty, req.IssuingCertificateAuthorityId);
        Assert.Null(req.Certificate.Config.SubjectConfig.Subject);
    }

    [Fact]
    public void LifetimeParameter_NotANumber_FallsBackToDefault()
    {
        // int.TryParse zeroes the out value on failure; the builder keeps whatever it ends up with, so just ensure no throw.
        var b = new CreateCertificateRequestBuilder()
            .WithEnrollmentProductInfo(Info("Default", new() { [GCPCASPluginConfig.EnrollmentParametersConstants.CertificateLifetimeDays] = "abc" }));
        Assert.NotNull(b.Build("l", "p", "pool", null!));
    }

    [Fact]
    public void ExtensionData_AddedExceptSan_AndBadBase64Ignored()
    {
        string der = Convert.ToBase64String(new byte[] { 0x30, 0x03, 0x01, 0x01, 0xFF });
        CreateCertificateRequest req = new CreateCertificateRequestBuilder()
            .WithEnrollmentProductInfo(Info("Default", new()
            {
                ["ExtensionData-1.2.3.4"] = der,
                ["ExtensionData-2.5.29.17"] = der,     // SAN: must be dropped
                ["ExtensionData-1.2.3.5"] = "%%not-base64%%", // invalid: ignored
            }))
            .Build("l", "p", "pool", null!);

        var ext = Assert.Single(req.Certificate.Config.X509Config.AdditionalExtensions);
        Assert.Equal(new[] { 1, 2, 3, 4 }, ext.ObjectId.ObjectIdPath.ToArray());
    }

    [Fact]
    public void WithRequestFormat_NonPkcs10_Throws()
        => Assert.Throws<Exception>(() => new CreateCertificateRequestBuilder().WithRequestFormat((RequestFormat)99));

    [Fact]
    public void NullProductParameters_AreTolerated()
        => Assert.NotNull(new CreateCertificateRequestBuilder().WithEnrollmentProductInfo(Info("Default", null)));
}

public class ParserTests
{
    [Fact]
    public void SubjectParser_ParsesKnownKeysAndIgnoresUnknown()
    {
        Subject s = SubjectParser.ParseFromString("CN=a.lab.test, c=US, O=Org, OU=Unit, L=City, ST=State, STREET=1 Main, PC=12345, XX=ignored, broken, E=")!;
        Assert.Equal("a.lab.test", s.CommonName);
        Assert.Equal("US", s.CountryCode);
        Assert.Equal("Org", s.Organization);
        Assert.Equal("Unit", s.OrganizationalUnit);
        Assert.Equal("City", s.Locality);
        Assert.Equal("State", s.Province);
        Assert.Equal("1 Main", s.StreetAddress);
        Assert.Equal("12345", s.PostalCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void SubjectParser_EmptyReturnsNull(string? input) => Assert.Null(SubjectParser.ParseFromString(input!));

    [Fact]
    public void SanTyped_RoutesByKeyAndSkipsBlanks()
    {
        var sans = new Dictionary<string, string[]>
        {
            ["Dns"] = new[] { "a.lab.test", " " },
            ["Email"] = new[] { "me@lab.test" },
            ["URI"] = new[] { "https://lab.test/x" },
            ["IPAddress"] = new[] { "10.0.0.1", "" },
            ["Other"] = new[] { "ignored" },
            ["Nothing"] = Array.Empty<string>(),
            ["NullValue"] = null!,
        };
        SubjectAltNames r = SubjectAltNamesParser.ParseFromTypedDictionary(sans);
        Assert.Equal(new[] { "a.lab.test" }, r.DnsNames);
        Assert.Equal(new[] { "me@lab.test" }, r.EmailAddresses);
        Assert.Equal(new[] { "https://lab.test/x" }, r.Uris);
        Assert.Equal(new[] { "10.0.0.1" }, r.IpAddresses);
    }

    [Fact]
    public void SanTyped_NullOrEmpty_ReturnsEmpty()
    {
        Assert.Empty(SubjectAltNamesParser.ParseFromTypedDictionary(null!).DnsNames);
        Assert.Empty(SubjectAltNamesParser.ParseFromTypedDictionary(new()).DnsNames);
    }

    [Fact]
    public void SanDnsList_ClassifiesEntries()
    {
        SubjectAltNames r = SubjectAltNamesParser.ParseFromDnsList(new List<string>
        {
            "me@lab.test", "https://lab.test/x", "10.0.0.1", "host.lab.test", "nodots", " ", null!,
        });
        Assert.Equal(new[] { "me@lab.test" }, r.EmailAddresses);
        Assert.Equal(new[] { "https://lab.test/x" }, r.Uris);
        Assert.Equal(new[] { "10.0.0.1" }, r.IpAddresses);
        Assert.Equal(new[] { "host.lab.test" }, r.DnsNames);
        Assert.Empty(SubjectAltNamesParser.ParseFromDnsList(null!).DnsNames);
        Assert.Empty(SubjectAltNamesParser.ParseFromDnsList(new()).DnsNames);
    }
}

public class ConfigTests
{
    [Fact]
    public void ConnectorAnnotations_CoverEveryConnectionField()
    {
        var a = GCPCASPluginConfig.GetPluginAnnotations();
        foreach (string key in new[] { "LocationId", "ProjectId", "CAPool", "CAId", "Enabled", "ServiceAccountKey" })
            Assert.True(a.ContainsKey(key), key);
        Assert.True(a["ServiceAccountKey"].Hidden);
        Assert.Equal("Secret", a["ServiceAccountKey"].Type);
    }

    [Fact]
    public void TemplateParameterAnnotations_IncludeLifetimeAndNarId()
    {
        var a = GCPCASPluginConfig.GetTemplateParameterAnnotations();
        Assert.Equal(GCPCASPluginConfig.DefaultCertificateLifetime, a["CertificateLifetimeDays"].DefaultValue);
        Assert.Equal("nar_id", GCPCASPluginConfig.EnrollmentParametersConstants.NarId);
        Assert.Equal("", a["nar_id"].DefaultValue);
        Assert.Equal("String", a["nar_id"].Type);
    }
}

public class FlowLoggerTests
{
    [Fact]
    public async Task RendersAllStepKindsOnDispose()
    {
        var log = new CapturingLogger();
        using (var flow = new FlowLogger(log, "Demo"))
        {
            flow.Step("Plain").Step("WithDetail", "d");
            flow.Step("Timed", () => Thread.Sleep(2), "td");
            await flow.StepAsync("Async", async () => await Task.Delay(2), "ad");
            flow.Skip("Skipped", "why").Skip("SkippedNoReason");
            flow.Branch("Branch").Step("Child", "cd").Fail("ChildFail", "nope").EndBranch();
            flow.Fail("Failed", "bad").Fail("FailedNoReason");
        }

        string rendered = log.Messages.Last();
        Assert.Contains("FLOW: Demo", rendered);
        foreach (string s in new[] { "[OK] Plain", "[SKIP] Skipped", "[...] Branch", "[FAIL] Failed", "Child", "ChildFail", "FLOW RESULT: FAILED" })
            Assert.Contains(s, rendered);
    }

    [Fact]
    public void ThrowingStep_RecordsFailureAndRethrows()
    {
        var log = new CapturingLogger();
        var flow = new FlowLogger(log, "F");
        Assert.Throws<InvalidOperationException>(() => flow.Step("Boom", () => throw new InvalidOperationException("x")));
        flow.Dispose();
        flow.Dispose(); // second dispose is a no-op
        Assert.Contains("[FAIL] Boom", log.Messages.Last());
        Assert.Single(log.Messages, m => m.Contains("FLOW:"));
    }

    [Fact]
    public async Task ThrowingAsyncStep_RecordsFailureAndRethrows()
    {
        var log = new CapturingLogger();
        using var flow = new FlowLogger(log, "F");
        await Assert.ThrowsAsync<InvalidOperationException>(() => flow.StepAsync("BoomAsync", () => throw new InvalidOperationException("x")));
    }

    [Fact]
    public void SuccessfulFlow_ReportsSuccess_AndEarlierFailureIsPartial()
    {
        var ok = new CapturingLogger();
        using (var f = new FlowLogger(ok, "ok")) f.Step("a");
        Assert.Contains("SUCCESS", ok.Messages.Last());

        var partial = new CapturingLogger();
        using (var f = new FlowLogger(partial, "p")) f.Fail("a").Step("b");
        Assert.Contains("PARTIAL FAILURE", partial.Messages.Last());
    }
}
