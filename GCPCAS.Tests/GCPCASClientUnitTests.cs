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
using Google.Cloud.Security.PrivateCA.V1;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.GCPCAS;
using Keyfactor.Extensions.CAPlugin.GCPCAS.Client;
using Keyfactor.PKI.Enums.EJBCA;

namespace Keyfactor.Extensions.CAPlugin.GCPCASTests;

/// <summary>Credential-free unit tests for <see cref="GCPCASClient"/> using a fake Google client.</summary>
public class GCPCASClientUnitTests
{
    private static GCPCASClient NewClient(ConfigurableFakeCasClient fake, string caId = "")
        => new(fake, TestData.Project, TestData.Location, TestData.Pool, caId);

    // ---- enable / disable ----

    [Fact]
    public async Task EnableDisable_TogglesIsEnabled()
    {
        var client = NewClient(new ConfigurableFakeCasClient());
        Assert.True(client.IsEnabled());
        await client.Disable();
        Assert.False(client.IsEnabled());
        await client.Disable(); // idempotent
        await client.Enable();
        Assert.True(client.IsEnabled());
        await client.Enable(); // idempotent
        Assert.Contains(TestData.Pool, client.ToString());
    }

    [Fact]
    public async Task DisabledClient_RejectsOperations()
    {
        var client = NewClient(new ConfigurableFakeCasClient());
        await client.Disable();
        await Assert.ThrowsAsync<Exception>(() => client.ValidateConnection());
        await Assert.ThrowsAsync<Exception>(() => client.DownloadCertificate("x"));
        await Assert.ThrowsAsync<Exception>(() => client.DownloadAllIssuedCertificates(new BlockingCollection<AnyCAPluginCertificate>(), CancellationToken.None));
        Assert.Throws<Exception>(() => client.GetTemplates());
        await Assert.ThrowsAsync<Exception>(() => client.RevokeCertificate("x", RevocationReason.KeyCompromise));
        var result = await client.Enroll(new CreateCertificateRequestBuilder(), CancellationToken.None);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void PublicConstructor_WithServiceAccountKey_Builds()
    {
        // A syntactically valid but fake service account key; credentials are only used lazily on the first call.
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        string pem = rsa.ExportPkcs8PrivateKeyPem();
        string json = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["type"] = "service_account",
            ["project_id"] = "p",
            ["private_key_id"] = "kid",
            ["private_key"] = pem,
            ["client_email"] = "sa@p.iam.gserviceaccount.com",
            ["client_id"] = "1",
            ["token_uri"] = "https://oauth2.googleapis.com/token",
        });
        var client = new GCPCASClient(TestData.Location, TestData.Project, TestData.Pool, "ca", json);
        Assert.False(client.IsEnabled());
    }

    // ---- ValidateConnection ----

    [Fact]
    public async Task ValidateConnection_PoolOnly_Enterprise_Succeeds()
    {
        var fake = new ConfigurableFakeCasClient { OnGetCaPool = _ => Task.FromResult(new CaPool { Tier = CaPool.Types.Tier.Enterprise }) };
        await NewClient(fake).ValidateConnection();
    }

    [Fact]
    public async Task ValidateConnection_PoolOnly_DevOps_Throws()
    {
        var fake = new ConfigurableFakeCasClient { OnGetCaPool = _ => Task.FromResult(new CaPool { Tier = CaPool.Types.Tier.Devops }) };
        var ex = await Assert.ThrowsAsync<Exception>(() => NewClient(fake).ValidateConnection());
        Assert.Contains("Tier", ex.Message);
    }

    private static CertificateAuthority Ca(CertificateAuthority.Types.State state, CaPool.Types.Tier tier) => new()
    {
        CertificateAuthorityName = new CertificateAuthorityName(TestData.Project, TestData.Location, TestData.Pool, "my-ca"),
        State = state,
        Tier = tier,
    };

    [Fact]
    public async Task ValidateConnection_WithCa_EnabledEnterprise_Succeeds()
    {
        var fake = new ConfigurableFakeCasClient { OnGetCa = _ => Task.FromResult(Ca(CertificateAuthority.Types.State.Enabled, CaPool.Types.Tier.Enterprise)) };
        await NewClient(fake, "my-ca").ValidateConnection();
    }

    [Fact]
    public async Task ValidateConnection_WithCa_NotEnabled_Throws()
    {
        var fake = new ConfigurableFakeCasClient { OnGetCa = _ => Task.FromResult(Ca(CertificateAuthority.Types.State.Disabled, CaPool.Types.Tier.Enterprise)) };
        var ex = await Assert.ThrowsAsync<Exception>(() => NewClient(fake, "my-ca").ValidateConnection());
        Assert.Contains("Expected Enabled", ex.Message);
    }

    [Fact]
    public async Task ValidateConnection_WithCa_NotEnterprise_Throws()
    {
        var fake = new ConfigurableFakeCasClient { OnGetCa = _ => Task.FromResult(Ca(CertificateAuthority.Types.State.Enabled, CaPool.Types.Tier.Devops)) };
        var ex = await Assert.ThrowsAsync<Exception>(() => NewClient(fake, "my-ca").ValidateConnection());
        Assert.Contains("Enterprise", ex.Message);
    }

    // ---- DownloadAllIssuedCertificates ----

    [Fact]
    public async Task DownloadAll_NullBuffer_Throws()
    {
        var client = NewClient(new ConfigurableFakeCasClient());
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.DownloadAllIssuedCertificates(null!, CancellationToken.None));
    }

    [Fact]
    public async Task DownloadAll_FiltersByCaAndSetsIssuedAfterFilter()
    {
        var fake = new ConfigurableFakeCasClient
        {
            OnListCertificates = _ => new FakePages(FakePages.Page(
                TestData.Cert("mine", issuerCa: "my-ca"),
                TestData.Cert("other", issuerCa: "other-ca"))),
        };
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        int n = await NewClient(fake, "my-ca").DownloadAllIssuedCertificates(buffer, CancellationToken.None, new DateTime(2025, 1, 2, 3, 4, 5, DateTimeKind.Utc));

        Assert.Equal(1, n);
        Assert.Equal("mine", buffer.Single().CARequestID);
        Assert.StartsWith("update_time >=", fake.ListRequests.Single().Filter);
    }

    [Fact]
    public async Task DownloadAll_NoCaFilter_NoIssuedAfter_TakesEverything()
    {
        var fake = new ConfigurableFakeCasClient
        {
            OnListCertificates = _ => new FakePages(FakePages.Page(TestData.Cert("a"), TestData.Cert("b"))),
        };
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();
        Assert.Equal(2, await NewClient(fake).DownloadAllIssuedCertificates(buffer, CancellationToken.None));
        Assert.Equal(string.Empty, fake.ListRequests.Single().Filter);
    }

    [Fact]
    public async Task DownloadAll_RateLimit_Rethrows_AndCompletesBuffer()
    {
        var fake = new ConfigurableFakeCasClient
        {
            OnListCertificates = _ => new FakePages(new RpcException(new Status(StatusCode.ResourceExhausted, "slow down"))),
        };
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();
        await Assert.ThrowsAsync<RpcException>(() => NewClient(fake).DownloadAllIssuedCertificates(buffer, CancellationToken.None));
        Assert.True(buffer.IsAddingCompleted);
    }

    [Fact]
    public async Task DownloadAll_Cancellation_Rethrows()
    {
        var fake = new ConfigurableFakeCasClient { OnListCertificates = _ => new FakePages(new OperationCanceledException()) };
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            NewClient(fake).DownloadAllIssuedCertificates(new BlockingCollection<AnyCAPluginCertificate>(), CancellationToken.None));
    }

    [Fact]
    public async Task DownloadAll_UnexpectedError_Rethrows()
    {
        var fake = new ConfigurableFakeCasClient { OnListCertificates = _ => new FakePages(new InvalidOperationException("boom")) };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewClient(fake).DownloadAllIssuedCertificates(new BlockingCollection<AnyCAPluginCertificate>(), CancellationToken.None));
    }

    // ---- DownloadCertificate / mapping ----

    [Fact]
    public async Task DownloadCertificate_Active_NoTemplate_MapsToDefaultProduct()
    {
        var fake = new ConfigurableFakeCasClient { OnGetCertificate = r => Task.FromResult(TestData.Cert("abc")) };
        AnyCAPluginCertificate result = await NewClient(fake).DownloadCertificate("abc");

        Assert.Equal("abc", result.CARequestID);
        Assert.Equal(GCPCASPluginConfig.NoTemplateName, result.ProductID);
        Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
        Assert.Null(result.RevocationDate);
    }

    [Fact]
    public async Task DownloadCertificate_Revoked_WithTemplate_MapsRevocation()
    {
        Certificate cert = TestData.Cert("rev", template: "tmpl");
        cert.RevocationDetails = new Certificate.Types.RevocationDetails
        {
            RevocationState = RevocationReason.KeyCompromise,
            RevocationTime = Timestamp.FromDateTime(new DateTime(2025, 5, 5, 0, 0, 0, DateTimeKind.Utc)),
        };
        var fake = new ConfigurableFakeCasClient { OnGetCertificate = _ => Task.FromResult(cert) };

        AnyCAPluginCertificate result = await NewClient(fake).DownloadCertificate("rev");

        Assert.Equal("tmpl", result.ProductID);
        Assert.Equal((int)EndEntityStatus.REVOKED, result.Status);
        Assert.Equal((int)RevocationReason.KeyCompromise, result.RevocationReason);
        Assert.Equal(new DateTime(2025, 5, 5), result.RevocationDate!.Value.Date);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a pem")]
    public async Task DownloadCertificate_EmptyOrUnparseablePem_StillReturns(string pem)
    {
        Certificate cert = TestData.Cert("weird", pem: pem);
        var fake = new ConfigurableFakeCasClient { OnGetCertificate = _ => Task.FromResult(cert) };
        AnyCAPluginCertificate result = await NewClient(fake).DownloadCertificate("weird");
        Assert.Equal("weird", result.CARequestID);
        Assert.Equal(pem, result.Certificate);
    }

    // ---- Enroll ----

    private static ICreateCertificateRequestBuilder Builder(string? narId = null)
    {
        var parameters = new Dictionary<string, string>();
        if (narId != null) parameters["nar_id"] = narId;
        return new CreateCertificateRequestBuilder()
            .WithSubject("CN=test.lab.test")
            .WithEnrollmentProductInfo(new EnrollmentProductInfo { ProductID = GCPCASPluginConfig.NoTemplateName, ProductParameters = parameters });
    }

    [Fact]
    public async Task Enroll_Success_SendsNarIdLabelToGoogle()
    {
        CreateCertificateRequest? sent = null;
        var fake = new ConfigurableFakeCasClient
        {
            OnCreateCertificate = r =>
            {
                sent = r;
                return Task.FromResult(TestData.Cert("new-cert"));
            },
        };

        EnrollmentResult result = await NewClient(fake, "my-ca").Enroll(Builder("app_1234"), CancellationToken.None);

        Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
        Assert.Equal("new-cert", result.CARequestID);
        Assert.NotNull(sent);
        Assert.Equal("app_1234", sent!.Certificate.Labels["nar_id"]);
        Assert.Equal("my-ca", sent.IssuingCertificateAuthorityId);
    }

    [Fact]
    public async Task Enroll_RpcError_ReturnsFailedWithDetail()
    {
        var fake = new ConfigurableFakeCasClient
        {
            OnCreateCertificate = _ => throw new RpcException(new Status(StatusCode.InvalidArgument, "bad label")),
        };
        EnrollmentResult result = await NewClient(fake).Enroll(Builder(), CancellationToken.None);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        Assert.Contains("bad label", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_Cancelled_ReturnsCancelled()
    {
        var fake = new ConfigurableFakeCasClient { OnCreateCertificate = _ => throw new OperationCanceledException() };
        EnrollmentResult result = await NewClient(fake).Enroll(Builder(), CancellationToken.None);
        Assert.Equal((int)EndEntityStatus.CANCELLED, result.Status);
    }

    [Fact]
    public async Task Enroll_UnexpectedError_ReturnsFailed()
    {
        var fake = new ConfigurableFakeCasClient { OnCreateCertificate = _ => throw new InvalidOperationException("kaboom") };
        EnrollmentResult result = await NewClient(fake).Enroll(Builder(), CancellationToken.None);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        Assert.Contains("kaboom", result.StatusMessage);
    }

    // ---- Revoke / templates ----

    [Fact]
    public async Task Revoke_SendsNameAndReason()
    {
        RevokeCertificateRequest? sent = null;
        var fake = new ConfigurableFakeCasClient { OnRevoke = r => { sent = r; return Task.FromResult(new Certificate()); } };

        await NewClient(fake).RevokeCertificate("c1", RevocationReason.Superseded);

        Assert.EndsWith("/certificates/c1", sent!.Name);
        Assert.Equal(RevocationReason.Superseded, sent.Reason);
    }

    [Fact]
    public void GetTemplates_AggregatesPages_AndAppendsDefault()
    {
        var fake = new ConfigurableFakeCasClient
        {
            OnListTemplates = _ => new FakeTemplatePages(FakeTemplatePages.Page("t1", "t2"), FakeTemplatePages.Page("t3")),
        };
        List<string> templates = NewClient(fake).GetTemplates();
        Assert.Equal(new[] { "t1", "t2", "t3", GCPCASPluginConfig.NoTemplateName }, templates);
    }
}
