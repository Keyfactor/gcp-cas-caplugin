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
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.GCPCAS;
using Keyfactor.Extensions.CAPlugin.GCPCAS.Client;
using Keyfactor.PKI.Enums.EJBCA;

namespace Keyfactor.Extensions.CAPlugin.GCPCASTests;

public class GCPCASCAPluginTests
{
    private sealed class FakeGcpClient : IGCPCASClient
    {
        public bool Enabled;
        public bool Validated;
        public bool ThrowOnDownloadAll;
        public bool CancelOnDownloadAll;
        public DateTime? LastIssuedAfter;
        public (string Id, RevocationReason Reason)? Revoked;
        public EnrollmentResult EnrollResult = new() { Status = (int)EndEntityStatus.GENERATED, CARequestID = "new" };

        public Task Enable() { Enabled = true; return Task.CompletedTask; }
        public Task Disable() { Enabled = false; return Task.CompletedTask; }
        public bool IsEnabled() => Enabled;
        public Task ValidateConnection() { Validated = true; return Task.CompletedTask; }
        public List<string> GetTemplates() => new() { "t1", "Default" };
        public Task<AnyCAPluginCertificate> DownloadCertificate(string id) => Task.FromResult(new AnyCAPluginCertificate { CARequestID = id });
        public Task<EnrollmentResult> Enroll(ICreateCertificateRequestBuilder b, CancellationToken t) => Task.FromResult(EnrollResult);
        public Task RevokeCertificate(string id, RevocationReason reason) { Revoked = (id, reason); return Task.CompletedTask; }

        public Task<int> DownloadAllIssuedCertificates(BlockingCollection<AnyCAPluginCertificate> buffer, CancellationToken token, DateTime? issuedAfter = null)
        {
            LastIssuedAfter = issuedAfter;
            if (ThrowOnDownloadAll) throw new InvalidOperationException("sync failed");
            if (CancelOnDownloadAll) throw new OperationCanceledException();
            buffer.Add(new AnyCAPluginCertificate { CARequestID = "one" });
            return Task.FromResult(1);
        }
    }

    private sealed class FakeConfigProvider : IAnyCAPluginConfigProvider
    {
        public Dictionary<string, object> CAConnectionData { get; set; } = new();
    }

    private static Dictionary<string, object> Conn(bool enabled = true, string? location = "us-central1", string? project = "p", string? pool = "pool")
        => new()
        {
            ["LocationId"] = location!,
            ["ProjectId"] = project!,
            ["CAPool"] = pool!,
            ["CAId"] = "ca",
            ["Enabled"] = enabled,
        };

    private static (GCPCASCAPlugin Plugin, FakeGcpClient Client) Create(Dictionary<string, object>? connection = null)
    {
        var client = new FakeGcpClient();
        var plugin = new GCPCASCAPlugin(client);
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = connection ?? Conn() }, null!);
        return (plugin, client);
    }

    [Fact]
    public void Initialize_Enabled_EnablesInjectedClient()
    {
        var (_, client) = Create();
        Assert.True(client.Enabled);
    }

    [Fact]
    public void Initialize_Disabled_DisablesClientAndSkipsValidation()
    {
        var (_, client) = Create(Conn(enabled: false, location: null));
        Assert.False(client.Enabled);
    }

    [Fact]
    public void Initialize_MissingFields_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Create(Conn(location: "", project: "")));
        Assert.Contains("LocationId", ex.Message);
        Assert.Contains("ProjectId", ex.Message);
    }

    [Fact]
    public void DefaultConstructor_DisabledConfig_DoesNotBuildClient()
    {
        // A disabled config returns before any real GCP client is built, so no credentials are needed.
        var plugin = new GCPCASCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = Conn(enabled: false) }, null!);
    }

    [Fact]
    public void Annotations_AndProductIds()
    {
        var (plugin, _) = Create();
        Assert.Contains("nar_id", plugin.GetTemplateParameterAnnotations().Keys);
        Assert.Contains("ProjectId", plugin.GetCAConnectorAnnotations().Keys);
        Assert.Equal(new[] { "t1", "Default" }, plugin.GetProductIds());
    }

    [Fact]
    public async Task Ping_Enabled_ValidatesConnection()
    {
        var (plugin, client) = Create();
        await plugin.Ping();
        Assert.True(client.Validated);
    }

    [Fact]
    public async Task Ping_Disabled_SkipsValidation()
    {
        var (plugin, client) = Create(Conn(enabled: false));
        await plugin.Ping();
        Assert.False(client.Validated);
    }

    [Fact]
    public async Task ValidateCAConnectionInfo_ValidatesWithNewConfig()
    {
        var (plugin, client) = Create();
        await plugin.ValidateCAConnectionInfo(Conn());
        Assert.True(client.Validated);
    }

    [Fact]
    public async Task ValidateProductInfo_AcceptsGoodInfo_AndRejectsBadLabel()
    {
        var (plugin, _) = Create();
        await plugin.ValidateProductInfo(new EnrollmentProductInfo { ProductID = "Default", ProductParameters = new() { ["nar_id"] = "ok_1" } }, Conn());
        Assert.Throws<ArgumentException>(() =>
        {
            _ = plugin.ValidateProductInfo(new EnrollmentProductInfo { ProductID = "Default", ProductParameters = new() { ["nar_id"] = "BAD VALUE" } }, Conn());
        });
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Synchronize_FullAndIncremental_PassCorrectFilter(bool fullSync)
    {
        var (plugin, client) = Create();
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();
        DateTime last = new(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        await plugin.Synchronize(buffer, last, fullSync, CancellationToken.None);

        Assert.Equal(fullSync ? null : last, client.LastIssuedAfter);
        Assert.Single(buffer);
    }

    [Fact]
    public async Task Synchronize_NullBuffer_Throws()
    {
        var (plugin, _) = Create();
        await Assert.ThrowsAsync<ArgumentNullException>(() => plugin.Synchronize(null!, null, false, CancellationToken.None));
    }

    [Fact]
    public async Task Synchronize_ClientFailure_Propagates()
    {
        var (plugin, client) = Create();
        client.ThrowOnDownloadAll = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => plugin.Synchronize(new BlockingCollection<AnyCAPluginCertificate>(), null, true, CancellationToken.None));
    }

    [Fact]
    public async Task Synchronize_Cancellation_Propagates()
    {
        var (plugin, client) = Create();
        client.CancelOnDownloadAll = true;
        await Assert.ThrowsAsync<OperationCanceledException>(() => plugin.Synchronize(new BlockingCollection<AnyCAPluginCertificate>(), null, false, CancellationToken.None));
    }

    [Fact]
    public async Task GetSingleRecord_ReturnsClientResult()
    {
        var (plugin, _) = Create();
        Assert.Equal("abc", (await plugin.GetSingleRecord("abc")).CARequestID);
    }

    [Fact]
    public async Task Enroll_BuildsRequestAndReturnsResult()
    {
        var (plugin, _) = Create();
        EnrollmentResult r = await plugin.Enroll(
            "csr", "CN=a.lab.test", new Dictionary<string, string[]> { ["Dns"] = new[] { "a.lab.test" } },
            new EnrollmentProductInfo { ProductID = "Default", ProductParameters = new() { ["nar_id"] = "x1" } },
            RequestFormat.PKCS10, EnrollmentType.New);
        Assert.Equal("new", r.CARequestID);
    }

    [Fact]
    public async Task Revoke_PassesReasonThrough_AndReturnsRevokedStatus()
    {
        var (plugin, client) = Create();
        int status = await plugin.Revoke("id1", "ABCD", (uint)RevocationReason.KeyCompromise);
        Assert.Equal((int)EndEntityStatus.REVOKED, status);
        Assert.Equal(("id1", RevocationReason.KeyCompromise), client.Revoked);
    }
}
