using System;
using System.Collections.Generic;
using Google.Cloud.Security.PrivateCA.V1;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.GCPCAS;
using Keyfactor.Extensions.CAPlugin.GCPCAS.Client;
using Xunit;

namespace GCPCAS.Tests;

public class CreateCertificateRequestBuilderLabels
{
    private static CreateCertificateRequest BuildWith(Dictionary<string, string> parameters)
    {
        var productInfo = new EnrollmentProductInfo
        {
            ProductID = GCPCASPluginConfig.NoTemplateName,
            ProductParameters = parameters
        };
        return new CreateCertificateRequestBuilder()
            .WithEnrollmentProductInfo(productInfo)
            .Build("us-central1", "proj", "pool", "ca");
    }

    [Fact]
    public void NarId_IsAppliedUnchangedAsLabel()
    {
        var request = BuildWith(new() { { "nar_id", "app_1234-x" } });
        Assert.Equal("app_1234-x", request.Certificate.Labels["nar_id"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NarId_EmptyAppliesNoLabel(string value)
    {
        var request = BuildWith(new() { { "nar_id", value } });
        Assert.Empty(request.Certificate.Labels);
    }

    [Fact]
    public void NarId_Missing_AppliesNoLabel()
    {
        var request = BuildWith(new());
        Assert.Empty(request.Certificate.Labels);
    }

    [Theory]
    [InlineData("UPPER")]
    [InlineData("has space")]
    public void NarId_InvalidLabelValue_Throws(string value)
    {
        Assert.Throws<ArgumentException>(() => BuildWith(new() { { "nar_id", value } }));
    }

    [Fact]
    public void NarId_TooLong_Throws()
    {
        Assert.Throws<ArgumentException>(() => BuildWith(new() { { "nar_id", new string('a', 64) } }));
    }
}
