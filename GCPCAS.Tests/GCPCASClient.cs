// Copyright 2024 Keyfactor
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
using Keyfactor.Extensions.CAPlugin.GCPCAS.Client;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keyfactor.PKI.Enums.EJBCA;
using Keyfactor.Extensions.CAPlugin.GCPCAS;
using Google.Cloud.Security.PrivateCA.V1;

namespace Keyfactor.Extensions.CAPlugin.GCPCASTests;

public class ClientTests
{
    ILogger _logger { get; set; }

    public ClientTests()
    {
        ConfigureLogging();

        _logger = LogHandler.GetClassLogger<ClientTests>();
    }

    [IntegrationTestingFact]
    public void GCPCASClient_Integration_GetTemplates_ReturnSuccess()
    {
        // Arrange
        IntegrationTestingFact env = new();

        IGCPCASClient client = new GCPCASClient(env.LocationId, env.ProjectId, env.CAPool, env.CAId);
        client.Enable();

        // Act
        List<string> templates = client.GetTemplates();
        // There is never a case where there are zero templates - there's always the default "no template"
        Assert.NotEmpty(templates);
        _logger.LogInformation($"Found {templates.Count} templates: {string.Join(", ", templates)}");
    }

    [IntegrationTestingFact]
    public void GCPCASClient_Integration_DownloadAllCertificates_ReturnSuccess()
    {
        // Arrange
        IntegrationTestingFact env = new();

        IGCPCASClient client = new GCPCASClient(env.LocationId, env.ProjectId, env.CAPool, env.CAId);
        client.Enable();

        BlockingCollection<AnyCAPluginCertificate> certificates = new();

        // Act
        int numberOfDownloadedCerts = client.DownloadAllIssuedCertificates(certificates, CancellationToken.None).Result;
        _logger.LogInformation($"Number of downloaded certificates: {numberOfDownloadedCerts}");
    }

    [IntegrationTestingFact]
    public void GCPCASClient_Integration_DownloadAllCertificatesAfter_ReturnSuccess()
    {
        // Arrange
        IntegrationTestingFact env = new();

        IGCPCASClient client = new GCPCASClient(env.LocationId, env.ProjectId, env.CAPool, env.CAId);
        client.Enable();

        BlockingCollection<AnyCAPluginCertificate> certificates = new();

        DateTime after = DateTime.UtcNow.AddDays(-100);

        // Act
        int numberOfDownloadedCerts = client.DownloadAllIssuedCertificates(certificates, CancellationToken.None, after).Result;
        _logger.LogInformation($"Number of downloaded certificates: {numberOfDownloadedCerts}");
    }

    [IntegrationTestingFact]
    public void GCPCASClient_Integration_EnrollGetRevoke_ReturnSuccess()
    {
        // Arrange
        IntegrationTestingFact env = new();

        GCPCASClient client = new GCPCASClient(env.LocationId, env.ProjectId, env.CAPool, env.CAId);
        client.Enable();

        // Create a CSR
        string subject = "CN=Test Subject";
        string csrString = GenerateCSR(subject);

        EnrollmentProductInfo productInfo = new EnrollmentProductInfo
        {
            ProductID = GCPCASPluginConfig.NoTemplateName,
            ProductParameters = new Dictionary<string, string>
            {
                { GCPCASPluginConfig.EnrollmentParametersConstants.CertificateLifetimeDays, "200" }
            }
        };
        ICreateCertificateRequestBuilder builder = new CreateCertificateRequestBuilder()
            .WithCsr(csrString)
            .WithEnrollmentProductInfo(productInfo);

        // Act
        _logger.LogInformation($"Enrolling test certificate with DN {subject} using GCP CAS CA called {env.CAId}");
        EnrollmentResult enrollResult = client.Enroll(builder, CancellationToken.None).Result;

        // Assert
        Assert.Equal(enrollResult.Status, (int)EndEntityStatus.GENERATED);
        Assert.NotNull(enrollResult.CARequestID);
        _logger.LogInformation($"Certificate enrollment validated successfully");

        // Act
        _logger.LogInformation($"Downloading test certificate identified as {enrollResult.CARequestID} from GCP CAS CA called {env.CAId}");
        AnyCAPluginCertificate downloadResult = client.DownloadCertificate(enrollResult.CARequestID).Result;

        // Assert
        Assert.Equal(enrollResult.Status, downloadResult.Status);
        Assert.Equal(enrollResult.CARequestID, downloadResult.CARequestID);
        Assert.Equal(enrollResult.Certificate, downloadResult.Certificate);
        _logger.LogInformation($"Verified that the downloaded certificate identified as {downloadResult.CARequestID} is the same as the initially enrolled certificate");

        // Act
        _logger.LogInformation($"Revoking test certificate identified as {enrollResult.CARequestID} issued by GCP CAS CA called {env.CAId}");
        client.RevokeCertificate(enrollResult.CARequestID, RevocationReason.CessationOfOperation).Wait();

        _logger.LogInformation($"Downloading test certificate identified as {enrollResult.CARequestID} from GCP CAS CA called {env.CAId}");
        downloadResult = client.DownloadCertificate(enrollResult.CARequestID).Result;

        // Assert
        Assert.Equal(enrollResult.CARequestID, downloadResult.CARequestID);
        Assert.Equal(enrollResult.Certificate, downloadResult.Certificate);
        Assert.Equal(downloadResult.Status, (int)EndEntityStatus.REVOKED);
        // Cecession of Operation should be reason 5
        Assert.Equal(downloadResult.RevocationReason, 5);

        _logger.LogInformation("GCPCASClient_Integration_EnrollGetRevoke_ReturnSuccess was successful");
    }

    static void ConfigureLogging()
    {
        var config = new NLog.Config.LoggingConfiguration();

        // Targets where to log to: File and Console
        var logconsole = new NLog.Targets.ConsoleTarget("logconsole");
        logconsole.Layout = @"${date:format=HH\:mm\:ss} ${logger} [${level}] - ${message}";

        // Rules for mapping loggers to targets            
        config.AddRule(NLog.LogLevel.Trace, NLog.LogLevel.Fatal, logconsole);

        // Apply config           
        NLog.LogManager.Configuration = config;

        LogHandler.Factory = LoggerFactory.Create(builder =>
                {
                    builder.AddNLog();
                });
    }

    static string GenerateCSR(string subject)
    {
        using RSA rsa = RSA.Create(2048);
        X500DistinguishedName subjectName = new X500DistinguishedName(subject);
        CertificateRequest csr = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return csr.CreateSigningRequestPem();
    }
}

