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
using static Keyfactor.Extensions.CAPlugin.GCPCAS.GCPCASPluginConfig;
using Keyfactor.PKI.Enums.EJBCA;

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
    public void GCPCASClient_Integration_Enroll_ReturnSuccess()
    {
        // Arrange
        IntegrationTestingFact env = new();

        for (int i = 0; i < 1000; i++)
        {
            IGCPCASClient client = new GCPCASClient(env.LocationId, env.ProjectId, env.CAPool, env.CAId);
            client.Enable();

            // CSR
            string subject = "CN=Test Subject";
            string csrString = GenerateCSR(subject);

            EnrollmentParameters parameters = new EnrollmentParameters();

            ICreateCertificateRequestBuilder builder = new CreateCertificateRequestBuilder()
                .WithCsr(csrString);

            // Act
            EnrollmentResult result = client.Enroll(builder, CancellationToken.None).Result;

            // Assert
            Assert.Equal(result.Status, (int)EndEntityStatus.GENERATED);
        }
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

