/*
Copyright © 2024 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Google.Cloud.Security.PrivateCA.V1;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.GCPCAS.Client;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS;

public class GCPCASCAPlugin : IAnyCAPlugin
{
    ILogger _logger = LogHandler.GetClassLogger<GCPCASCAPlugin>();
    ICertificateDataReader _certificateDataReader;
    IGCPCASClient Client { get; set; }
    private bool _gcpCasClientWasInjected = false;

    public GCPCASCAPlugin()
    {
        // Explicit default constructor
    }

    public GCPCASCAPlugin(IGCPCASClient client)
    {
        Client = client;
        _gcpCasClientWasInjected = true;
    }

    public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
    {
        GCPCASClientFromCAConnectionData(configProvider.CAConnectionData);
    }

    public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
    {
        _logger.LogDebug("Returning CA Connector Annotations (Properties)");
        return GCPCASPluginConfig.GetPluginAnnotations();
    }

    public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
    {
        _logger.LogDebug("Returning Template Parameter Annotations (Custom Enrollment Parameters)");
        return GCPCASPluginConfig.GetTemplateParameterAnnotations();
    }

    public List<string> GetProductIds()
    {
        _logger.LogDebug("Returning available Product IDs as Certificate Templates in the connected GCP CAS");
        return Client.GetTemplates();
    }

    public async Task Ping()
    {
        if (!Client.IsEnabled())
        {
            _logger.LogDebug("GCPCASClient is disabled. Skipping Ping");
            return;
        }
        _logger.LogDebug("Pinging GCP CAS to validate connection");
        await Client.ValidateConnection();
    }

    public Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
    {
        GCPCASClientFromCAConnectionData(connectionInfo);
        return Ping();
    }

    public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
    {
        // WithEnrollmentProductInfo() validates that the custom parameters in EnrollmentProductInfo are valid
        new CreateCertificateRequestBuilder().WithEnrollmentProductInfo(productInfo);
        // If this method doesn't throw, the product info is valid
        return Task.CompletedTask;
    }

    public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
    {
        if (fullSync && lastSync != null)
        {
            _logger.LogInformation("Performing a full CA synchronization");
            lastSync = null;
        }
        else
        {
            _logger.LogInformation($"Performing an incremental CA synchronization - downloading certificates issued after {lastSync}");
        }
        int certificates = await Client.DownloadAllIssuedCertificates(blockingBuffer, cancelToken, lastSync);
        _logger.LogDebug($"Synchronized {certificates} certificates");
    }

    public Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
    {
        return Client.DownloadCertificate(caRequestID);
    }

    public Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
    {
        ICreateCertificateRequestBuilder ccrBuilder = new CreateCertificateRequestBuilder()
            .WithCsr(csr)
            .WithSubject(subject)
            .WithSans(san)
            .WithEnrollmentProductInfo(productInfo)
            .WithRequestFormat(requestFormat)
            .WithEnrollmentType(enrollmentType);

        return Client.Enroll(ccrBuilder, CancellationToken.None);
    }

    public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
    {
        _logger.LogDebug($"Revoking certificate withKeyfactor.PKI.Enums.EJBCA.EndEntityStatus request ID: {caRequestID}");

        // Google.Cloud.Security.PrivateCA.V1.RevocationReason has the same mapping as 
        // Keyfactor.PKI.Enums.EJBCA.EndEntityStatus
        await Client.RevokeCertificate(caRequestID, (RevocationReason)revocationReason);
        return (int)EndEntityStatus.REVOKED;
    }

    private void GCPCASClientFromCAConnectionData(Dictionary<string, object> connectionData)
    {
        _logger.LogDebug($"Validating GCP CAS CA Connection properties");
        var rawData = JsonSerializer.Serialize(connectionData);
        GCPCASPluginConfig.Config config = JsonSerializer.Deserialize<GCPCASPluginConfig.Config>(rawData);

        _logger.LogTrace($"GCPCASClientFromCAConnectionData - LocationId: {config.LocationId}");
        _logger.LogTrace($"GCPCASClientFromCAConnectionData - ProjectId: {config.ProjectId}");
        _logger.LogTrace($"GCPCASClientFromCAConnectionData - CAPool: {config.CAPool}");
        _logger.LogTrace($"GCPCASClientFromCAConnectionData - CAId: {config.CAId}");
        _logger.LogTrace($"GCPCASClientFromCAConnectionData - Enabled: {config.Enabled}");

        List<string> missingFields = new List<string>();

        if (string.IsNullOrEmpty(config.LocationId)) missingFields.Add(nameof(config.LocationId));
        if (string.IsNullOrEmpty(config.ProjectId)) missingFields.Add(nameof(config.ProjectId));
        if (string.IsNullOrEmpty(config.CAPool)) missingFields.Add(nameof(config.CAPool));
        if (string.IsNullOrEmpty(config.CAId)) missingFields.Add(nameof(config.CAId));

        if (config.Enabled && missingFields.Count > 0)
        {
            throw new ArgumentException($"The following required fields are missing or empty: {string.Join(", ", missingFields)}");
        }

        if (_gcpCasClientWasInjected && Client != null)
        {
            _logger.LogDebug("Not building a GCPCASClient - one was injected");
        }
        else
        {
            _logger.LogDebug("Creating new GCPCASClient instance.");
            Client = new GCPCASClient(config.LocationId, config.ProjectId, config.CAPool, config.CAId);
        }

        if (config.Enabled)
        {
            Client.Enable();
        }
        else
        {
            Client.Disable();
        }
    }
}
