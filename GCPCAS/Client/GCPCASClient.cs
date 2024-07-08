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
using System.Threading;
using System.Threading.Tasks;
using Google.Api.Gax;
using Google.Api.Gax.Grpc.Rest;
using Google.Api.Gax.ResourceNames;
using Google.Cloud.Security.PrivateCA.V1;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS.Client;

public class GCPCASClient : IGCPCASClient
{
    private ILogger _logger;
    private CertificateAuthorityServiceClient _client;

    bool _clientIsEnabled;

    string _projectId;
    string _locationId;
    string _caPool;
    string _caId;
    int _defaultCertificateDurationDays = 365;

    public GCPCASClient(string locationId, string projectId, string caPool, string caId)
    {
        _logger = LogHandler.GetClassLogger<GCPCASClient>();

        _logger.LogDebug($"Creating GCP CA Services Client with Location: {locationId}, Project Name: {projectId}, CA Pool: {caPool}");

        this._projectId = projectId;
        this._locationId = locationId;
        this._caPool = caPool;
        this._caId = caId;

        _client = new CertificateAuthorityServiceClientBuilder
        {
            GrpcAdapter = RestGrpcAdapter.Default
        }.Build();
    }

    public Task Enable()
    {
        if (!_clientIsEnabled)
        {
            _logger.LogDebug("Enabling GCPCAS client");
            _clientIsEnabled = true;
        }
        return Task.CompletedTask;
    }

    public Task Disable()
    {
        if (_clientIsEnabled)
        {
            _logger.LogDebug("Disabling GCPCAS client");
            _clientIsEnabled = false;
        }
        return Task.CompletedTask;
    }

    public bool IsEnabled()
    {
        return _clientIsEnabled;
    }

    public Task Ping()
    {
        throw new System.NotImplementedException();
    }

    public async Task<int> DownloadAllIssuedCertificates(BlockingCollection<AnyCAPluginCertificate> certificatesBuffer, CancellationToken cancelToken)
    {
        if (certificatesBuffer == null)
        {
            throw new Exception($"Failed to download issued certificates - certificatesBuffer is null");
        }

        _logger.LogDebug($"Downloading all issued certificates from GCP CAS [locationId={_locationId}] [projectId={_projectId}] [caPool={_caPool}]");
        ListCertificatesRequest request = new ListCertificatesRequest
        {
            ParentAsCaPoolName = new CaPoolName(_projectId, _locationId, _caPool),
        };

        // TODO catch exception
        PagedAsyncEnumerable<ListCertificatesResponse, Certificate> certificates = _client.ListCertificatesAsync(request);

        int pageNumber = 0;
        int numberOfCertificates = 0;
        await foreach (var response in certificates.AsRawResponses())
        {
            if (response.Certificates == null)
            {
                _logger.LogWarning($"GCP returned null Certificates object for page number {pageNumber}");
                continue;
            }
            foreach (Certificate certificate in response.Certificates)
            {
                certificatesBuffer.Add(AnyCAPluginCertificateFromGCPCertificate(certificate));
                numberOfCertificates++;
                _logger.LogDebug($"Found Certificate with name {certificate.CertificateName.CertificateId} [locationId={certificate.CertificateName.LocationId}] [projectId={certificate.CertificateName.ProjectId}] [caPool={certificate.CertificateName.CaPoolId}]");
            }
            _logger.LogTrace($"Fetched page {pageNumber} - Next Page Token: {response.NextPageToken}");
            pageNumber++;
        }
        _logger.LogDebug($"Fetched {certificatesBuffer.Count} certificates from GCP across {pageNumber} pages of certificates from GCP CAS [locationId={_locationId}] [projectId={_projectId}] [caPool={_caPool}]");
        certificatesBuffer.CompleteAdding();
        return numberOfCertificates;
    }

    public async Task<AnyCAPluginCertificate> DownloadCertificate(string certificateId)
    {
        _logger.LogDebug($"Downloading certificate with ID {certificateId}");

        CertificateName name = new CertificateName(_projectId, _locationId, _caPool, certificateId);
        GetCertificateRequest request = new GetCertificateRequest
        {
            Name = name.ToString()
        };

        Certificate certificate = await _client.GetCertificateAsync(request);
        return AnyCAPluginCertificateFromGCPCertificate(certificate);
    }

    private AnyCAPluginCertificate AnyCAPluginCertificateFromGCPCertificate(Certificate certificate)
    {
        string productId = "";
        if (certificate.CertificateTemplateAsCertificateTemplateName == null)
        {
            productId = GCPCASPluginConfig.NoTemplateName;
        }
        else
        {
            productId = certificate.CertificateTemplateAsCertificateTemplateName.CertificateTemplateId;
        }

        EndEntityStatus status = EndEntityStatus.GENERATED;

        DateTime? revocationDate = null;
        int? revocationReason = null;
        // Certificate is considered as revoked if and only if RevocationDetails is not null
        if (certificate.RevocationDetails != null)
        {
            revocationDate = certificate.RevocationDetails.RevocationTime.ToDateTime();
            status = EndEntityStatus.REVOKED;
            revocationReason = (int)certificate.RevocationDetails.RevocationState;
        }

        return new AnyCAPluginCertificate
        {
            CARequestID = certificate.Name,
            Certificate = certificate.PemCertificate,
            Status = (int)status,
            ProductID = productId,
            RevocationDate = revocationDate,
            RevocationReason = revocationReason,
        };
    }

    public async Task<EnrollmentResult> Enroll(ICreateCertificateRequestBuilder createCertificateRequestBuilder, CancellationToken cancelToken)
    {
        // TODO catch exception
        Certificate certificate = await _client.CreateCertificateAsync(createCertificateRequestBuilder.Build(_locationId, _projectId, _caPool, _caId));

        _logger.LogDebug($"Created Certificate in GCP CAS with name {certificate.CertificateName}");

        return new EnrollmentResult
        {
            CARequestID = certificate.CertificateName.CertificateId,
            Certificate = certificate.PemCertificate,
            Status = (int)EndEntityStatus.GENERATED,
            StatusMessage = $"Certificate with ID {certificate.CertificateName} has been issued",
        };
    }

    public Task RevokeCertificate(string certificateId, RevocationReason reason)
    {
        _logger.LogDebug($"Revoking certificate with ID {certificateId} for reason {reason.ToString()}");

        CertificateName name = new CertificateName(_projectId, _locationId, _caPool, certificateId);
        RevokeCertificateRequest request = new RevokeCertificateRequest
        {
            Name = name.ToString(),
            Reason = reason,
        };
        return _client.RevokeCertificateAsync(request);
    }

    public List<string> GetTemplates()
    {
        _logger.LogDebug($"Getting Certificate Templates from GCP CA Service for Project: {_projectId}, Location: {_locationId}");
        LocationName location = new LocationName(_projectId, _locationId);
        List<string> templateStrings = new List<string>();

        PagedEnumerable<ListCertificateTemplatesResponse, CertificateTemplate> templates = _client.ListCertificateTemplates(location);

        int pageNumber = 0;
        // By iterating over templates or templates.AsRawResponses(), 
        // API requests are made transparently, propagating the page token from one response to the next request
        // until all pages are fetched.
        foreach (ListCertificateTemplatesResponse response in templates.AsRawResponses())
        {
            foreach (CertificateTemplate template in response.CertificateTemplates)
            {
                _logger.LogDebug($"Found Certificate Template: {template.Name}");
                templateStrings.Add(template.CertificateTemplateName.CertificateTemplateId);
            }
            _logger.LogTrace($"Next Page Token: {response.NextPageToken}");
            pageNumber++;
        }
        _logger.LogDebug($"Found {templateStrings.Count} Certificate Templates across {pageNumber} pages");

        return templateStrings;
    }
}

