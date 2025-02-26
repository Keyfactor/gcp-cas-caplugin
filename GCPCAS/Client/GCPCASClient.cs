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
using Google.Api.Gax.Grpc;
using Google.Api.Gax.Grpc.Rest;
using Google.Api.Gax.ResourceNames;
using Google.Cloud.Security.PrivateCA.V1;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS.Client;

/// <summary>
/// Class <c>GCPCASClient</c> implements <see cref="IGCPCASClient"/> to provide a standard set of certificate-based operations on a GCP CAS specified by a Project ID, Location ID, CA Pool ID, and CA ID.
/// </summary>
///
/// <remarks><c>GCPCASClient</c> wraps a <see cref="Google.Cloud.Security.PrivateCA.V1.CertificateAuthorityServiceClient"/>. As such, valid <see langword="GCP Application Default Credentials" href="https://cloud.google.com/docs/authentication/application-default-credentials"/> must be configured before this class is used.</remarks>
public class GCPCASClient : IGCPCASClient
{
    private ILogger _logger;
    private CertificateAuthorityServiceClient _client;

    bool _clientIsEnabled;

    string _projectId;
    string _locationId;
    string _caPool;
    string _caId;

    /// <summary>
    /// Initializes a new instance of the <see cref="GCPCASClient"/> class.
    /// </summary>
    /// <param name="locationId">The GCP location ID where the project containing the target GCP CAS CA is located. For example, <c>us-central1</c>.</param>
    /// <param name="projectId">The GCP project ID where the target GCP CAS CA is located</param>
    /// <param name="caPool">The CA Pool ID in GCP CAS to use for certificate operations. If the CA Pool has resource name <c>projects/my-project/locations/us-central1/caPools/my-pool</c>, this field should be set to <c>my-pool</c></param>
    /// <param name="caId">The CA ID of a CA in the same CA Pool as CAPool. For example, to issue certificates from a CA with resource name <c>projects/my-project/locations/us-central1/caPools/my-pool/certificateAuthorities/my-ca</c>, this field should be set to <c>my-ca</c>.</param>
    public GCPCASClient(string locationId, string projectId, string caPool, string caId)
    {
        _logger = LogHandler.GetClassLogger<GCPCASClient>();

        _logger.LogDebug($"Creating GCP CA Services Client with Location: {locationId}, Project ID: {projectId}, CA Pool: {caPool}, CA ID: {caId}");

        this._projectId = projectId;
        this._locationId = locationId;
        this._caPool = caPool;
        this._caId = caId;

        _logger.LogTrace($"Setting up a {typeof(CertificateAuthorityServiceClient).ToString()} using the Default gRPC adapter");
        _client = new CertificateAuthorityServiceClientBuilder().Build();
    }

    public override string ToString()
    {
        return $"[locationId={_locationId} projectId={_projectId} caPool={_caPool} caId={_caId}]";
    }

    /// <summary>
    /// Enables the <see cref="GCPCASClient"/> client. This must be called before any other operations are performed.
    /// </summary>
    /// <returns></returns>
    public Task Enable()
    {
        if (!_clientIsEnabled)
        {
            _logger.LogDebug($"Enabling GCPCAS client {this.ToString()}");
            _clientIsEnabled = true;
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Disables the <see cref="GCPCASClient"/> client. After this is called, no further operations can be performed until <see cref="Enable"/> is called.
    /// </summary>
    /// <returns></returns>
    public Task Disable()
    {
        if (_clientIsEnabled)
        {
            _logger.LogDebug($"Disabling GCPCAS client {this.ToString()}");
            _clientIsEnabled = false;
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Determines if the client is enabled.
    /// </summary>
    /// <returns>
    /// A <see cref="bool"/> indicating if the client is enabled.
    /// </returns>
    public bool IsEnabled()
    {
        return _clientIsEnabled;
    }

    /// <summary>
    /// Attempts to connect to the GCP CAS service to verify connectivity. Verifies that the GCP Application Default Credentials are properly configured.
    /// </summary>
    /// <returns>
    /// Returns nothing if the connection is successful.
    /// </returns>
    /// <exception cref="Exception">Thrown if the GCP Application Default Credentials are not properly configured, if the GCP CAS CA Pool/CA is not found/is not compatible, or if the <see cref="GCPCASClient"/> was not enabled via the <see cref="Enable"/> method.</exception>
    public async Task ValidateConnection()
    {
        EnsureClientIsEnabled();

        _logger.LogTrace($"Searching for  CA called {_caId} in the {_caPool} CA pool");
        CertificateAuthority ca = await _client.GetCertificateAuthorityAsync(new CertificateAuthorityName(_projectId, _locationId, _caPool, _caId));
        _logger.LogDebug($"Found CA called {ca.CertificateAuthorityName.CertificateAuthorityId} in the {ca.CertificateAuthorityName.CaPoolId} CA pool");

        // Validate that the CA is enabled
        if (ca.State != CertificateAuthority.Types.State.Enabled)
        {
            string error = $"CA called {ca.CertificateAuthorityName.CertificateAuthorityId} in the {ca.CertificateAuthorityName.CaPoolId} CA pool is {ca.State.ToString()}. Expected state was {CertificateAuthority.Types.State.Enabled.ToString()}";
            _logger.LogError(error);
            throw new Exception(error);
        }

        // Validate that the CA is in the Enterprise tier
        if (ca.Tier != CaPool.Types.Tier.Enterprise)
        {
            string error = $"CA called {ca.CertificateAuthorityName.CertificateAuthorityId} is in a {ca.Tier.ToString()} Tier CA Pool. {this.ToString()} is only compatible with {CaPool.Types.Tier.Enterprise.ToString()} Tier CA pools.";
            _logger.LogError(error);
            throw new Exception(error);
        }

        _logger.LogDebug($"{typeof(GCPCASClient).ToString()} is compatible with CA called {ca.CertificateAuthorityName.CertificateAuthorityId} in the {ca.CertificateAuthorityName.CaPoolId} CA Pool.");
        return;
    }

    /// <summary>
    /// Downloads all issued certificates from the GCP CAS service and adds them to the provided <see cref="BlockingCollection{T}"/>. This call can be cancelled by passing a <see cref="CancellationToken"/>.
    /// </summary>
    /// <param name="certificatesBuffer">
    /// A <see cref="BlockingCollection{T}"/> to which the downloaded certificates will be added.
    /// </param>
    /// <param name="cancelToken">
    /// A <see cref="CancellationToken"/> that can be used to cancel the operation.
    /// </param>
    /// <returns>
    /// The number of certificates downloaded.
    /// </returns>
    /// <exception cref="Exception">
    /// Thrown if the <see cref="BlockingCollection{T}"/> is null or if the operation fails.
    /// </exception>
    public async Task<int> DownloadAllIssuedCertificates(BlockingCollection<AnyCAPluginCertificate> certificatesBuffer, CancellationToken cancelToken, DateTime? issuedAfter = null)
    {
        EnsureClientIsEnabled();

        if (certificatesBuffer == null)
        {
            string message = "Failed to download issued certificates - certificatesBuffer is null";
            _logger.LogError(message);
            throw new ArgumentNullException(nameof(certificatesBuffer), message);
        }

        _logger.LogTrace($"Setting up {typeof(ListCertificatesRequest).ToString()} with {this.ToString()}");

        ListCertificatesRequest request = new ListCertificatesRequest
        {
            ParentAsCaPoolName = new CaPoolName(_projectId, _locationId, _caPool),
        };

        if (issuedAfter != null)
        {
            Timestamp ts = Timestamp.FromDateTime(issuedAfter.Value.ToUniversalTime());
            _logger.LogDebug($"Filtering issued certificates by update_time >= {ts}");
            request.Filter = $"update_time >= {ts}";
        }

        _logger.LogTrace($"Setting up {typeof(CallSettings).ToString()} with provided {typeof(CancellationToken).ToString()} {this.ToString()}");
        CallSettings settings = CallSettings.FromCancellationToken(cancelToken);

        _logger.LogDebug($"Downloading all issued certificates from GCP CAS {this.ToString()}");
        PagedAsyncEnumerable<ListCertificatesResponse, Certificate> certificates = _client.ListCertificatesAsync(request, settings);

        int pageNumber = 0;
        int numberOfCertificates = 0;

        try
        {
            await foreach (var response in certificates.AsRawResponses())
            {
                if (response.Certificates == null)
                {
                    _logger.LogWarning($"GCP returned null certificate list for page number {pageNumber} - continuing {this.ToString()}");
                    continue;
                }

                foreach (Certificate certificate in response.Certificates)
                {
                    certificatesBuffer.Add(AnyCAPluginCertificateFromGCPCertificate(certificate));
                    numberOfCertificates++;
                    _logger.LogDebug($"Found Certificate with name {certificate.CertificateName.CertificateId} {this.ToString()}");
                }

                _logger.LogTrace($"Fetched page {pageNumber} - Next Page Token: {response.NextPageToken}");
                pageNumber++;
            }
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.ResourceExhausted)
        {
            _logger.LogError($"Rate limit exceeded while fetching certificates: {ex.Message}");
            throw;
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Certificate download operation was canceled.");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Unexpected error while fetching certificates: {ex.Message}");
            throw;
        }
        finally
        {
            certificatesBuffer.CompleteAdding();
            _logger.LogDebug($"Fetched {certificatesBuffer.Count} certificates from GCP over {pageNumber} pages.");
        }

        return numberOfCertificates;
    }



    /// <summary>
    /// Downloads a certificate with the specified <paramref name="certificateId"/> in PEM format and stores it in a <see cref="AnyCAPluginCertificate"/>.
    /// </summary>
    /// <param name="certificateId">
    /// The Certificate ID of the certificate to download.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as a <see cref="AnyCAPluginCertificate"/> containing the downloaded certificate.
    /// </returns>
    public async Task<AnyCAPluginCertificate> DownloadCertificate(string certificateId)
    {
        EnsureClientIsEnabled();

        _logger.LogDebug($"Downloading certificate with ID {certificateId} {this.ToString()}");

        _logger.LogTrace($"Setting up {typeof(GetCertificateRequest).ToString()} with {this.ToString()} and [certificateId={certificateId}]");
        GetCertificateRequest request = new GetCertificateRequest
        {
            Name = new CertificateName(_projectId, _locationId, _caPool, certificateId).ToString()
        };

        Certificate certificate = await _client.GetCertificateAsync(request);
        _logger.LogTrace("GetCertificateAsync succeeded");
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
            CARequestID = certificate.CertificateName.CertificateId,
            Certificate = certificate.PemCertificate,
            Status = (int)status,
            ProductID = productId,
            RevocationDate = revocationDate,
            RevocationReason = revocationReason,
        };
    }
    /// <summary>
    /// Enrolls a certificate using a configured <see cref="ICreateCertificateRequestBuilder"/> and returns the result.
    /// </summary>
    /// <param name="createCertificateRequestBuilder">
    /// The <see cref="ICreateCertificateRequestBuilder"/> to use for the enrollment. Must be configured before calling this method.
    /// </param>
    /// <param name="cancelToken">
    /// The <see cref="CancellationToken"/> to cancel the operation.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as an <see cref="EnrollmentResult"/> containing the result of the enrollment.
    /// </returns>
    public async Task<EnrollmentResult> Enroll(ICreateCertificateRequestBuilder createCertificateRequestBuilder, CancellationToken cancelToken)
    {
        try
        {
            EnsureClientIsEnabled();

            CreateCertificateRequest request = createCertificateRequestBuilder.Build(_locationId, _projectId, _caPool, _caId);

            _logger.LogDebug($"Creating Certificate in GCP CAS with ID {request.CertificateId} {this}");

            Certificate certificate = await _client.CreateCertificateAsync(request, cancelToken);

            _logger.LogDebug($"Created Certificate in GCP CAS with name {certificate.CertificateName} {this}");

            return new EnrollmentResult
            {
                CARequestID = certificate.CertificateName.CertificateId,
                Certificate = certificate.PemCertificate,
                Status = (int)EndEntityStatus.GENERATED,
                StatusMessage = $"Certificate with ID {certificate.CertificateName} has been issued",
            };
        }
        catch (RpcException rpcEx)
        {
            _logger.LogError(rpcEx, "RPC Exception while creating certificate.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = $"RPC Error: {rpcEx.Status.Detail}",
            };
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Certificate enrollment operation was canceled.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.CANCELLED,
                StatusMessage = "Certificate enrollment was canceled.",
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during certificate enrollment.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = $"Unexpected error: {ex.Message}",
            };
        }
    }

    /// <summary>
    /// Revokes a certificate with the specified <paramref name="certificateId"/> and <paramref name="reason"/>.
    /// </summary>
    /// <param name="certificateId">
    /// The Certificate ID of the certificate to revoke.
    /// </param>
    /// <param name="reason">
    /// The <see cref="RevocationReason"/> to revoke the certificate.
    /// </param>
    /// <returns></returns>
    public Task RevokeCertificate(string certificateId, RevocationReason reason)
    {
        EnsureClientIsEnabled();

        _logger.LogDebug($"Revoking certificate with ID {certificateId} for reason {reason.ToString()} {this.ToString()}");

        _logger.LogTrace($"Setting up {typeof(RevokeCertificateRequest).ToString()} with {this.ToString()} and [certificateId={certificateId}]");
        RevokeCertificateRequest request = new RevokeCertificateRequest
        {
            Name = new CertificateName(_projectId, _locationId, _caPool, certificateId).ToString(),
            Reason = reason,
        };
        return _client.RevokeCertificateAsync(request);
    }

    /// <summary>
    /// Retrieves the templates available in a GCP CAS project/region. 
    /// </summary>
    /// <returns>
    /// A <see cref="List{T}"/> of <see cref="string"/> containing the available <see cref="Google.Cloud.Security.PrivateCA.V1.CertificateTemplateName"/>s.
    /// </returns>
    public List<string> GetTemplates()
    {
        EnsureClientIsEnabled();

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

        _logger.LogDebug($"Adding the default certificate template called {GCPCASPluginConfig.NoTemplateName}");
        templateStrings.Add(GCPCASPluginConfig.NoTemplateName);

        return templateStrings;
    }

    private void EnsureClientIsEnabled()
    {
        if (!_clientIsEnabled)
        {
            _logger.LogWarning("GCPCASClient client is disabled - throwing");
            throw new Exception("GCPCASClient is disabled");
        }
    }
}
