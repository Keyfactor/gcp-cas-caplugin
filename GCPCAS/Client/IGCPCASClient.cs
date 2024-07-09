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

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Google.Cloud.Security.PrivateCA.V1;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS.Client;

/// <summary>
/// <see cref="IGCPCASClient"/> exposes standard methods for the operations required by a full-featured AnyCA Gateway REST plugin.
/// </summary>
public interface IGCPCASClient
{
    /// <summary>
    /// Pings the CA to ensure it is reachable using the underlying authentication and connection information.
    /// Always returns if the CA is reachable or if the client is not enabled by the <see cref="Enable"/> method.
    /// </summary>
    /// <returns></returns>
    Task ValidateConnection();
    /// <summary>
    /// Enables the client to perform operations against the CA.
    /// </summary>
    /// <returns>
    /// Always returns a <see cref="Task"/>.
    /// </returns>
    Task Enable();
    /// <summary>
    /// Disables the client from performing operations against the CA.
    /// </summary>
    /// <returns>
    /// Always returns a <see cref="Task"/>.
    /// </returns>
    Task Disable();
    /// <summary>
    /// Returns the current enabled state of the <see cref="IGCPCASClient"/>.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> if the client is enabled; otherwise, <see langword="false"/>.
    /// </returns>
    bool IsEnabled();
    /// <summary>
    /// Retrieves the templates available in a GCP CAS project/region. 
    /// </summary>
    /// <returns>
    /// A <see cref="List{T}"/> of <see cref="string"/> containing the available <see cref="Google.Cloud.Security.PrivateCA.V1.CertificateTemplateName"/>s.
    /// </returns>
    List<string> GetTemplates();
    /// <summary>
    /// Downloads a certificate with the specified <paramref name="certificateId"/> in PEM format and stores it in a <see cref="AnyCAPluginCertificate"/>.
    /// </summary>
    /// <param name="certificateId">
    /// The Certificate ID of the certificate to download.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as a <see cref="AnyCAPluginCertificate"/> containing the downloaded certificate.
    /// </returns>
    Task<AnyCAPluginCertificate> DownloadCertificate(string certificateId);
    /// <summary>
    /// Downloads all certificates issued by the CA and stores them in a <see cref="BlockingCollection{T}"/>.
    /// </summary>
    /// <param name="certificatesBuffer">
    /// The <see cref="BlockingCollection{T}"/> to store the downloaded certificates.
    /// </param>
    /// <param name="cancelToken">
    /// The <see cref="CancellationToken"/> to cancel the operation.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as an <see cref="int"/> containing the number of downloaded certificates.
    /// </returns>
    Task<int> DownloadAllIssuedCertificates(BlockingCollection<AnyCAPluginCertificate> certificatesBuffer, CancellationToken cancelToken);
    /// <summary>
    /// Enrolls a certificate using a configured <see cref="ICreateCertificateRequestBuilder"/> and returns the result.
    /// </summary>
    /// <param name="certificateRequestBuilder">
    /// The <see cref="ICreateCertificateRequestBuilder"/> to use for the enrollment. Must be configured before calling this method.
    /// </param>
    /// <param name="cancelToken">
    /// The <see cref="CancellationToken"/> to cancel the operation.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as an <see cref="EnrollmentResult"/> containing the result of the enrollment.
    /// </returns>
    Task<EnrollmentResult> Enroll(ICreateCertificateRequestBuilder certificateRequestBuilder, CancellationToken cancelToken);
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
    Task RevokeCertificate(string certificateId, RevocationReason reason);
}
