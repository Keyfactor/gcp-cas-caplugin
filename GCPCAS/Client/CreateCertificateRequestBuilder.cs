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
using System.Collections.Generic;
using System.Text.Json;
using Google.Cloud.Security.PrivateCA.V1;
using Google.Protobuf.WellKnownTypes;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS.Client;

public class CreateCertificateRequestBuilder : ICreateCertificateRequestBuilder
{
    ILogger _logger = LogHandler.GetClassLogger<CreateCertificateRequestBuilder>();

    private string _csrString;
    private string _certificateTemplate;
    private int _certificateLifetimeDays = GCPCASPluginConfig.DefaultCertificateLifetime;

    public ICreateCertificateRequestBuilder WithCsr(string csr)
    {
        _csrString = csr;
        return this;
    }

    public ICreateCertificateRequestBuilder WithEnrollmentProductInfo(EnrollmentProductInfo productInfo)
    {
        if (productInfo.ProductID == GCPCASPluginConfig.NoTemplateName)
        {
            _certificateTemplate = null;
            _logger.LogDebug($"{GCPCASPluginConfig.NoTemplateName} template selected - Certificate enrollment will defer to the baseline values and policy configured by the CA Pool.");
        }
        else
        {
            _logger.LogDebug($"Configuring CreateCertificateRequest with the {productInfo.ProductID} Certificate Template.");
            _certificateTemplate = productInfo.ProductID;
        }

        _logger.LogDebug($"Parsing Custom Enrollment Parameters");
        var parametersJson = JsonSerializer.Serialize(productInfo.ProductParameters);
        GCPCASPluginConfig.EnrollmentParameters enrollmentParameters = JsonSerializer.Deserialize<GCPCASPluginConfig.EnrollmentParameters>(parametersJson);

        if (enrollmentParameters.CertificateValidityDays > 0)
        {
            _logger.LogDebug($"Found non-null CertificateValidityDays Custom Enrollment parameter - Configuring CreateCertificateRequest to use a validity of {enrollmentParameters.CertificateValidityDays} days.");
            _certificateLifetimeDays = enrollmentParameters.CertificateValidityDays;
        }

        return this;
    }

    public ICreateCertificateRequestBuilder WithEnrollmentType(EnrollmentType enrollmentType)
    {
        // Not used
        return this;
    }

    public ICreateCertificateRequestBuilder WithRequestFormat(RequestFormat requestFormat)
    {
        // Not used
        return this;
    }

    public ICreateCertificateRequestBuilder WithSans(Dictionary<string, string[]> san)
    {
        // Not used
        return this;
    }

    public ICreateCertificateRequestBuilder WithSubject(string subject)
    {
        // Not used
        _logger.LogTrace($"Found Subject {subject} - Using CSR value");
        return this;
    }

    public CreateCertificateRequest Build(string locationId, string projectId, string caPool, string caId)
    {
        _logger.LogDebug("Constructing CreateCertificateRequest");
        CaPoolName caPoolName = new CaPoolName(projectId, locationId, caPool);

        Certificate theCertificate = new Certificate
        {
            PemCsr = _csrString,
            Lifetime = Duration.FromTimeSpan(new TimeSpan(_certificateLifetimeDays, 0, 0, 0)),
        };

        if (!string.IsNullOrWhiteSpace(_certificateTemplate))
        {
            CertificateTemplateName template = new CertificateTemplateName(projectId, locationId, _certificateTemplate);
            theCertificate.CertificateTemplate = template.ToString();
        }

        CreateCertificateRequest theRequest = new CreateCertificateRequest
        {
            ParentAsCaPoolName = caPoolName,
            CertificateId = Guid.NewGuid().ToString(),
            Certificate = theCertificate,
        };

        return theRequest;
    }
}

