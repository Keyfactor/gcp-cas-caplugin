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
using System.Linq;
using System.Text;
using System.Text.Json;
using Google.Cloud.Security.PrivateCA.V1;
using Google.Protobuf;
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
	private string _subject;
	private List<string> _dnsSans;
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
            _logger.LogDebug($"Configuring {typeof(CreateCertificateRequest).ToString()} with the {productInfo.ProductID} Certificate Template.");
            _certificateTemplate = productInfo.ProductID;
        }

        if (productInfo.ProductParameters != null)
        {
            _logger.LogDebug($"Parsing Custom Enrollment Parameters");

            if (productInfo.ProductParameters.TryGetValue(GCPCASPluginConfig.EnrollmentParametersConstants.CertificateLifetimeDays, out string certificateLifetimeDaysString))
            {
                if (int.TryParse(certificateLifetimeDaysString, out _certificateLifetimeDays))
                {
                    _logger.LogDebug($"Found non-null CertificateValidityDays Custom Enrollment parameter - Configured CreateCertificateRequest to use a validity of {_certificateLifetimeDays} days.");
                }
                else
                {
                    string error = $"Unable to parse integer value from {GCPCASPluginConfig.EnrollmentParametersConstants.CertificateLifetimeDays} Custom Enrollment Parameter";
                    _logger.LogError(error);
                    throw new ArgumentException(error);
                }

            }
        }

        return this;
    }

    public ICreateCertificateRequestBuilder WithEnrollmentType(EnrollmentType enrollmentType)
    {
        if (enrollmentType != EnrollmentType.New) _logger.LogTrace($"{typeof(EnrollmentType).ToString()} is {enrollmentType.ToString()} - Ignoring and treating enrollment as {EnrollmentType.New.ToString()}");
        return this;
    }

    public ICreateCertificateRequestBuilder WithRequestFormat(RequestFormat requestFormat)
    {
        if (requestFormat != RequestFormat.PKCS10)
        {
            string error = $"AnyCA Gateway REST framework provided CSR in unsupported format: {requestFormat.ToString()}";
            _logger.LogError(error);
            throw new Exception(error);
        }
        return this;
    }

    public ICreateCertificateRequestBuilder WithSans(Dictionary<string, string[]> san)
    {
		_dnsSans = new List<string>();
		if (san != null & san.Count > 0)
		{			
			var dnsKeys = san.Keys.Where(k => k.Contains("dns", StringComparison.OrdinalIgnoreCase)).ToList();
			foreach (var key in dnsKeys)
			{
				_dnsSans.AddRange(san[key]);
			}
			_logger.LogTrace($"Found {_dnsSans.Count} SANs");
		}
		else
		{
			_logger.LogTrace($"Found no external SANs - Using SANs from CSR");
		}
        return this;
    }

    public ICreateCertificateRequestBuilder WithSubject(string subject)
    {
		if (!string.IsNullOrWhiteSpace(subject))
		{
			_logger.LogTrace($"Found non-empty subject {subject}");
			_subject = subject;
		}
        return this;
    }

    public CreateCertificateRequest Build(string locationId, string projectId, string caPool, string caId)
    {
        _logger.LogDebug("Constructing CreateCertificateRequest");
        CaPoolName caPoolName = new CaPoolName(projectId, locationId, caPool);

		CertificateConfig certConfig = new CertificateConfig();
		certConfig.SubjectConfig = new CertificateConfig.Types.SubjectConfig();

		if (!string.IsNullOrEmpty(_subject))
		{
            Subject parsedSubject = SubjectParser.ParseFromString(_subject);
            certConfig.SubjectConfig.Subject = parsedSubject;
		}

        if (_dnsSans.Count > 0)
		{
            SubjectAltNames parsedSubjectAltNames = SubjectAltNamesParser.ParseFromDnsList(_dnsSans);
            certConfig.SubjectConfig.SubjectAltName = parsedSubjectAltNames;
        }

        if(!string.IsNullOrEmpty(_csrString))
        {
            // Convert CSR string to Base64
            //string csrBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(_csrString));

            // Convert Base64 CSR to ByteString
            //ByteString csrByteString = ByteString.CopyFromUtf8(csrBase64);

            ByteString csrByteString = ByteString.CopyFromUtf8(_csrString);

            certConfig.PublicKey = new PublicKey
            {
                Format= PublicKey.Types.KeyFormat.Pem,
                Key= csrByteString
            };
        }

        certConfig.X509Config = new X509Parameters
        {
            KeyUsage = new KeyUsage
            {
                BaseKeyUsage = new KeyUsage.Types.KeyUsageOptions
                {
                    DigitalSignature = true,
                    KeyEncipherment = true
                },
                ExtendedKeyUsage = new KeyUsage.Types.ExtendedKeyUsageOptions
                {
                    ClientAuth = true //TODO find a way to determine client vs server
                }
            },
            CaOptions = new X509Parameters.Types.CaOptions
            {
                IsCa = false
            }
        };

        Certificate theCertificate = new Certificate
        {
            Lifetime = Duration.FromTimeSpan(new TimeSpan(_certificateLifetimeDays, 0, 0, 0)),
			Config = certConfig
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

