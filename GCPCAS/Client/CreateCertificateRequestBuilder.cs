/*
Copyright © 2025 Keyfactor

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
using Google.Cloud.Security.PrivateCA.V1;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using X509Extension = Google.Cloud.Security.PrivateCA.V1.X509Extension;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS.Client
{
    public class CreateCertificateRequestBuilder : ICreateCertificateRequestBuilder
    {
        ILogger _logger = LogHandler.GetClassLogger<CreateCertificateRequestBuilder>();

        private string _csrString;
        private string _certificateTemplate;
        private string _subject;
        private List<string> _dnsSans;
        private int _certificateLifetimeDays = GCPCASPluginConfig.DefaultCertificateLifetime;

        // Store additional extensions
        private List<Google.Cloud.Security.PrivateCA.V1.X509Extension> _additionalExtensions = new List<X509Extension>();

        public ICreateCertificateRequestBuilder WithCsr(string csr)
        {
            _logger.MethodEntry();
            _csrString = csr;
            _logger.MethodExit();
            return this;
        }

        public ICreateCertificateRequestBuilder WithEnrollmentProductInfo(EnrollmentProductInfo productInfo)
        {
            _logger.MethodEntry();
            if (productInfo.ProductID == GCPCASPluginConfig.NoTemplateName)
            {
                _certificateTemplate = null;
                _logger.LogDebug($"{GCPCASPluginConfig.NoTemplateName} template selected.");
            }
            else
            {
                _logger.LogDebug($"Configuring request with {productInfo.ProductID} Certificate Template.");
                _certificateTemplate = productInfo.ProductID;
            }

            if (productInfo.ProductParameters != null)
            {
                _logger.LogDebug($"Parsing Custom Enrollment Parameters");

                if (productInfo.ProductParameters.TryGetValue(GCPCASPluginConfig.EnrollmentParametersConstants.CertificateLifetimeDays, out string certificateLifetimeDaysString))
                {
                    if (int.TryParse(certificateLifetimeDaysString, out _certificateLifetimeDays))
                    {
                        _logger.LogDebug($"Using validity of {_certificateLifetimeDays} days.");
                    }
                }

                _logger.LogTrace($"Looping through extensions for Auto Enrollment Params");
                // Extract Additional Extensions
                foreach (var param in productInfo.ProductParameters)
                {
                    if (param.Key.StartsWith("ExtensionData"))
                    {
                        string oid = param.Key.Replace("ExtensionData-", ""); // Extract OID from key
                        string base64Value = param.Value;

                        _logger.LogTrace($"Loggin oid and value {oid} {base64Value}");

                        var extension = CreateX509Extension(oid, base64Value);
                        if (extension != null)
                        {
                            _logger.LogTrace($"Adding Extension");
                            _additionalExtensions.Add(extension);
                        }
                    }
                }
            }
            _logger.MethodExit();
            return this;
        }

        public ICreateCertificateRequestBuilder WithEnrollmentType(EnrollmentType enrollmentType)
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return this;
        }

        public ICreateCertificateRequestBuilder WithRequestFormat(RequestFormat requestFormat)
        {
            _logger.MethodEntry();
            if (requestFormat != RequestFormat.PKCS10)
            {
                throw new Exception($"Unsupported CSR format: {requestFormat}");
            }
            _logger.MethodExit();
            return this;
        }

        public ICreateCertificateRequestBuilder WithSans(Dictionary<string, string[]> san)
        {
            _logger.MethodEntry();
            _dnsSans = new List<string>();

            if (san != null && san.Count > 0)
            {
                foreach (var key in san.Keys)
                {
                    _logger.LogTrace($"San Value {san[key]}");
                    _dnsSans.AddRange(san[key]);
                }

                _logger.LogTrace($"Found {_dnsSans.Count} SANs");
            }
            _logger.MethodExit();
            return this;
        }

        public ICreateCertificateRequestBuilder WithSubject(string subject)
        {
            _logger.MethodEntry();
            if (!string.IsNullOrWhiteSpace(subject))
            {
                _logger.LogTrace($"Found subject {subject}");
                _subject = subject;
            }
            _logger.MethodExit();
            return this;
        }

        public CreateCertificateRequest Build(string locationId, string projectId, string caPool, string caId)
        {
            _logger.MethodEntry();

            CaPoolName caPoolName = new CaPoolName(projectId, locationId, caPool);

            CertificateConfig certConfig = new CertificateConfig();
            certConfig.SubjectConfig = new CertificateConfig.Types.SubjectConfig();

            if (!string.IsNullOrEmpty(_subject))
            {
                _logger.LogTrace($"Subject {_subject}");
                Subject parsedSubject = SubjectParser.ParseFromString(_subject);
                _logger.LogTrace($"Parsed Subject {JsonConvert.SerializeObject(parsedSubject)}");
                certConfig.SubjectConfig.Subject = parsedSubject;
            }

            if (_dnsSans.Count > 0)
            {
                _logger.LogTrace($"Getting Subject Alt Names");
                SubjectAltNames parsedSubjectAltNames = SubjectAltNamesParser.ParseFromDnsList(_dnsSans);
                _logger.LogTrace($"Parsed AltNames {JsonConvert.SerializeObject(parsedSubjectAltNames)}");
                certConfig.SubjectConfig.SubjectAltName = parsedSubjectAltNames;
            }

            if (!string.IsNullOrEmpty(_csrString))
            {
                _logger.LogTrace($"Putting Csr in public key {_csrString}");
                ByteString csrByteString = ByteString.CopyFromUtf8(_csrString);

                certConfig.PublicKey = new PublicKey
                {
                    Format = PublicKey.Types.KeyFormat.Pem,
                    Key = csrByteString
                };
                _logger.LogTrace($"Serialized PublicKey {JsonConvert.SerializeObject(certConfig.PublicKey)}");
            }

            certConfig.X509Config = new X509Parameters();

            // Add Additional Extensions if present
            if (_additionalExtensions.Count > 0)
            {
                _logger.LogTrace($"Adding additional Extensions");
                _logger.LogTrace($"Serialized Additional Extensions {JsonConvert.SerializeObject(_additionalExtensions)}");
                certConfig.X509Config.AdditionalExtensions.AddRange(_additionalExtensions);
            }

            _logger.LogTrace($"Creating The Certificate");
            Certificate theCertificate = new Certificate
            {
                Lifetime = Duration.FromTimeSpan(new TimeSpan(_certificateLifetimeDays, 0, 0, 0)),
                Config = certConfig
            };
            _logger.LogTrace($"Serialized theCertificate {JsonConvert.SerializeObject(theCertificate)}");

            if (!string.IsNullOrWhiteSpace(_certificateTemplate))
            {
                CertificateTemplateName template = new CertificateTemplateName(projectId, locationId, _certificateTemplate);
                theCertificate.CertificateTemplate = template.ToString();
                _logger.LogTrace($"Serialized theCertificate after template {JsonConvert.SerializeObject(theCertificate)}");
            }

            CreateCertificateRequest theRequest = new CreateCertificateRequest
            {
                ParentAsCaPoolName = caPoolName,
                CertificateId = Guid.NewGuid().ToString(),
                Certificate = theCertificate,
            };

            _logger.MethodExit();
            return theRequest;
        }

        /// <summary>
        /// Creates a properly formatted X509Extension from an OID and Base64-encoded value.
        /// </summary>
        private X509Extension CreateX509Extension(string oid, string base64EncodedValue)
        {
            try
            {
                _logger.MethodEntry();
                // Decode the Base64-encoded value
                byte[] decodedBytes = Convert.FromBase64String(base64EncodedValue);
                _logger.MethodExit();
                // Create the X.509 extension with the correct format
                return new X509Extension
                {
                    ObjectId = new ObjectId
                    {
                        ObjectIdPath = { oid.Split('.').Select(int.Parse) }  // Convert OID to int array
                    },
                    Value = ByteString.CopyFrom(decodedBytes)  // Store properly DER-encoded value
                };
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error processing extension {oid}: {ex.Message}");
                return null;
            }
        }

    }
}
