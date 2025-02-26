using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Google.Cloud.Security.PrivateCA.V1;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
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
            _csrString = csr;
            return this;
        }

        public ICreateCertificateRequestBuilder WithEnrollmentProductInfo(EnrollmentProductInfo productInfo)
        {
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

                // Extract Additional Extensions
                foreach (var param in productInfo.ProductParameters)
                {
                    if (param.Key.StartsWith("ExtensionData"))
                    {
                        string oid = param.Key.Replace("ExtensionData-", ""); // Extract OID from key
                        string base64Value = param.Value;

                        var extension = CreateX509Extension(oid, base64Value);
                        if (extension != null)
                        {
                            _additionalExtensions.Add(extension);
                        }
                    }
                }
            }

            return this;
        }

        public ICreateCertificateRequestBuilder WithEnrollmentType(EnrollmentType enrollmentType)
        {
            return this;
        }

        public ICreateCertificateRequestBuilder WithRequestFormat(RequestFormat requestFormat)
        {
            if (requestFormat != RequestFormat.PKCS10)
            {
                throw new Exception($"Unsupported CSR format: {requestFormat}");
            }
            return this;
        }

        public ICreateCertificateRequestBuilder WithSans(Dictionary<string, string[]> san)
        {
            _dnsSans = new List<string>();

            if (san != null && san.Count > 0)
            {
                foreach (var key in san.Keys)
                {
                    _dnsSans.AddRange(san[key]);
                }

                _logger.LogTrace($"Found {_dnsSans.Count} SANs");
            }
            return this;
        }

        public ICreateCertificateRequestBuilder WithSubject(string subject)
        {
            if (!string.IsNullOrWhiteSpace(subject))
            {
                _logger.LogTrace($"Found subject {subject}");
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

            if (!string.IsNullOrEmpty(_csrString))
            {
                ByteString csrByteString = ByteString.CopyFromUtf8(_csrString);

                certConfig.PublicKey = new PublicKey
                {
                    Format = PublicKey.Types.KeyFormat.Pem,
                    Key = csrByteString
                };
            }

            certConfig.X509Config = new X509Parameters();

            // Add Additional Extensions if present
            if (_additionalExtensions.Count > 0)
            {
                certConfig.X509Config.AdditionalExtensions.AddRange(_additionalExtensions);
            }

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

        /// <summary>
        /// Creates a properly formatted X509Extension from an OID and Base64-encoded value.
        /// </summary>
        private X509Extension CreateX509Extension(string oid, string base64EncodedValue)
        {
            try
            {
                // Decode the Base64-encoded value
                byte[] decodedBytes = Convert.FromBase64String(base64EncodedValue);

                //// Wrap the decoded bytes in an ASN.1 Octet String
                //Asn1Encodable asn1Encodable = new DerOctetString(decodedBytes);
                //byte[] derEncodedValue = decodedBytes.GetEncoded();  // Ensure DER encoding

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
