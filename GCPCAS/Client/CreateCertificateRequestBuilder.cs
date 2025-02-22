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
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Google.Cloud.Security.PrivateCA.V1;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Keyfactor.PKI.PEM;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using static Google.Cloud.Security.PrivateCA.V1.KeyUsage.Types;
using static Google.Cloud.Security.PrivateCA.V1.X509Parameters.Types;



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

    public static X509Parameters ExtractX509ParametersFromCsr(byte[] csrData)
    {
        var csr = new Pkcs10CertificationRequest(csrData);
        var attributes = csr.GetCertificationRequestInfo().Attributes;

        var x509Params = new X509Parameters();

        foreach (var asn1Attribute in attributes)
        {
            var attribute = Org.BouncyCastle.Asn1.Pkcs.AttributePkcs.GetInstance(asn1Attribute);

            if (attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
            {
                var extensionValues = attribute.AttrValues;
                var extensions = X509Extensions.GetInstance(extensionValues[0]);

                foreach (DerObjectIdentifier oid in extensions.GetExtensionOids())
                {
                    var ext = extensions.GetExtension(oid);
                    if (ext == null || ext.GetParsedValue() == null)
                    {
                        continue; // ❌ Skip null extensions
                    }

                    // ✅ Key Usage
                    if (oid.Id.Equals(X509Extensions.KeyUsage.Id))
                    {
                        var keyUsageBits = (DerBitString)ext.GetParsedValue();
                        var bcKeyUsage = new Org.BouncyCastle.Asn1.X509.KeyUsage(keyUsageBits.IntValue);

                        x509Params.KeyUsage ??= new Google.Cloud.Security.PrivateCA.V1.KeyUsage(); // Ensure initialized
                        x509Params.KeyUsage.BaseKeyUsage = new Google.Cloud.Security.PrivateCA.V1.KeyUsage.Types.KeyUsageOptions
                        {
                            DigitalSignature = (bcKeyUsage.IntValue & Org.BouncyCastle.Asn1.X509.KeyUsage.DigitalSignature) != 0,
                            KeyEncipherment = (bcKeyUsage.IntValue & Org.BouncyCastle.Asn1.X509.KeyUsage.KeyEncipherment) != 0
                        };
                    }

                    // ✅ Extended Key Usage
                    else if (oid.Id.Equals(X509Extensions.ExtendedKeyUsage.Id))
                    {
                        var extKeyUsage = ExtendedKeyUsage.GetInstance(ext.GetParsedValue());
                        if (extKeyUsage != null)
                        {
                            var extendedKeyUsageOptions = new Google.Cloud.Security.PrivateCA.V1.KeyUsage.Types.ExtendedKeyUsageOptions
                            {
                                ClientAuth = extKeyUsage.HasKeyPurposeId(KeyPurposeID.id_kp_clientAuth),
                                ServerAuth = extKeyUsage.HasKeyPurposeId(KeyPurposeID.id_kp_serverAuth),
                                CodeSigning = extKeyUsage.HasKeyPurposeId(KeyPurposeID.id_kp_codeSigning),
                                EmailProtection = extKeyUsage.HasKeyPurposeId(KeyPurposeID.id_kp_codeSigning)
                            };

                            x509Params.KeyUsage ??= new Google.Cloud.Security.PrivateCA.V1.KeyUsage(); // Ensure initialized
                            x509Params.KeyUsage.ExtendedKeyUsage = extendedKeyUsageOptions;
                        }
                    }

                    // ✅ Subject Key Identifier (SKI)
                    //else if (oid.Id.Equals(X509Extensions.SubjectKeyIdentifier.Id))
                    //{
                    //    var skiExt = SubjectKeyIdentifier.GetInstance(ext.GetParsedValue());
                    //    if (skiExt != null && skiExt.GetKeyIdentifier() != null)
                    //    {
                    //        x509Params.AdditionalExtensions.Add(new Google.Cloud.Security.PrivateCA.V1.X509Extension
                    //        {
                    //            ObjectId = new Google.Cloud.Security.PrivateCA.V1.ObjectId
                    //            {
                    //                ObjectIdPath = { oid.Id.Split('.').Select(int.Parse) }
                    //            },
                    //            Value = Google.Protobuf.ByteString.CopyFrom(skiExt.GetKeyIdentifier())
                    //        });
                    //    }
                    //}

                    // ✅ Basic Constraints (CA option)
                    else if (oid.Id.Equals(X509Extensions.BasicConstraints.Id))
                    {
                        var basicConstraints = BasicConstraints.GetInstance(ext.GetParsedValue());
                        if (basicConstraints != null)
                        {
                            x509Params.CaOptions = new CaOptions { IsCa = basicConstraints.IsCA() };
                        }
                    }

                    // ✅ Certificate Policies
                    else if (oid.Id.Equals(X509Extensions.CertificatePolicies.Id))
                    {
                        var policies = CertificatePolicies.GetInstance(ext.GetParsedValue());
                        if (policies != null)
                        {
                            var policyObjectIds = policies.GetPolicyInformation()
                                .Select(policy => new Google.Cloud.Security.PrivateCA.V1.ObjectId
                                {
                                    ObjectIdPath = { policy.PolicyIdentifier.Id.Split('.').Select(int.Parse) }
                                }).ToList();

                            x509Params.PolicyIds.AddRange(policyObjectIds);
                        }
                    }

                    // ✅ Authority Information Access (OCSP Servers)
                    else if (oid.Id.Equals(X509Extensions.AuthorityInfoAccess.Id))
                    {
                        var aia = AuthorityInformationAccess.GetInstance(ext.GetParsedValue());
                        if (aia != null)
                        {
                            foreach (var accessDescription in aia.GetAccessDescriptions())
                            {
                                if (accessDescription.AccessMethod.Equals(Org.BouncyCastle.Asn1.X509.AccessDescription.IdADOcsp))
                                {
                                    x509Params.AiaOcspServers.Add(accessDescription.AccessLocation.ToString());
                                }
                            }
                        }
                    }

                    // ✅ Name Constraints
                    else if (oid.Id.Equals(X509Extensions.NameConstraints.Id))
                    {
                        x509Params.NameConstraints = new Google.Cloud.Security.PrivateCA.V1.X509Parameters.Types.NameConstraints();
                    }

                    else
                    {
                        var parsedValue = ext.GetParsedValue();
                        if (parsedValue != null)
                        {
                            x509Params.AdditionalExtensions.Add(new Google.Cloud.Security.PrivateCA.V1.X509Extension
                            {
                                ObjectId = new Google.Cloud.Security.PrivateCA.V1.ObjectId
                                {
                                    ObjectIdPath = { oid.Id.Split('.').Select(int.Parse) }
                                },
                                Value = Google.Protobuf.ByteString.CopyFrom(parsedValue.GetEncoded())
                            });
                        }
                    }
                }
            }
        }

        return x509Params;
    }


    public static byte[] ConvertCsrToByteArray(string csrPem)
    {
        // Remove PEM headers and newlines
        string base64Csr = Regex.Replace(csrPem, @"-----BEGIN CERTIFICATE REQUEST-----|-----END CERTIFICATE REQUEST-----|\s+", "");

        // Convert Base64 string to byte array
        return Convert.FromBase64String(base64Csr);
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

        //If Email in the subject move it to SAN, Google does not support email in subject
        Match match = Regex.Match(_subject, @"E=([^,]+)", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            string email = match.Groups[1].Value.Trim();
            _dnsSans.Add(email);
        }

        if (_dnsSans.Count > 0)
        {
            SubjectAltNames parsedSubjectAltNames = SubjectAltNamesParser.ParseFromDnsList(_dnsSans);
            certConfig.SubjectConfig.SubjectAltName = parsedSubjectAltNames;
        }
        if (!string.IsNullOrEmpty(_csrString))
        {
            Pkcs10CertificationRequest certificationRequest = new Pkcs10CertificationRequest(PemUtilities.PEMToDER(_csrString));

            ByteString csrByteString = ByteString.CopyFromUtf8(_csrString);

            certConfig.PublicKey = new PublicKey
            {
                Format = PublicKey.Types.KeyFormat.Pem,
                Key = csrByteString
            };
        }

        byte[] csrBytes = ConvertCsrToByteArray(_csrString);

        // Call the function with the byte array
        X509Parameters x509Params = ExtractX509ParametersFromCsr(csrBytes);

        certConfig.X509Config = x509Params;

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

