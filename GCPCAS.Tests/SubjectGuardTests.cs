// Copyright 2025 Keyfactor
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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keyfactor.Extensions.CAPlugin.GCPCAS.Client;

namespace Keyfactor.Extensions.CAPlugin.GCPCASTests;

/// <summary>
/// Regression tests for the sync subject guard (issue #30). The 1.3.3 guard shipped against an older, lenient
/// BouncyCastle whose <c>X509Name</c> parse never threw on a CN ending in a dangling backslash, so such certs
/// were admitted, persisted, and then aborted Command's Full Scan with "badly formatted directory string" when
/// the gateway (on a stricter BouncyCastle) re-parsed the subject on its search response. The plugin now pins
/// the same BouncyCastle build as the gateway, so <see cref="GCPCASClient.SubjectSurvivesGatewayRoundTrip"/> is
/// a faithful reproduction of the gateway's accept/reject decision - it rejects only what the gateway rejects
/// and accepts everything it accepts (no structural heuristic).
///
/// Subject strings below are in .NET's <see cref="X509Certificate2.Subject"/> form. These are pure unit tests
/// and run under a plain <c>dotnet test</c>.
/// </summary>
public class SubjectGuardTests
{
    [Theory]
    // Well-formed subjects parse.
    [InlineData("CN=baseline-app-01.lab.test", true)]
    [InlineData("CN=wellformed.lab.test", true)]
    [InlineData("CN=host.lab.test, OU=PKI, O=Keyfactor Labs, C=US", true)]
    // shape1: CN ends in ONE dangling backslash -> BouncyCastle throws. The regression: must be rejected now
    // (the lenient 1.3.3 BouncyCastle admitted it).
    [InlineData(@"CN=shape1.lab.test\", false)]
    // A dangling backslash right before a real RDN separator is rejected the same way.
    [InlineData(@"CN=host.lab.test\, OU=PKI", false)]
    // shape2 / shape3: TWO and FOUR backslashes are valid escaped pairs -> accepted, matching the lab
    // reproduction, which saw only shape1 abort the scan.
    [InlineData(@"CN=shape2.lab.test\\", true)]
    [InlineData(@"CN=shape3.lab.test\\\\, OU=PKI, O=Keyfactor Labs", true)]
    // NOT false positives: a backslash+two-hex is a valid RFC 4514 hex escape, and an escaped comma is a valid
    // escaped special. These synced fine before and must keep syncing - the old odd-run heuristic wrongly
    // skipped them.
    [InlineData(@"CN=a\bc", true)]
    [InlineData(@"CN=a\,b", true)]
    // A bare unescaped separator yields a malformed second RDN, which BouncyCastle rejects. (.NET quotes such
    // values rather than emitting this, but the guard rejects it regardless.)
    [InlineData("CN=a,b", false)]
    public void SubjectSurvivesGatewayRoundTrip_ClassifiesSubjects(string dotNetSubject, bool expectedSurvives)
    {
        bool survives = GCPCASClient.SubjectSurvivesGatewayRoundTrip(dotNetSubject, out string failureReason);

        Assert.Equal(expectedSurvives, survives);
        if (expectedSurvives)
        {
            Assert.Null(failureReason);
        }
        else
        {
            Assert.False(string.IsNullOrEmpty(failureReason));
        }
    }

    [Fact]
    public void RealCertificate_WithTrailingBackslashCn_IsRejected()
    {
        // End-to-end shape check: build a real cert whose CN ends in a literal backslash byte (as GCP CAS
        // would accept and issue), then feed the .NET subject string through the guard. This is the exact
        // shape from the lab reproduction (shape1).
        string pem = SelfSignedPemWithCommonName(@"shape1.lab.test\");
        using X509Certificate2 cert = X509Certificate2.CreateFromPem(pem);

        // Sanity: .NET renders the single literal backslash verbatim (not doubled).
        Assert.EndsWith(@"\", cert.Subject);
        Assert.DoesNotContain(@"\\", cert.Subject);

        Assert.False(GCPCASClient.SubjectSurvivesGatewayRoundTrip(cert.Subject, out string failureReason));
        Assert.False(string.IsNullOrEmpty(failureReason));
    }

    [Fact]
    public void RealCertificate_WithWellFormedCn_IsAccepted()
    {
        string pem = SelfSignedPemWithCommonName("baseline-app-01.lab.test");
        using X509Certificate2 cert = X509Certificate2.CreateFromPem(pem);

        Assert.True(GCPCASClient.SubjectSurvivesGatewayRoundTrip(cert.Subject, out string failureReason));
        Assert.Null(failureReason);
    }

    private static string SelfSignedPemWithCommonName(string commonNameValue)
    {
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(commonNameValue);
        X500DistinguishedName subject = builder.Build();

        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return cert.ExportCertificatePem();
    }
}
