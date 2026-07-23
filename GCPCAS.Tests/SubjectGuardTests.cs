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
/// Regression tests for the sync subject guard (issue #28). The 1.3.3 guard only ran
/// <c>new X509Name(true, netCert.Subject)</c>, which does not throw on a CN containing an odd-length run of
/// literal backslash bytes. Such a subject was therefore admitted, persisted, and then aborted Command's Full
/// Scan with "badly formatted directory string" when the gateway un-escaped and re-parsed it on its search
/// response.
///
/// Subject strings below are in .NET's <see cref="X509Certificate2.Subject"/> form, where literal backslash
/// bytes appear verbatim (empirically verified - .NET does not backslash-double them and quotes
/// separator-bearing values instead). These are pure unit tests and run under a plain <c>dotnet test</c>.
/// </summary>
public class SubjectGuardTests
{
    [Theory]
    // Well-formed subjects survive the round trip.
    [InlineData("CN=baseline-app-01.lab.test", true)]
    [InlineData("CN=wellformed.lab.test", true)]
    [InlineData("CN=host.lab.test, OU=PKI, O=Keyfactor Labs, C=US", true)]
    // shape1: CN ends in ONE literal backslash (odd run) -> gateway un-escapes to a dangling "\" and the
    // re-parse throws. This is the regression: must be rejected now (1.3.3 admitted it).
    [InlineData(@"CN=shape1.lab.test\", false)]
    // shape2: CN ends in TWO literal backslashes (even run) -> round-trips as a valid escaped pair. Survives,
    // matching the ticket, which saw only shape1 abort the scan.
    [InlineData(@"CN=shape2.lab.test\\", true)]
    // shape3: FOUR literal backslashes (even run) ahead of a real RDN separator -> survives.
    [InlineData(@"CN=shape3.lab.test\\\\, OU=PKI, O=Keyfactor Labs", true)]
    // Odd run in the middle of a value is just as unsafe as a trailing one.
    [InlineData(@"CN=sha\pe.lab.test", false)]
    [InlineData(@"CN=sha\\\pe.lab.test", false)]
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

    [Theory]
    [InlineData("CN=nobackslash.lab.test", false)]
    [InlineData(@"CN=one\backslash", true)]        // single -> odd
    [InlineData(@"CN=two\\backslash", false)]      // pair -> even
    [InlineData(@"CN=three\\\backslash", true)]    // three -> odd
    [InlineData(@"CN=four\\\\backslash", false)]   // four -> even
    [InlineData(@"CN=trailing\", true)]            // single trailing -> odd
    [InlineData(@"CN=a\b\c", true)]                // two separate single (odd) runs
    [InlineData(@"CN=a\\b\\c", false)]             // two separate pair (even) runs
    public void HasOddBackslashRun_DetectsOddRuns(string value, bool expected)
    {
        Assert.Equal(expected, GCPCASClient.HasOddBackslashRun(value));
    }

    [Fact]
    public void RealCertificate_WithTrailingBackslashCn_IsRejected()
    {
        // End-to-end shape check: build a real cert whose CN ends in a literal backslash byte (as GCP CAS
        // would accept and issue), then feed the .NET subject string through the guard. This is the exact
        // shape from the ticket (customer row 301651 / lab shape1).
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
