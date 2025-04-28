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

using System.Collections.Generic;
using Google.Cloud.Security.PrivateCA.V1;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS.Client;

public interface ICreateCertificateRequestBuilder
{
    ICreateCertificateRequestBuilder WithCsr(string csr);
    ICreateCertificateRequestBuilder WithSubject(string subject);
    ICreateCertificateRequestBuilder WithSans(Dictionary<string, string[]> san);
    ICreateCertificateRequestBuilder WithEnrollmentProductInfo(EnrollmentProductInfo productInfo);
    ICreateCertificateRequestBuilder WithRequestFormat(RequestFormat requestFormat);
    ICreateCertificateRequestBuilder WithEnrollmentType(EnrollmentType enrollmentType);
    CreateCertificateRequest Build(string locationId, string projectId, string caPool,string caId);
}
