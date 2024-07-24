// Copyright 2024 Keyfactor
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

namespace Keyfactor.Extensions.CAPlugin.GCPCASTests;

public sealed class IntegrationTestingFact : FactAttribute
{
    public string ProjectId { get; private set; }
    public string LocationId { get; private set; }
    public string CAPool { get; private set; }
    public string CAId { get; private set; }

    public IntegrationTestingFact()
    {
        ProjectId = Environment.GetEnvironmentVariable("GCP_PROJECT_ID") ?? string.Empty;
        LocationId = Environment.GetEnvironmentVariable("GCP_LOCATION_ID") ?? string.Empty;
        CAPool = Environment.GetEnvironmentVariable("GCP_CAS_CAPOOL") ?? string.Empty;
        CAId = Environment.GetEnvironmentVariable("GCP_CAS_CAID") ?? string.Empty;

        if (string.IsNullOrEmpty(ProjectId) || string.IsNullOrEmpty(LocationId) || string.IsNullOrEmpty(CAPool) || string.IsNullOrEmpty(CAId))
        {
            Skip = "Integration testing environment variables are not set - Skipping test";
        }
    }
}
