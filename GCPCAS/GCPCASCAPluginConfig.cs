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

using System.Collections.Generic;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS;

public class GCPCASPluginConfig
{
    // The GCP CAS API doesn't require certificate templates - always give the user the option
    // to use the default template which is the same as the no-template name
    public const string NoTemplateName = "Default";
    public const int DefaultCertificateLifetime = 365;

    public class ConfigConstants
    {
        public const string ProjectId = "ProjectId";
        public const string LocationId = "LocationId";
        public const string CAPool = "CAPool";
        public const string CAId = "CAId";
        public const string Enabled = "Enabled";
    }

    public class Config
    {
        public string ProjectId { get; set; }
        public string LocationId { get; set; }
        public string CAPool { get; set; }
        public string CAId { get; set; }
        public bool Enabled { get; set; }
    }

    public static class EnrollmentConfigConstants
    {
    }

    public class EnrollmentParameters
    {
        public int CertificateValidityDays { get; set; }
    }

    public static Dictionary<string, PropertyConfigInfo> GetPluginAnnotations()
    {
        return new Dictionary<string, PropertyConfigInfo>()
        {
            // TODO make these comments better - they were copied from SPIRE
            [ConfigConstants.LocationId] = new PropertyConfigInfo()
            {
                Comments = "The GCP location ID where the project containing the target GCP CAS CA is located. For example, 'us-central1'.",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
            [ConfigConstants.ProjectId] = new PropertyConfigInfo()
            {
                Comments = "The GCP project ID where the target GCP CAS CA is located",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
            [ConfigConstants.CAPool] = new PropertyConfigInfo()
            {
                Comments = "The CA Pool ID in GCP CAS to use for certificate operations. If the CA Pool has resource name `projects/my-project/locations/us-central1/caPools/my-pool`, this field should be set to `my-pool`",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
            [ConfigConstants.CAId] = new PropertyConfigInfo()
            {
                Comments = "The CA ID of a CA in the same CA Pool as CAPool. For example, to issue certificates from a CA with resource name `projects/my-project/locations/us-central1/caPools/my-pool/certificateAuthorities/my-ca`, this field should be set to `my-ca`.",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
            [ConfigConstants.Enabled] = new PropertyConfigInfo()
            {
                Comments = "Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available.",
                Hidden = false,
                DefaultValue = true,
                Type = "Boolean"
            },
        };
    }

    public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
    {
        return new Dictionary<string, PropertyConfigInfo>()
        {

        };
    }
}

