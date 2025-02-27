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
using System.Net;
using Google.Cloud.Security.PrivateCA.V1;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS
{

    public class SubjectAltNamesParser
    {
        public static SubjectAltNames ParseFromDnsList(List<string> dnsSans)
        {
            if (dnsSans == null || dnsSans.Count == 0)
                return new SubjectAltNames();

            var subjectAltNames = new SubjectAltNames();

            foreach (var entry in dnsSans)
            {
                if (string.IsNullOrWhiteSpace(entry))
                    continue;

                if (entry.Contains("@"))  // Email detection
                {
                    subjectAltNames.EmailAddresses.Add(entry);
                }
                else if (Uri.IsWellFormedUriString(entry, UriKind.Absolute))  // URI detection
                {
                    subjectAltNames.Uris.Add(entry);
                }
                else if (IPAddress.TryParse(entry, out _))  // IP Address detection
                {
                    subjectAltNames.IpAddresses.Add(entry);
                }
                else if (entry.Contains("."))  // DNS Name detection
                {
                    subjectAltNames.DnsNames.Add(entry);
                }
            }

            return subjectAltNames;
        }

    }
}
