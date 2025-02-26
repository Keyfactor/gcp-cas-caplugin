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
using Google.Cloud.Security.PrivateCA.V1;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS
{


    public class SubjectParser
    {
        public static Subject ParseFromString(string subjectString)
        {
            if (string.IsNullOrWhiteSpace(subjectString))
                return null;

            var subject = new Subject();
            string[] keyValuePairs = subjectString.Split(',');

            foreach (var pair in keyValuePairs)
            {
                var parts = pair.Split('=');
                if (parts.Length == 2)
                {
                    string key = parts[0].Trim().ToUpper(); // Normalize key case
                    string value = parts[1].Trim();

                    if (!string.IsNullOrEmpty(value))
                    {
                        switch (key)
                        {
                            case "CN":
                                subject.CommonName = value;
                                break;
                            case "C":
                                subject.CountryCode = value;
                                break;
                            case "O":
                                subject.Organization = value;
                                break;
                            case "OU":
                                subject.OrganizationalUnit = value;
                                break;
                            case "L":
                                subject.Locality = value;
                                break;
                            case "ST":
                                subject.Province = value;
                                break;
                            case "STREET":
                                subject.StreetAddress = value;
                                break;
                            case "PC":
                                subject.PostalCode = value;
                                break;
                            default:
                                // Ignore unknown keys
                                break;
                        }
                    }
                }
            }

            return subject;
        }
    }
}
