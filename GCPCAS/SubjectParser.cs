using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
