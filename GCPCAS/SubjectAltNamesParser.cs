using System;
using System.Collections.Generic;
using System.Net;
using Google.Cloud.Security.PrivateCA.V1; // Google's SubjectAltNames class

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
