using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.GCPCAS
{
	public class Utilities
	{
		public static string ParseSubject(string subject, string rdn, bool required = true)
		{
			string escapedSubject = subject.Replace("\\,", "|");
			string rdnString = escapedSubject.Split(',').ToList().Where(x => x.Contains(rdn)).FirstOrDefault();

			if (!string.IsNullOrEmpty(rdnString))
			{
				return rdnString.Replace(rdn, "").Replace("|", ",").Trim();
			}
			else if (required)
			{
				throw new Exception($"The request is missing a {rdn} value");
			}
			else
			{
				return null;
			}
		}
	}
}
