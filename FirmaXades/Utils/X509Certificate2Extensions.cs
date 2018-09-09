using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace FirmaXades.Utils
{
    internal static class X509Certificate2Extensions
    {
        public static string GetSerialNumberAsDecimalString(this X509Certificate2 certificate)
        {
            List<int> list = new List<int>
        {
            0
        };
            string serialNumber = certificate.SerialNumber;
            for (int i = 0; i < serialNumber.Length; i++)
            {
                int num = Convert.ToInt32(serialNumber[i].ToString(), 16);
                for (int j = 0; j < list.Count; j++)
                {
                    int num2 = list[j] * 16 + num;
                    list[j] = num2 % 10;
                    num = num2 / 10;
                }
                while (num > 0)
                {
                    list.Add(num % 10);
                    num /= 10;
                }
            }
            IEnumerable<char> source = from d in list
                                       select (char)(48 + d);
            char[] value = source.Reverse().ToArray();
            return new string(value);
        }

        public static Org.BouncyCastle.X509.X509Certificate ToBouncyX509Certificate(this X509Certificate2 certificate)
        {
            return DotNetUtilities.FromX509Certificate(certificate);
        }
    }
}