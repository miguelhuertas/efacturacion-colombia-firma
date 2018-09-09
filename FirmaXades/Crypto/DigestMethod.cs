using System;
using System.Security.Cryptography;

namespace FirmaXades.Crypto
{
    public class DigestMethod
    {
        private string _name;

        private string _uri;

        private string _oid;

        public static DigestMethod SHA1 = new DigestMethod("SHA1", "http://www.w3.org/2000/09/xmldsig#sha1", "1.3.14.3.2.26");

        public static DigestMethod SHA256 = new DigestMethod("SHA256", "http://www.w3.org/2001/04/xmlenc#sha256", "2.16.840.1.101.3.4.2.1");

        public static DigestMethod SHA512 = new DigestMethod("SHA512", "http://www.w3.org/2001/04/xmlenc#sha512", "2.16.840.1.101.3.4.2.3");

        public string Name => _name;

        public string URI => _uri;

        public string Oid => _oid;

        private DigestMethod(string name, string uri, string oid)
        {
            _name = name;
            _uri = uri;
            _oid = oid;
        }

        public static DigestMethod GetByOid(string oid)
        {
            if (!(oid == SHA1.Oid))
            {
                if (!(oid == SHA256.Oid))
                {
                    if (!(oid == SHA512.Oid))
                    {
                        throw new Exception("Unsupported digest method");
                    }
                    return SHA512;
                }
                return SHA256;
            }
            return SHA1;
        }

        public HashAlgorithm GetHashAlgorithm()
        {
            if (!(_name == "SHA1"))
            {
                if (!(_name == "SHA256"))
                {
                    if (!(_name == "SHA512"))
                    {
                        throw new Exception("Algoritmo no soportado");
                    }
                    return System.Security.Cryptography.SHA512.Create();
                }
                return System.Security.Cryptography.SHA256.Create();
            }
            return System.Security.Cryptography.SHA1.Create();
        }
    }
}
