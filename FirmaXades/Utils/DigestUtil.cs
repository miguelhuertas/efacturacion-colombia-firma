using FirmaXades.Crypto;
using Microsoft.Xades;
using System.Security.Cryptography;

namespace FirmaXades.Utils
{
    internal class DigestUtil
    {
        public static void SetCertDigest(byte[] rawCert, FirmaXades.Crypto.DigestMethod digestMethod, DigestAlgAndValueType destination)
        {
            using (HashAlgorithm hashAlgorithm = digestMethod.GetHashAlgorithm())
            {
                destination.DigestMethod.Algorithm = digestMethod.URI;
                destination.DigestValue = hashAlgorithm.ComputeHash(rawCert);
            }
        }

        public static byte[] ComputeHashValue(byte[] value, FirmaXades.Crypto.DigestMethod digestMethod)
        {
            using (HashAlgorithm hashAlgorithm = digestMethod.GetHashAlgorithm())
            {
                return hashAlgorithm.ComputeHash(value);
            }
        }
    }
}