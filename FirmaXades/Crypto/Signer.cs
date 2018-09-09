using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FirmaXades.Crypto
{
    public class Signer : IDisposable
    {
        private bool _disposeCryptoProvider;

        private X509Certificate2 _signingCertificate;

        private AsymmetricAlgorithm _signingKey;

        public X509Certificate2 Certificate => _signingCertificate;

        public AsymmetricAlgorithm SigningKey => _signingKey;

        public Signer(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
            if (!certificate.HasPrivateKey)
            {
                throw new Exception("El certificado no contiene ninguna clave privada");
            }
            _signingCertificate = certificate;
            SetSigningKey(_signingCertificate);
        }

        public void Dispose()
        {
            if (_disposeCryptoProvider && _signingKey != null)
            {
                _signingKey.Dispose();
            }
        }

        private void SetSigningKey(X509Certificate2 certificate)
        {
            RSACryptoServiceProvider rSACryptoServiceProvider = (RSACryptoServiceProvider)certificate.PrivateKey;
            if (rSACryptoServiceProvider.CspKeyContainerInfo.ProviderName == "Microsoft Strong Cryptographic Provider" || rSACryptoServiceProvider.CspKeyContainerInfo.ProviderName == "Microsoft Enhanced Cryptographic Provider v1.0" || rSACryptoServiceProvider.CspKeyContainerInfo.ProviderName == "Microsoft Base Cryptographic Provider v1.0" || rSACryptoServiceProvider.CspKeyContainerInfo.ProviderName == "Microsoft RSA SChannel Cryptographic Provider")
            {
                Type typeFromHandle = typeof(CspKeyContainerInfo);
                FieldInfo field = typeFromHandle.GetField("m_parameters", BindingFlags.Instance | BindingFlags.NonPublic);
                CspParameters cspParameters = (CspParameters)field.GetValue(rSACryptoServiceProvider.CspKeyContainerInfo);
                CspParameters cspParameters2 = new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", rSACryptoServiceProvider.CspKeyContainerInfo.KeyContainerName);
                cspParameters2.KeyNumber = cspParameters.KeyNumber;
                cspParameters2.Flags = cspParameters.Flags;
                _signingKey = new RSACryptoServiceProvider(cspParameters2);
                _disposeCryptoProvider = true;
            }
            else
            {
                _signingKey = rSACryptoServiceProvider;
                _disposeCryptoProvider = false;
            }
        }
    }
}
