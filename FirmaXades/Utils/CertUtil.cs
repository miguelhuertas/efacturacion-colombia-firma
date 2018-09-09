using System;
using System.Security.Cryptography.X509Certificates;

namespace FirmaXades.Utils
{
    public class CertUtil
    {
        public static X509Chain GetCertChain(X509Certificate2 certificate, X509Certificate2[] certificates = null)
        {
            X509Chain x509Chain = new X509Chain();
            x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            x509Chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage;
            if (certificates != null)
            {
                x509Chain.ChainPolicy.ExtraStore.AddRange(certificates);
            }
            if (!x509Chain.Build(certificate))
            {
                throw new Exception("No se puede construir la cadena de certificación");
            }
            return x509Chain;
        }

        public static X509Certificate2 SelectCertificate(string message = null, string title = null)
        {
            X509Certificate2 x509Certificate = null;
            try
            {
                X509Store x509Store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                x509Store.Open(OpenFlags.OpenExistingOnly);
                X509Certificate2Collection certificates = x509Store.Certificates;
                X509Certificate2Collection certificates2 = certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                if (string.IsNullOrEmpty(message))
                {
                    message = "Seleccione un certificado.";
                }
                if (string.IsNullOrEmpty(title))
                {
                    title = "Firmar archivo";
                }
                X509Certificate2Collection x509Certificate2Collection = X509Certificate2UI.SelectFromCollection(certificates2, title, message, X509SelectionFlag.SingleSelection);
                if (x509Certificate2Collection != null && x509Certificate2Collection.Count == 1)
                {
                    x509Certificate = x509Certificate2Collection[0];
                    if (!x509Certificate.HasPrivateKey)
                    {
                        throw new Exception("El certificado no tiene asociada una clave privada.");
                    }
                }
                x509Store.Close();
            }
            catch (Exception innerException)
            {
                throw new Exception("No se ha podido obtener la clave privada.", innerException);
            }
            return x509Certificate;
        }
    }
}