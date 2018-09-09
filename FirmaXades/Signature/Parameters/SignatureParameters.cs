using FirmaXades.Crypto;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace FirmaXades.Signature.Parameters
{
    public class SignatureParameters
    {
        private SignatureMethod _defaultSignatureMethod = SignatureMethod.RSAwithSHA256;

        private DigestMethod _defaultDigestMethod = DigestMethod.SHA256;

        public Signer Signer { get; set; }

        public SignatureMethod SignatureMethod { get; set; }

        public DigestMethod DigestMethod { get; set; }

        public DateTime? SigningDate { get; set; }

        public SignerRole SignerRole { get; set; }

        public List<SignatureXPathExpression> XPathTransformations { get; private set; }

        public SignaturePolicyInfo SignaturePolicyInfo { get; set; }

        public SignatureXPathExpression SignatureDestination { get; set; }

        public SignaturePackaging SignaturePackaging { get; set; }

        public string InputMimeType { get; set; }

        public string ElementIdToSign { get; set; }

        public string ExternalContentUri { get; set; }

        public string CertificateIssuerName { get; set; }

        public SignatureParameters()
        {
            XPathTransformations = new List<SignatureXPathExpression>();
            SignatureMethod = _defaultSignatureMethod;
            DigestMethod = _defaultDigestMethod;
        }
    }
}