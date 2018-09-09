using FirmaXades.Crypto;

namespace FirmaXades.Signature.Parameters
{
    public class SignaturePolicyInfo
    {
        private DigestMethod _defaultPolicyDigestAlgorithm = DigestMethod.SHA1;

        public string PolicyIdentifier { get; set; }

        public string PolicyDescription { get; set; }

        public string PolicyHash
        {
            get;
            set;
        }

        public DigestMethod PolicyDigestAlgorithm { get; set; }

        public string PolicyUri { get; set; }

        public SignaturePolicyInfo()
        {
            PolicyDigestAlgorithm = _defaultPolicyDigestAlgorithm;
        }
    }
}