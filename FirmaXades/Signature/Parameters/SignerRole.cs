using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace FirmaXades.Signature.Parameters
{
    public class SignerRole
    {
        private List<X509Certificate> _certifiedRoles;

        private List<string> _claimedRoles;

        public List<X509Certificate> CertifiedRoles => _certifiedRoles;

        public List<string> ClaimedRoles => _claimedRoles;

        public SignerRole()
        {
            _certifiedRoles = new List<X509Certificate>();
            _claimedRoles = new List<string>();
        }
    }
}