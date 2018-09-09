using FirmaXades.Clients;
using FirmaXades.Crypto;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System.IO;

namespace FirmaXades.Upgraders.Parameters
{
    public class UpgradeParameters
    {
        private List<string> _ocspServers;

        private List<X509Crl> _crls;

        private X509CrlParser _crlParser;

        private DigestMethod _defaultDigestMethod = DigestMethod.SHA1;

        public List<string> OCSPServers => _ocspServers;

        public IEnumerable<X509Crl> CRL => _crls;

        public DigestMethod DigestMethod { get; set; }

        public TimeStampClient TimeStampClient { get; set; }

        public UpgradeParameters()
        {
            _ocspServers = new List<string>();
            _crls = new List<X509Crl>();
            DigestMethod = _defaultDigestMethod;
            _crlParser = new X509CrlParser();
        }

        public void AddCRL(Stream stream)
        {
            X509Crl item = _crlParser.ReadCrl(stream);
            _crls.Add(item);
        }

        public void ClearCRL()
        {
            _crls.Clear();
        }
    }
}