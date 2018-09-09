using System.Collections.Generic;

namespace FirmaXades.Signature.Parameters
{
    public class SignatureXPathExpression
    {
        private Dictionary<string, string> _namespaces;

        public string XPathExpression
        {
            get;
            set;
        }

        public Dictionary<string, string> Namespaces => _namespaces;

        public SignatureXPathExpression()
        {
            _namespaces = new Dictionary<string, string>();
        }
    }
}