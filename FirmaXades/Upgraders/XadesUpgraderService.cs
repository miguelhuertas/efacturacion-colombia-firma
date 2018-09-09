using FirmaXades.Signature;
using FirmaXades.Upgraders.Parameters;

namespace FirmaXades.Upgraders
{
    public class XadesUpgraderService
    {
        public void Upgrade(SignatureDocument sigDocument, SignatureFormat toFormat, UpgradeParameters parameters)
        {
            XadesTUpgrader xadesTUpgrader = null;
            XadesXLUpgrader xadesXLUpgrader = null;
            SignatureDocument.CheckSignatureDocument(sigDocument);
            if (toFormat == SignatureFormat.XAdES_T)
            {
                xadesTUpgrader = new XadesTUpgrader();
                xadesTUpgrader.Upgrade(sigDocument, parameters);
            }
            else
            {
                if (sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count == 0)
                {
                    xadesTUpgrader = new XadesTUpgrader();
                    xadesTUpgrader.Upgrade(sigDocument, parameters);
                }
                xadesXLUpgrader = new XadesXLUpgrader();
                xadesXLUpgrader.Upgrade(sigDocument, parameters);
            }
        }
    }
}