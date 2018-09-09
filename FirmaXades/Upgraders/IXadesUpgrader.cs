using FirmaXades.Signature;
using FirmaXades.Upgraders.Parameters;

namespace FirmaXades.Upgraders
{
    internal interface IXadesUpgrader
    {
        void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters);
    }
}