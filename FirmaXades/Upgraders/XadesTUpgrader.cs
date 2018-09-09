using FirmaXades.Signature;
using FirmaXades.Upgraders;
using FirmaXades.Upgraders.Parameters;
using FirmaXades.Utils;
using Microsoft.Xades;
using System;
using System.Collections;

namespace FirmaXades.Upgraders
{
    internal class XadesTUpgrader : IXadesUpgrader
    {
        public void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
            try
            {
                if (unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count > 0)
                {
                    throw new Exception("La firma ya contiene un sello de tiempo");
                }
                ArrayList arrayList = new ArrayList();
                arrayList.Add("ds:SignatureValue");
                byte[] hash = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(signatureDocument.XadesSignature, arrayList), parameters.DigestMethod);
                byte[] timeStamp = parameters.TimeStampClient.GetTimeStamp(hash, parameters.DigestMethod, true);
                TimeStamp timeStamp2 = new TimeStamp("SignatureTimeStamp");
                timeStamp2.Id = "SignatureTimeStamp-" + signatureDocument.XadesSignature.Signature.Id;
                timeStamp2.EncapsulatedTimeStamp.PkiData = timeStamp;
                timeStamp2.EncapsulatedTimeStamp.Id = "SignatureTimeStamp-" + Guid.NewGuid().ToString();
                unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Add(timeStamp2);
                signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
                signatureDocument.UpdateDocument();
            }
            catch (Exception innerException)
            {
                throw new Exception("Ha ocurrido un error al insertar el sellado de tiempo.", innerException);
            }
        }
    }
}