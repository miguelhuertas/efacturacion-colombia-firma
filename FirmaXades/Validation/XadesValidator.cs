using FirmaXades.Crypto;
using FirmaXades.Signature;
using FirmaXades.Utils;
using FirmaXades.Validation;
using Microsoft.Xades;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;

namespace FirmaXades.Validation
{
    internal class XadesValidator
    {
        public ValidationResult Validate(SignatureDocument sigDocument)
        {
            ValidationResult validationResult = new ValidationResult();
            try
            {
                sigDocument.XadesSignature.CheckXmldsigSignature();
            }
            catch (Exception)
            {
                validationResult.IsValid = false;
                validationResult.Message = "La verificación de la firma no ha sido satisfactoria";
                return validationResult;
            }
            if (sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count > 0)
            {
                TimeStamp timeStamp = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0];
                TimeStampToken timeStampToken = new TimeStampToken(new CmsSignedData(timeStamp.EncapsulatedTimeStamp.PkiData));
                byte[] messageImprintDigest = timeStampToken.TimeStampInfo.GetMessageImprintDigest();
                FirmaXades.Crypto.DigestMethod byOid = FirmaXades.Crypto.DigestMethod.GetByOid(timeStampToken.TimeStampInfo.HashAlgorithm.ObjectID.Id);
                ArrayList arrayList = new ArrayList();
                arrayList.Add("ds:SignatureValue");
                byte[] b = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(sigDocument.XadesSignature, arrayList), byOid);
                if (!Arrays.AreEqual(messageImprintDigest, b))
                {
                    validationResult.IsValid = false;
                    validationResult.Message = "La huella del sello de tiempo no se corresponde con la calculada";
                    return validationResult;
                }
            }
            validationResult.IsValid = true;
            validationResult.Message = "Verificación de la firma satisfactoria";
            return validationResult;
        }
    }
}