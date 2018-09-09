using FirmaXades.Clients;
using FirmaXades.Crypto;
using FirmaXades.Signature;
using FirmaXades.Upgraders.Parameters;
using FirmaXades.Utils;
using Microsoft.Xades;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace FirmaXades.Upgraders
{
    internal class XadesXLUpgrader : IXadesUpgrader
    {
        public void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            UnsignedProperties unsignedProperties = null;
            CertificateValues certificateValues = null;
            X509Certificate2 signingCertificate = signatureDocument.XadesSignature.GetSigningCertificate();
            unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
            unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs = new CompleteCertificateRefs();
            CompleteCertificateRefs completeCertificateRefs = unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs;
            Guid guid = Guid.NewGuid();
            completeCertificateRefs.Id = "CompleteCertificates-" + guid.ToString();
            unsignedProperties.UnsignedSignatureProperties.CertificateValues = new CertificateValues();
            certificateValues = unsignedProperties.UnsignedSignatureProperties.CertificateValues;
            CertificateValues certificateValues2 = certificateValues;
            guid = Guid.NewGuid();
            certificateValues2.Id = "CertificatesValues-" + guid.ToString();
            unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs = new CompleteRevocationRefs();
            CompleteRevocationRefs completeRevocationRefs = unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs;
            guid = Guid.NewGuid();
            completeRevocationRefs.Id = "CompleteRev-" + guid.ToString();
            unsignedProperties.UnsignedSignatureProperties.RevocationValues = new RevocationValues();
            RevocationValues revocationValues = unsignedProperties.UnsignedSignatureProperties.RevocationValues;
            guid = Guid.NewGuid();
            revocationValues.Id = "RevocationValues-" + guid.ToString();
            AddCertificate(signingCertificate, unsignedProperties, false, parameters.OCSPServers, parameters.CRL, parameters.DigestMethod, null);
            AddTSACertificates(unsignedProperties, parameters.OCSPServers, parameters.CRL, parameters.DigestMethod);
            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
            TimeStampCertRefs(signatureDocument, parameters);
            signatureDocument.UpdateDocument();
        }

        private string RevertIssuerName(string issuer)
        {
            string[] array = issuer.Split(',');
            string text = "";
            for (int num = array.Length - 1; num >= 0; num--)
            {
                if (!string.IsNullOrEmpty(text))
                {
                    text += ",";
                }
                text += array[num];
            }
            return text;
        }

        private string GetResponderName(ResponderID responderId, ref bool byKey)
        {
            DerTaggedObject derTaggedObject = (DerTaggedObject)responderId.ToAsn1Object();
            if (derTaggedObject.TagNo != 1)
            {
                if (derTaggedObject.TagNo != 2)
                {
                    return null;
                }
                Asn1TaggedObject asn1TaggedObject = (Asn1TaggedObject)responderId.ToAsn1Object();
                Asn1OctetString asn1OctetString = (Asn1OctetString)asn1TaggedObject.GetObject();
                byKey = true;
                return Convert.ToBase64String(asn1OctetString.GetOctets());
            }
            X509Name instance = X509Name.GetInstance(derTaggedObject.GetObject());
            byKey = false;
            return instance.ToString();
        }

        private bool CertificateChecked(X509Certificate2 cert, UnsignedProperties unsignedProperties)
        {
            foreach (EncapsulatedX509Certificate item in unsignedProperties.UnsignedSignatureProperties.CertificateValues.EncapsulatedX509CertificateCollection)
            {
                X509Certificate2 x509Certificate = new X509Certificate2(item.PkiData);
                if (x509Certificate.SubjectName.Equals(cert.SubjectName))
                {
                    return true;
                }
            }
            return false;
        }

        private void AddCertificate(X509Certificate2 cert, UnsignedProperties unsignedProperties, bool addCert, IEnumerable<string> ocspServers, IEnumerable<X509Crl> crlList, FirmaXades.Crypto.DigestMethod digestMethod, X509Certificate2[] extraCerts = null)
        {
            if (addCert)
            {
                if (CertificateChecked(cert, unsignedProperties))
                {
                    return;
                }
                string str = Guid.NewGuid().ToString();
                Cert cert2 = new Cert();
                cert2.IssuerSerial.X509IssuerName = cert.IssuerName.Name;
                cert2.IssuerSerial.X509SerialNumber = cert.GetSerialNumberAsDecimalString();
                DigestUtil.SetCertDigest(cert.GetRawCertData(), digestMethod, cert2.CertDigest);
                cert2.URI = "#Cert" + str;
                unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection.Add(cert2);
                EncapsulatedX509Certificate encapsulatedX509Certificate = new EncapsulatedX509Certificate();
                encapsulatedX509Certificate.Id = "Cert" + str;
                encapsulatedX509Certificate.PkiData = cert.GetRawCertData();
                unsignedProperties.UnsignedSignatureProperties.CertificateValues.EncapsulatedX509CertificateCollection.Add(encapsulatedX509Certificate);
            }
            X509ChainElementCollection chainElements = CertUtil.GetCertChain(cert, extraCerts).ChainElements;
            if (chainElements.Count > 1)
            {
                X509ChainElementEnumerator enumerator = chainElements.GetEnumerator();
                enumerator.MoveNext();
                enumerator.MoveNext();
                if (!ValidateCertificateByCRL(unsignedProperties, cert, enumerator.Current.Certificate, crlList, digestMethod))
                {
                    X509Certificate2[] array = ValidateCertificateByOCSP(unsignedProperties, cert, enumerator.Current.Certificate, ocspServers, digestMethod);
                    if (array != null)
                    {
                        X509Certificate2 x509Certificate = DetermineStartCert(new List<X509Certificate2>(array));
                        if (x509Certificate.IssuerName.Name != enumerator.Current.Certificate.SubjectName.Name)
                        {
                            X509Chain certChain = CertUtil.GetCertChain(x509Certificate, array);
                            AddCertificate(certChain.ChainElements[1].Certificate, unsignedProperties, true, ocspServers, crlList, digestMethod, array);
                        }
                    }
                }
                AddCertificate(enumerator.Current.Certificate, unsignedProperties, true, ocspServers, crlList, digestMethod, extraCerts);
            }
        }

        private bool ExistsCRL(CRLRefCollection collection, string issuer)
        {
            foreach (CRLRef item in collection)
            {
                if (item.CRLIdentifier.Issuer == issuer)
                {
                    return true;
                }
            }
            return false;
        }

        private long? GetCRLNumber(X509Crl crlEntry)
        {
            Asn1OctetString extensionValue = crlEntry.GetExtensionValue(X509Extensions.CrlNumber);
            if (extensionValue == null)
            {
                return null;
            }
            Asn1Object obj = X509ExtensionUtilities.FromExtensionValue(extensionValue);
            return DerInteger.GetInstance(obj).PositiveValue.LongValue;
        }

        private bool ValidateCertificateByCRL(UnsignedProperties unsignedProperties, X509Certificate2 certificate, X509Certificate2 issuer, IEnumerable<X509Crl> crlList, FirmaXades.Crypto.DigestMethod digestMethod)
        {
            Org.BouncyCastle.X509.X509Certificate cert = certificate.ToBouncyX509Certificate();
            Org.BouncyCastle.X509.X509Certificate x509Certificate = issuer.ToBouncyX509Certificate();
            foreach (X509Crl crl in crlList)
            {
                if (crl.IssuerDN.Equivalent(x509Certificate.SubjectDN) && crl.NextUpdate.Value > DateTime.Now)
                {
                    if (crl.IsRevoked(cert))
                    {
                        throw new Exception("Certificado revocado");
                    }
                    if (!ExistsCRL(unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection, issuer.Subject))
                    {
                        string text = "CRLValue-" + Guid.NewGuid().ToString();
                        CRLRef cRLRef = new CRLRef();
                        cRLRef.CRLIdentifier.UriAttribute = "#" + text;
                        cRLRef.CRLIdentifier.Issuer = issuer.Subject;
                        cRLRef.CRLIdentifier.IssueTime = crl.ThisUpdate.ToLocalTime();
                        long? cRLNumber = GetCRLNumber(crl);
                        if (cRLNumber.HasValue)
                        {
                            cRLRef.CRLIdentifier.Number = cRLNumber.Value;
                        }
                        byte[] encoded = crl.GetEncoded();
                        DigestUtil.SetCertDigest(encoded, digestMethod, cRLRef.CertDigest);
                        CRLValue cRLValue = new CRLValue();
                        cRLValue.PkiData = encoded;
                        cRLValue.Id = text;
                        unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection.Add(cRLRef);
                        unsignedProperties.UnsignedSignatureProperties.RevocationValues.CRLValues.CRLValueCollection.Add(cRLValue);
                    }
                    return true;
                }
            }
            return false;
        }

        private X509Certificate2[] ValidateCertificateByOCSP(UnsignedProperties unsignedProperties, X509Certificate2 client, X509Certificate2 issuer, IEnumerable<string> ocspServers, FirmaXades.Crypto.DigestMethod digestMethod)
        {
            bool byKey = false;
            List<string> list = new List<string>();
            Org.BouncyCastle.X509.X509Certificate eeCert = client.ToBouncyX509Certificate();
            Org.BouncyCastle.X509.X509Certificate x509Certificate = issuer.ToBouncyX509Certificate();
            OcspClient ocspClient = new OcspClient();
            string authorityInformationAccessOcspUrl = ocspClient.GetAuthorityInformationAccessOcspUrl(x509Certificate);
            if (!string.IsNullOrEmpty(authorityInformationAccessOcspUrl))
            {
                list.Add(authorityInformationAccessOcspUrl);
            }
            foreach (string ocspServer in ocspServers)
            {
                list.Add(ocspServer);
            }
            foreach (string item in list)
            {
                byte[] array = ocspClient.QueryBinary(eeCert, x509Certificate, item);
                switch (ocspClient.ProcessOcspResponse(array))
                {
                    case FirmaXades.Clients.CertificateStatus.Revoked:
                        throw new Exception("Certificado revocado");
                    case FirmaXades.Clients.CertificateStatus.Good:
                        {
                            OcspResp ocspResp = new OcspResp(array);
                            byte[] encoded = ocspResp.GetEncoded();
                            BasicOcspResp basicOcspResp = (BasicOcspResp)ocspResp.GetResponseObject();
                            string str = Guid.NewGuid().ToString();
                            OCSPRef oCSPRef = new OCSPRef();
                            oCSPRef.OCSPIdentifier.UriAttribute = "#OcspValue" + str;
                            DigestUtil.SetCertDigest(encoded, digestMethod, oCSPRef.CertDigest);
                            ResponderID responderId = basicOcspResp.ResponderId.ToAsn1Object();
                            string responderName = GetResponderName(responderId, ref byKey);
                            if (!byKey)
                            {
                                oCSPRef.OCSPIdentifier.ResponderID = RevertIssuerName(responderName);
                            }
                            else
                            {
                                oCSPRef.OCSPIdentifier.ResponderID = responderName;
                                oCSPRef.OCSPIdentifier.ByKey = true;
                            }
                            oCSPRef.OCSPIdentifier.ProducedAt = basicOcspResp.ProducedAt.ToLocalTime();
                            unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.OCSPRefs.OCSPRefCollection.Add(oCSPRef);
                            OCSPValue oCSPValue = new OCSPValue();
                            oCSPValue.PkiData = encoded;
                            oCSPValue.Id = "OcspValue" + str;
                            unsignedProperties.UnsignedSignatureProperties.RevocationValues.OCSPValues.OCSPValueCollection.Add(oCSPValue);
                            return (from cert in basicOcspResp.GetCerts()
                                    select new X509Certificate2(cert.GetEncoded())).ToArray();
                        }
                }
            }
            throw new Exception("El certificado no ha podido ser validado");
        }

        private X509Certificate2 DetermineStartCert(IList<X509Certificate2> certs)
        {
            X509Certificate2 x509Certificate = null;
            bool flag = true;
            for (int i = 0; i < certs.Count; i++)
            {
                if (!flag)
                {
                    break;
                }
                x509Certificate = certs[i];
                flag = false;
                for (int j = 0; j < certs.Count; j++)
                {
                    if (certs[j].IssuerName.Name == x509Certificate.SubjectName.Name)
                    {
                        flag = true;
                        break;
                    }
                }
            }
            return x509Certificate;
        }

        private void AddTSACertificates(UnsignedProperties unsignedProperties, IEnumerable<string> ocspServers, IEnumerable<X509Crl> crlList, FirmaXades.Crypto.DigestMethod digestMethod)
        {
            TimeStampToken timeStampToken = new TimeStampToken(new CmsSignedData(unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0].EncapsulatedTimeStamp.PkiData));
            IX509Store certificates = timeStampToken.GetCertificates("Collection");
            SignerID signerID = timeStampToken.SignerID;
            List<X509Certificate2> list = new List<X509Certificate2>();
            foreach (object match in certificates.GetMatches(null))
            {
                X509Certificate2 item = new X509Certificate2(((Org.BouncyCastle.X509.X509Certificate)match).GetEncoded());
                list.Add(item);
            }
            X509Certificate2 cert = DetermineStartCert(list);
            AddCertificate(cert, unsignedProperties, true, ocspServers, crlList, digestMethod, list.ToArray());
        }

        private void TimeStampCertRefs(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            XmlElement signatureElement = signatureDocument.XadesSignature.GetSignatureElement();
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(signatureDocument.Document.NameTable);
            xmlNamespaceManager.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");
            xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            XmlNode xmlNode = signatureElement.SelectSingleNode("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs", xmlNamespaceManager);
            if (xmlNode == null)
            {
                signatureDocument.UpdateDocument();
            }
            ArrayList arrayList = new ArrayList();
            arrayList.Add("ds:SignatureValue");
            arrayList.Add("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp");
            arrayList.Add("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs");
            arrayList.Add("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs");
            byte[] hash = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(signatureDocument.XadesSignature, arrayList), parameters.DigestMethod);
            byte[] timeStamp = parameters.TimeStampClient.GetTimeStamp(hash, parameters.DigestMethod, true);
            TimeStamp timeStamp2 = new TimeStamp("SigAndRefsTimeStamp");
            timeStamp2.Id = "SigAndRefsStamp-" + signatureDocument.XadesSignature.Signature.Id;
            timeStamp2.EncapsulatedTimeStamp.PkiData = timeStamp;
            timeStamp2.EncapsulatedTimeStamp.Id = "SigAndRefsStamp-" + Guid.NewGuid().ToString();
            UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
            unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampFlag = false;
            unsignedProperties.UnsignedSignatureProperties.SigAndRefsTimeStampCollection.Add(timeStamp2);
            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
        }
    }
}