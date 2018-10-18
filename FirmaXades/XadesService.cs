using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

using Org.BouncyCastle.Asn1;
using BCx509 = Org.BouncyCastle.Asn1.X509;
using BCEncoders = Org.BouncyCastle.Utilities.Encoders;

using FirmaXades.Signature;
using FirmaXades.Signature.Parameters;
using FirmaXades.Utils;
using FirmaXades.Validation;
using Microsoft.Xades;

namespace FirmaXades
{
    public class XadesService
    {
        private Reference _refContent;

        private string _mimeType;

        private string _encoding;

        public SignatureDocument Sign(Stream input, SignatureParameters parameters)
        {
            if (parameters.Signer == null)
            {
                throw new Exception("Es necesario un certificado válido para la firma");
            }
            if (input == null && string.IsNullOrEmpty(parameters.ExternalContentUri))
            {
                throw new Exception("No se ha especificado ningún contenido a firmar");
            }
            SignatureDocument signatureDocument = new SignatureDocument();
            switch (parameters.SignaturePackaging)
            {
                case SignaturePackaging.INTERNALLY_DETACHED:
                    if (string.IsNullOrEmpty(parameters.InputMimeType))
                    {
                        throw new NullReferenceException("Se necesita especificar el tipo MIME del elemento a firmar.");
                    }
                    if (!string.IsNullOrEmpty(parameters.ElementIdToSign))
                    {
                        SetContentInternallyDetached(signatureDocument, XMLUtil.LoadDocument(input), parameters.ElementIdToSign, parameters.InputMimeType);
                    }
                    else
                    {
                        SetContentInternallyDetached(signatureDocument, input, parameters.InputMimeType);
                    }
                    break;
                case SignaturePackaging.ENVELOPED:
                    SetContentEnveloped(signatureDocument, XMLUtil.LoadDocument(input));
                    break;
                case SignaturePackaging.ENVELOPING:
                    SetContentEveloping(signatureDocument, XMLUtil.LoadDocument(input));
                    break;
                case SignaturePackaging.EXTERNALLY_DETACHED:
                    SetContentExternallyDetached(signatureDocument, parameters.ExternalContentUri);
                    break;
            }
            PrepareSignature(signatureDocument, parameters);
            ComputeSignature(signatureDocument);
            signatureDocument.UpdateDocument();
            return signatureDocument;
        }

        public SignatureDocument CoSign(SignatureDocument sigDocument, SignatureParameters parameters)
        {
            SignatureDocument.CheckSignatureDocument(sigDocument);
            _refContent = sigDocument.XadesSignature.GetContentReference();
            if (_refContent == null)
            {
                throw new Exception("No se ha podido encontrar la referencia del contenido firmado.");
            }
            _mimeType = string.Empty;
            _encoding = string.Empty;
            foreach (DataObjectFormat item in sigDocument.XadesSignature.XadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.DataObjectFormatCollection)
            {
                if (item.ObjectReferenceAttribute == "#" + _refContent.Id)
                {
                    _mimeType = item.MimeType;
                    _encoding = item.Encoding;
                    break;
                }
            }
            SignatureDocument signatureDocument = new SignatureDocument();
            signatureDocument.Document = (XmlDocument)sigDocument.Document.Clone();
            signatureDocument.Document.PreserveWhitespace = true;
            signatureDocument.XadesSignature = new XadesSignedXml(signatureDocument.Document);
            signatureDocument.XadesSignature.LoadXml(sigDocument.XadesSignature.GetXml());
            XmlNode parentNode = signatureDocument.XadesSignature.GetSignatureElement().ParentNode;
            signatureDocument.XadesSignature = new XadesSignedXml(signatureDocument.Document);
            _refContent.Id = "Reference-" + Guid.NewGuid().ToString();
            if (_refContent.Type != "http://www.w3.org/2000/09/xmldsig#Object")
            {
                _refContent.Type = "";
            }
            signatureDocument.XadesSignature.AddReference(_refContent);
            if (parentNode.NodeType != XmlNodeType.Document)
            {
                signatureDocument.XadesSignature.SignatureNodeDestination = (XmlElement)parentNode;
            }
            else
            {
                signatureDocument.XadesSignature.SignatureNodeDestination = ((XmlDocument)parentNode).DocumentElement;
            }
            PrepareSignature(signatureDocument, parameters);
            ComputeSignature(signatureDocument);
            signatureDocument.UpdateDocument();
            return signatureDocument;
        }

        public SignatureDocument CounterSign(SignatureDocument sigDocument, SignatureParameters parameters)
        {
            if (parameters.Signer == null)
            {
                throw new Exception("Es necesario un certificado válido para la firma.");
            }
            SignatureDocument.CheckSignatureDocument(sigDocument);
            SignatureDocument signatureDocument = new SignatureDocument();
            signatureDocument.Document = (XmlDocument)sigDocument.Document.Clone();
            signatureDocument.Document.PreserveWhitespace = true;
            XadesSignedXml xadesSignedXml = new XadesSignedXml(signatureDocument.Document);
            xadesSignedXml.Signature.Id = "xmldsig-" + Guid.NewGuid().ToString();
            xadesSignedXml.SignatureValueId = sigDocument.XadesSignature.Signature.Id + "-sigvalue";
            xadesSignedXml.SigningKey = parameters.Signer.SigningKey;
            _refContent = new Reference();
            _refContent.Uri = "#" + sigDocument.XadesSignature.SignatureValueId;
            Reference refContent = _refContent;
            Guid guid = Guid.NewGuid();
            refContent.Id = "Reference-" + guid.ToString();
            _refContent.Type = "http://uri.etsi.org/01903#CountersignedSignature";
            _refContent.AddTransform(new XmlDsigC14NTransform());
            xadesSignedXml.AddReference(_refContent);
            _mimeType = "text/xml";
            _encoding = "UTF-8";
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.Id = "KeyInfoId-" + xadesSignedXml.Signature.Id;
            keyInfo.AddClause(new KeyInfoX509Data(parameters.Signer.Certificate));
            keyInfo.AddClause(new RSAKeyValue((RSA)parameters.Signer.SigningKey));
            xadesSignedXml.KeyInfo = keyInfo;
            Reference reference = new Reference();
            reference.Id = "ReferenceKeyInfo-" + xadesSignedXml.Signature.Id;
            reference.Uri = "#KeyInfoId-" + xadesSignedXml.Signature.Id;
            xadesSignedXml.AddReference(reference);
            XadesObject xadesObject = new XadesObject();
            XadesObject xadesObject2 = xadesObject;
            guid = Guid.NewGuid();
            xadesObject2.Id = "CounterSignatureXadesObject-" + guid.ToString();
            xadesObject.QualifyingProperties.Target = "#" + xadesSignedXml.Signature.Id;
            xadesObject.QualifyingProperties.SignedProperties.Id = "SignedProperties-" + xadesSignedXml.Signature.Id;
            AddSignatureProperties(signatureDocument, xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties, xadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties, xadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties, parameters);
            xadesSignedXml.AddXadesObject(xadesObject);
            foreach (Reference reference2 in xadesSignedXml.SignedInfo.References)
            {
                reference2.DigestMethod = parameters.DigestMethod.URI;
            }
            xadesSignedXml.SignedInfo.SignatureMethod = parameters.SignatureMethod.URI;
            xadesSignedXml.AddXadesNamespace = true;
            xadesSignedXml.ComputeSignature();
            signatureDocument.XadesSignature = new XadesSignedXml(signatureDocument.Document);
            signatureDocument.XadesSignature.LoadXml(sigDocument.XadesSignature.GetXml());
            UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
            unsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection.Add(xadesSignedXml);
            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
            signatureDocument.UpdateDocument();
            return signatureDocument;
        }

        public SignatureDocument[] Load(Stream input)
        {
            return Load(XMLUtil.LoadDocument(input));
        }

        public SignatureDocument[] Load(string fileName)
        {
            using (FileStream input = new FileStream(fileName, FileMode.Open))
            {
                return Load(input);
            }
        }

        public SignatureDocument[] Load(XmlDocument xmlDocument)
        {
            XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
            if (elementsByTagName.Count == 0)
            {
                throw new Exception("No se ha encontrado ninguna firma.");
            }
            List<SignatureDocument> list = new List<SignatureDocument>();
            foreach (object item in elementsByTagName)
            {
                SignatureDocument signatureDocument = new SignatureDocument();
                signatureDocument.Document = (XmlDocument)xmlDocument.Clone();
                signatureDocument.Document.PreserveWhitespace = true;
                signatureDocument.XadesSignature = new XadesSignedXml(signatureDocument.Document);
                signatureDocument.XadesSignature.LoadXml((XmlElement)item);
                list.Add(signatureDocument);
            }
            return list.ToArray();
        }

        public ValidationResult Validate(SignatureDocument sigDocument)
        {
            SignatureDocument.CheckSignatureDocument(sigDocument);
            XadesValidator xadesValidator = new XadesValidator();
            return xadesValidator.Validate(sigDocument);
        }

        private void SetContentInternallyDetached(SignatureDocument sigDocument, XmlDocument xmlDocument, string elementId, string mimeType)
        {
            sigDocument.Document = xmlDocument;
            _refContent = new Reference();
            _refContent.Uri = "#" + elementId;
            _refContent.Id = "Reference-" + Guid.NewGuid().ToString();
            _mimeType = mimeType;
            if (mimeType == "text/xml")
            {
                XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
                _refContent.AddTransform(transform);
                _encoding = "UTF-8";
            }
            else
            {
                XmlDsigBase64Transform xmlDsigBase64Transform = new XmlDsigBase64Transform();
                _refContent.AddTransform(xmlDsigBase64Transform);
                _encoding = xmlDsigBase64Transform.Algorithm;
            }
            sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);
            sigDocument.XadesSignature.AddReference(_refContent);
        }

        private void SetContentInternallyDetached(SignatureDocument sigDocument, Stream input, string mimeType)
        {
            sigDocument.Document = new XmlDocument();
            XmlElement xmlElement = sigDocument.Document.CreateElement("DOCFIRMA");
            sigDocument.Document.AppendChild(xmlElement);
            Guid guid = Guid.NewGuid();
            string text = "CONTENT-" + guid.ToString();
            _refContent = new Reference();
            _refContent.Uri = "#" + text;
            Reference refContent = _refContent;
            guid = Guid.NewGuid();
            refContent.Id = "Reference-" + guid.ToString();
            _refContent.Type = "http://www.w3.org/2000/09/xmldsig#Object";
            _mimeType = mimeType;
            XmlElement xmlElement2 = sigDocument.Document.CreateElement("CONTENT");
            if (mimeType == "text/xml")
            {
                _encoding = "UTF-8";
                XmlDocument xmlDocument = new XmlDocument();
                xmlDocument.PreserveWhitespace = true;
                xmlDocument.Load(input);
                xmlElement2.InnerXml = xmlDocument.DocumentElement.OuterXml;
                XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
                _refContent.AddTransform(transform);
            }
            else
            {
                XmlDsigBase64Transform xmlDsigBase64Transform = new XmlDsigBase64Transform();
                _refContent.AddTransform(xmlDsigBase64Transform);
                _encoding = xmlDsigBase64Transform.Algorithm;
                if (mimeType == "hash/sha256")
                {
                    using (SHA256 sHA = SHA256.Create())
                    {
                        xmlElement2.InnerText = Convert.ToBase64String(sHA.ComputeHash(input));
                    }
                }
                else
                {
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        input.CopyTo(memoryStream);
                        xmlElement2.InnerText = Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
            xmlElement2.SetAttribute("Id", text);
            xmlElement2.SetAttribute("MimeType", _mimeType);
            xmlElement2.SetAttribute("Encoding", _encoding);
            xmlElement.AppendChild(xmlElement2);
            sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);
            sigDocument.XadesSignature.AddReference(_refContent);
        }

        private void SetContentEveloping(SignatureDocument sigDocument, XmlDocument xmlDocument)
        {
            _refContent = new Reference();
            sigDocument.XadesSignature = new XadesSignedXml();
            XmlDocument xmlDocument2 = (XmlDocument)xmlDocument.Clone();
            xmlDocument2.PreserveWhitespace = true;
            if (xmlDocument2.ChildNodes[0].NodeType == XmlNodeType.XmlDeclaration)
            {
                xmlDocument2.RemoveChild(xmlDocument2.ChildNodes[0]);
            }
            Guid guid = Guid.NewGuid();
            string text = "DataObject-" + guid.ToString();
            DataObject dataObject = new DataObject();
            dataObject.Data = xmlDocument2.ChildNodes;
            dataObject.Id = text;
            sigDocument.XadesSignature.AddObject(dataObject);
            Reference refContent = _refContent;
            guid = Guid.NewGuid();
            refContent.Id = "Reference-" + guid.ToString();
            _refContent.Uri = "#" + text;
            _refContent.Type = "http://www.w3.org/2000/09/xmldsig#Object";
            XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
            _refContent.AddTransform(transform);
            _mimeType = "text/xml";
            _encoding = "UTF-8";
            sigDocument.XadesSignature.AddReference(_refContent);
        }

        private void SetSignatureDestination(SignatureDocument sigDocument, SignatureXPathExpression destination)
        {
            XmlNode xmlNode;
            if (destination.Namespaces.Count > 0)
            {
                XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(sigDocument.Document.NameTable);
                foreach (KeyValuePair<string, string> @namespace in destination.Namespaces)
                {
                    xmlNamespaceManager.AddNamespace(@namespace.Key, @namespace.Value);
                }
                xmlNode = sigDocument.Document.SelectSingleNode(destination.XPathExpression, xmlNamespaceManager);
            }
            else
            {
                xmlNode = sigDocument.Document.SelectSingleNode(destination.XPathExpression);
            }
            if (xmlNode == null)
            {
                throw new Exception("Elemento no encontrado");
            }
            sigDocument.XadesSignature.SignatureNodeDestination = (XmlElement)xmlNode;
        }

        private void SetContentExternallyDetached(SignatureDocument sigDocument, string fileName)
        {
            _refContent = new Reference();
            sigDocument.Document = new XmlDocument();
            sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);
            _refContent.Uri = new Uri(fileName).AbsoluteUri;
            _refContent.Id = "Reference-" + Guid.NewGuid().ToString();
            if (_refContent.Uri.EndsWith(".xml") || _refContent.Uri.EndsWith(".XML"))
            {
                _mimeType = "text/xml";
                _refContent.AddTransform(new XmlDsigC14NTransform());
            }
            sigDocument.XadesSignature.AddReference(_refContent);
        }

        private void AddXPathTransform(SignatureDocument sigDocument, Dictionary<string, string> namespaces, string XPathString)
        {
            XmlDocument xmlDocument = (sigDocument.Document == null) ? new XmlDocument() : sigDocument.Document;
            XmlElement xmlElement = xmlDocument.CreateElement("XPath");
            foreach (KeyValuePair<string, string> @namespace in namespaces)
            {
                XmlAttribute xmlAttribute = xmlDocument.CreateAttribute("xmlns:" + @namespace.Key);
                xmlAttribute.Value = @namespace.Value;
                xmlElement.Attributes.Append(xmlAttribute);
            }
            xmlElement.InnerText = XPathString;
            XmlDsigXPathTransform xmlDsigXPathTransform = new XmlDsigXPathTransform();
            xmlDsigXPathTransform.LoadInnerXml(xmlElement.SelectNodes("."));
            Reference reference = sigDocument.XadesSignature.SignedInfo.References[0] as Reference;
            reference.AddTransform(xmlDsigXPathTransform);
        }

        private void SetContentEnveloped(SignatureDocument sigDocument, XmlDocument xmlDocument)
        {
            sigDocument.Document = xmlDocument;

            sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);
            sigDocument.XadesSignature.Signature.Id = "xmldsig-" + Guid.NewGuid().ToString();
            sigDocument.XadesSignature.SignatureValueId = sigDocument.XadesSignature.Signature.Id + "-sigvalue";

            _refContent = new Reference();
            _refContent.Id = sigDocument.XadesSignature.Signature.Id + "-ref0";
            _refContent.Uri = "";
            _mimeType = "text/xml";
            _encoding = "UTF-8";
            for (int i = 0; i < sigDocument.Document.DocumentElement.Attributes.Count; i++)
            {
                if (sigDocument.Document.DocumentElement.Attributes[i].Name.Equals("id", StringComparison.InvariantCultureIgnoreCase))
                {
                    _refContent.Uri = "#" + sigDocument.Document.DocumentElement.Attributes[i].Value;
                    break;
                }
            }
            XmlDsigEnvelopedSignatureTransform transform = new XmlDsigEnvelopedSignatureTransform();
            _refContent.AddTransform(transform);
            sigDocument.XadesSignature.AddReference(_refContent);
        }

        private void PrepareSignature(SignatureDocument sigDocument, SignatureParameters parameters)
        {
            sigDocument.XadesSignature.SignedInfo.SignatureMethod = parameters.SignatureMethod.URI;
            AddCertificateInfo(sigDocument, parameters);
            AddXadesInfo(sigDocument, parameters);
            foreach (Reference reference in sigDocument.XadesSignature.SignedInfo.References)
            {
                reference.DigestMethod = parameters.DigestMethod.URI;
            }
            if (parameters.SignatureDestination != null)
            {
                SetSignatureDestination(sigDocument, parameters.SignatureDestination);
            }
            if (parameters.XPathTransformations.Count > 0)
            {
                foreach (SignatureXPathExpression xPathTransformation in parameters.XPathTransformations)
                {
                    AddXPathTransform(sigDocument, xPathTransformation.Namespaces, xPathTransformation.XPathExpression);
                }
            }
        }

        private void ComputeSignature(SignatureDocument sigDocument)
        {
            try
            {
                sigDocument.XadesSignature.ComputeSignature();
                XmlElement xml = sigDocument.XadesSignature.GetXml();
                sigDocument.XadesSignature.LoadXml(xml);
            }
            catch (Exception innerException)
            {
                throw new Exception("Ha ocurrido un error durante el proceso de firmado", innerException);
            }
        }

        private void AddXadesInfo(SignatureDocument sigDocument, SignatureParameters parameters)
        {
            XadesObject xadesObject = new XadesObject();
            xadesObject.QualifyingProperties.Target = "#" + sigDocument.XadesSignature.Signature.Id;
            xadesObject.QualifyingProperties.SignedProperties.Id = sigDocument.XadesSignature.Signature.Id + "-signedprops";
            AddSignatureProperties(sigDocument, xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties, xadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties, xadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties, parameters);
            sigDocument.XadesSignature.AddXadesObject(xadesObject);
        }

        private void AddCertificateInfo(SignatureDocument sigDocument, SignatureParameters parameters)
        {
            sigDocument.XadesSignature.SigningKey = parameters.Signer.SigningKey;
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.Id = "KeyInfo";
            keyInfo.AddClause(new KeyInfoX509Data(parameters.Signer.Certificate));
            sigDocument.XadesSignature.KeyInfo = keyInfo;
            Reference reference = new Reference();
            reference.Id = sigDocument.XadesSignature.Signature.Id + "-ref1";
            reference.Uri = "#" + keyInfo.Id;
            sigDocument.XadesSignature.AddReference(reference);
        }

        private void AddSignatureProperties(SignatureDocument sigDocument, SignedSignatureProperties signedSignatureProperties, SignedDataObjectProperties signedDataObjectProperties, UnsignedSignatureProperties unsignedSignatureProperties, SignatureParameters parameters)
        {
            var certificateIssuerName = !string.IsNullOrEmpty(parameters.CertificateIssuerName) ?
                parameters.CertificateIssuerName : createValidIssuerName(parameters.Signer.Certificate);

            Cert cert = new Cert();
            cert.IssuerSerial.X509IssuerName = certificateIssuerName;
            cert.IssuerSerial.X509SerialNumber = parameters.Signer.Certificate.GetSerialNumberAsDecimalString();
            DigestUtil.SetCertDigest(parameters.Signer.Certificate.GetRawCertData(), parameters.DigestMethod, cert.CertDigest);
            signedSignatureProperties.SigningCertificate.CertCollection.Add(cert);
            if (parameters.SignaturePolicyInfo != null)
            {
                if (!string.IsNullOrEmpty(parameters.SignaturePolicyInfo.PolicyIdentifier))
                {
                    signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyImplied = false;
                    signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyId.Identifier.IdentifierUri = parameters.SignaturePolicyInfo.PolicyIdentifier;
                }
                if (!string.IsNullOrEmpty(parameters.SignaturePolicyInfo.PolicyDescription))
                {
                    signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyId.Description = parameters.SignaturePolicyInfo.PolicyDescription;
                }
                if (!string.IsNullOrEmpty(parameters.SignaturePolicyInfo.PolicyUri))
                {
                    SigPolicyQualifier sigPolicyQualifier = new SigPolicyQualifier();
                    sigPolicyQualifier.AnyXmlElement = sigDocument.Document.CreateElement("SPURI", "http://uri.etsi.org/01903/v1.3.2#");
                    sigPolicyQualifier.AnyXmlElement.InnerText = parameters.SignaturePolicyInfo.PolicyUri;
                    signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyQualifiers.SigPolicyQualifierCollection.Add(sigPolicyQualifier);
                }
                if (!string.IsNullOrEmpty(parameters.SignaturePolicyInfo.PolicyHash))
                {
                    signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyHash.DigestMethod.Algorithm = parameters.SignaturePolicyInfo.PolicyDigestAlgorithm.URI;
                    signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyHash.DigestValue = Convert.FromBase64String(parameters.SignaturePolicyInfo.PolicyHash);
                }
            }
            signedSignatureProperties.SigningTime = (parameters.SigningDate.HasValue ? parameters.SigningDate.Value : DateTime.Now);

            if (parameters.SignerRole != null && (parameters.SignerRole.CertifiedRoles.Count > 0 || parameters.SignerRole.ClaimedRoles.Count > 0))
            {
                signedSignatureProperties.SignerRole = new Microsoft.Xades.SignerRole();
                foreach (X509Certificate certifiedRole in parameters.SignerRole.CertifiedRoles)
                {
                    signedSignatureProperties.SignerRole.CertifiedRoles.CertifiedRoleCollection.Add(new CertifiedRole
                    {
                        PkiData = certifiedRole.GetRawCertData()
                    });
                }
                foreach (string claimedRole in parameters.SignerRole.ClaimedRoles)
                {
                    signedSignatureProperties.SignerRole.ClaimedRoles.ClaimedRoleCollection.Add(new ClaimedRole
                    {
                        InnerText = claimedRole
                    });
                }
            }
        }
        
        private string createValidIssuerName(X509Certificate2 certificate)
        {
            try
            {
                var x509Name = new BCx509.X509Name(certificate.IssuerName.Name);
                var oids = x509Name.GetOidList();
                var vals = x509Name.GetValueList();

                for (int x = 0; x < oids.Count; x++)
                {
                    var oid = oids[x] as DerObjectIdentifier;

                    // verificar oid de email
                    if (oid.Id == BCx509.X509Name.EmailAddress.Id)
                    {
                        var val = vals[x] as string;
                        // codificar a hex si es necesario
                        if (val != null && val.Length > 0 && val[0] != '#')
                        {
                            var str = new DerIA5String(val);
                            var eStr = str.GetEncoded();

                            val = "#" + BCEncoders.Hex.ToHexString(eStr);
                        }

                        vals[x] = val;
                    }
                }

                var oidSymbols = new Hashtable();
                oidSymbols.Add(BCx509.X509Name.C, "C");
                oidSymbols.Add(BCx509.X509Name.O, "O");
                oidSymbols.Add(BCx509.X509Name.T, "T");
                oidSymbols.Add(BCx509.X509Name.OU, "OU");
                oidSymbols.Add(BCx509.X509Name.CN, "CN");
                oidSymbols.Add(BCx509.X509Name.L, "L");
                oidSymbols.Add(BCx509.X509Name.ST, "ST");
                oidSymbols.Add(BCx509.X509Name.SerialNumber, "SERIALNUMBER");
                //oidSymbols.Add(BCx509.X509Name.EmailAddress, "E"); // ignorar
                oidSymbols.Add(BCx509.X509Name.DC, "DC");
                oidSymbols.Add(BCx509.X509Name.UID, "UID");
                oidSymbols.Add(BCx509.X509Name.Street, "STREET");
                oidSymbols.Add(BCx509.X509Name.Surname, "SURNAME");
                oidSymbols.Add(BCx509.X509Name.GivenName, "GIVENNAME");
                oidSymbols.Add(BCx509.X509Name.Initials, "INITIALS");
                oidSymbols.Add(BCx509.X509Name.Generation, "GENERATION");
                oidSymbols.Add(BCx509.X509Name.UnstructuredAddress, "unstructuredAddress");
                oidSymbols.Add(BCx509.X509Name.UnstructuredName, "unstructuredName");
                oidSymbols.Add(BCx509.X509Name.UniqueIdentifier, "UniqueIdentifier");
                oidSymbols.Add(BCx509.X509Name.DnQualifier, "DN");
                oidSymbols.Add(BCx509.X509Name.Pseudonym, "Pseudonym");
                oidSymbols.Add(BCx509.X509Name.PostalAddress, "PostalAddress");
                oidSymbols.Add(BCx509.X509Name.NameAtBirth, "NameAtBirth");
                oidSymbols.Add(BCx509.X509Name.CountryOfCitizenship, "CountryOfCitizenship");
                oidSymbols.Add(BCx509.X509Name.CountryOfResidence, "CountryOfResidence");
                oidSymbols.Add(BCx509.X509Name.Gender, "Gender");
                oidSymbols.Add(BCx509.X509Name.PlaceOfBirth, "PlaceOfBirth");
                oidSymbols.Add(BCx509.X509Name.DateOfBirth, "DateOfBirth");
                oidSymbols.Add(BCx509.X509Name.PostalCode, "PostalCode");
                oidSymbols.Add(BCx509.X509Name.BusinessCategory, "BusinessCategory");
                oidSymbols.Add(BCx509.X509Name.TelephoneNumber, "TelephoneNumber");

                var components = new ArrayList();

                StringBuilder ava = null;
                for (int i = 0; i < oids.Count; i++)
                {
                    ava = new StringBuilder();
                    appendValue(ava, oidSymbols, (DerObjectIdentifier)oids[i], (string)vals[i]);

                    components.Add(ava);
                }

                var buf = new StringBuilder();
                if (components.Count > 0)
                {
                    buf.Append(components[0].ToString());

                    for (int i = 1; i < components.Count; ++i)
                    {
                        buf.Append(',');
                        buf.Append(components[i].ToString());
                    }
                }

                return buf.ToString();
            }
            catch
            {
                return certificate.IssuerName.Name;
            }
        }

        private void appendValue(StringBuilder buf, IDictionary oidSymbols, DerObjectIdentifier oid, string val)
        {
            string sym = (string)oidSymbols[oid];

            if (sym != null)
            {
                buf.Append(sym);
            }
            else
            {
                buf.Append(oid.Id);
            }

            buf.Append('=');

            int index = buf.Length;

            buf.Append(val);

            int end = buf.Length;

            if (val.StartsWith("\\#"))
            {
                index += 2;
            }

            while (index != end)
            {
                if ((buf[index] == ',') ||
                    (buf[index] == '"') ||
                    (buf[index] == '\\') ||
                    (buf[index] == '+') ||
                    (buf[index] == '=') ||
                    (buf[index] == '<') ||
                    (buf[index] == '>') ||
                    (buf[index] == ';'))
                {
                    buf.Insert(index++, "\\");
                    end++;
                }

                index++;
            }
        }
    }
}
