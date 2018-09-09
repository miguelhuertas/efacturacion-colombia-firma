using FirmaXades.Utils;
using Microsoft.Xades;
using System;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace FirmaXades.Signature
{
    public class SignatureDocument
    {
        private XadesSignedXml _xadesSignedXml;

        private XmlDocument _document;

        public XmlDocument Document
        {
            get
            {
                return _document;
            }
            set
            {
                _document = value;
            }
        }

        public XadesSignedXml XadesSignature
        {
            get
            {
                return _xadesSignedXml;
            }
            set
            {
                _xadesSignedXml = value;
            }
        }

        public byte[] GetDocumentBytes()
        {
            CheckSignatureDocument(this);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                Save(memoryStream);
                return memoryStream.ToArray();
            }
        }

        public void Save(string fileName)
        {
            CheckSignatureDocument(this);
            XmlWriterSettings xmlWriterSettings = new XmlWriterSettings();
            xmlWriterSettings.Encoding = new UTF8Encoding();
            using (XmlWriter w = XmlWriter.Create(fileName, xmlWriterSettings))
            {
                Document.Save(w);
            }
        }

        public void Save(Stream output)
        {
            XmlWriterSettings xmlWriterSettings = new XmlWriterSettings();
            xmlWriterSettings.Encoding = new UTF8Encoding();
            using (XmlWriter w = XmlWriter.Create(output, xmlWriterSettings))
            {
                Document.Save(w);
            }
        }

        internal void UpdateDocument()
        {
            if (_document == null)
            {
                _document = new XmlDocument();
            }
            if (_document.DocumentElement != null)
            {
                XmlNode xmlNode = _document.SelectSingleNode("//*[@Id='" + _xadesSignedXml.Signature.Id + "']");
                if (xmlNode != null)
                {
                    XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(_document.NameTable);
                    xmlNamespaceManager.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");
                    xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
                    XmlNode xmlNode2 = xmlNode.SelectSingleNode("ds:Object/xades:QualifyingProperties", xmlNamespaceManager);
                    XmlNode xmlNode3 = xmlNode.SelectSingleNode("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties", xmlNamespaceManager);
                    if (xmlNode3 != null)
                    {
                        xmlNode3.InnerXml = _xadesSignedXml.XadesObject.QualifyingProperties.UnsignedProperties.GetXml().InnerXml;
                    }
                    else
                    {
                        xmlNode3 = _document.ImportNode(_xadesSignedXml.XadesObject.QualifyingProperties.UnsignedProperties.GetXml(), true);
                        xmlNode2.AppendChild(xmlNode3);
                    }
                }
                else
                {
                    XmlElement xml = _xadesSignedXml.GetXml();
                    byte[] bytes = XMLUtil.ApplyTransform(xml, new XmlDsigC14NTransform());
                    XmlDocument xmlDocument = new XmlDocument();
                    xmlDocument.PreserveWhitespace = true;
                    xmlDocument.LoadXml(Encoding.UTF8.GetString(bytes));
                    XmlNode newChild = _document.ImportNode(xmlDocument.DocumentElement, true);
                    _xadesSignedXml.GetSignatureElement().AppendChild(newChild);
                }
            }
            else
            {
                _document.LoadXml(_xadesSignedXml.GetXml().OuterXml);
            }
        }

        internal static void CheckSignatureDocument(SignatureDocument sigDocument)
        {
            if (sigDocument == null)
            {
                throw new ArgumentNullException("sigDocument");
            }
            if (sigDocument.Document == null || sigDocument.XadesSignature == null)
            {
                throw new Exception("No existe información sobre la firma");
            }
        }
    }
}