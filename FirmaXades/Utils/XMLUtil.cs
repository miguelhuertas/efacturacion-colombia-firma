using Microsoft.Xades;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace FirmaXades.Utils
{
    internal class XMLUtil
    {
        public static byte[] ApplyTransform(XmlElement element, System.Security.Cryptography.Xml.Transform transform)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(element.OuterXml);
            using (MemoryStream obj = new MemoryStream(bytes))
            {
                transform.LoadInput(obj);
                using (MemoryStream memoryStream = (MemoryStream)transform.GetOutput(typeof(Stream)))
                {
                    return memoryStream.ToArray();
                }
            }
        }

        public static byte[] ComputeValueOfElementList(XadesSignedXml xadesSignedXml, ArrayList elementXpaths)
        {
            XmlElement signatureElement = xadesSignedXml.GetSignatureElement();
            List<XmlAttribute> allNamespaces = xadesSignedXml.GetAllNamespaces(signatureElement);
            XmlDocument ownerDocument = signatureElement.OwnerDocument;
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(ownerDocument.NameTable);
            xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            xmlNamespaceManager.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");
            using (MemoryStream memoryStream = new MemoryStream())
            {
                foreach (string elementXpath in elementXpaths)
                {
                    XmlNodeList xmlNodeList = signatureElement.SelectNodes(elementXpath, xmlNamespaceManager);
                    if (xmlNodeList.Count == 0)
                    {
                        throw new CryptographicException("Element " + elementXpath + " not found while calculating hash");
                    }
                    foreach (XmlNode item in xmlNodeList)
                    {
                        XmlElement xmlElement = (XmlElement)item.Clone();
                        xmlElement.SetAttribute("xmlns:" + XadesSignedXml.XmlDSigPrefix, "http://www.w3.org/2000/09/xmldsig#");
                        foreach (XmlAttribute item2 in allNamespaces)
                        {
                            xmlElement.SetAttribute(item2.Name, item2.Value);
                        }
                        byte[] array = ApplyTransform(xmlElement, new XmlDsigC14NTransform());
                        memoryStream.Write(array, 0, array.Length);
                    }
                }
                return memoryStream.ToArray();
            }
        }

        public static XmlDocument LoadDocument(Stream input)
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.Load(input);
            return xmlDocument;
        }
    }
}