using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using FirmaXades;
using FirmaXades.Crypto;
using FirmaXades.Signature.Parameters;

namespace eFacturacionColombia.Firma
{

    public class FirmaElectronica
    {
        #region Propiedades públicas

        public RolFirmante RolFirmante { get; set; }

        public string RutaCertificado { get; set; }

        public string ClaveCertificado { get; set; }

        public string EmisorCertificado { get; set; }

        #endregion

        #region Contructores

        /// <summary>
        /// Crea una instancia para la firma electrónica.
        /// </summary>
        /// <remarks>
        /// Completar las propiedades antes de usar los métodos.
        /// </remarks>
        public FirmaElectronica()
        {

        }

        /// <summary>
        /// Crea una instancia para la firma electrónica con las propiedades necesarias.
        /// </summary>
        /// <param name="_rolFirmante"> Rol de firmante </param>
        /// <param name="_rutaCertificado"> Ruta completa del certificado .p12 (PKCS #12) </param>
        /// <param name="_claveCertificado"> Contraseña del certificado .p12 (PKCS #12) </param>
        /// <param name="_emisorCertificado"> Emisor del certificado; usar si falla la validación. </param>
        /// <returns> El array de bytes resultante. </returns>
        public FirmaElectronica(RolFirmante _rolFirmante, string _rutaCertificado,
            string _claveCertificado, string _emisorCertificado = null)
        {
            RolFirmante = _rolFirmante;
            RutaCertificado = _rutaCertificado;
            ClaveCertificado = _claveCertificado;
            EmisorCertificado = _emisorCertificado;
        }

        #endregion

        #region Métodos públicos

        /// <summary>
        /// Firma el archivo XML indicado.
        /// </summary>
        /// <param name="_archivoXml"> Archivo XML a firmar </param>
        /// <param name="_tipo"> Tipo de documento </param>
        /// <param name="_fecha"> Fecha de firma </param>
        /// <returns> El array de bytes resultante. </returns>
        public byte[] Firmar(FileInfo _archivoXml, TipoDocumento _tipo, DateTime _fecha)
        {
            _verificarPropiedades();

            var bytesXml = File.ReadAllBytes(_archivoXml.FullName);

            return _firmar(bytesXml, _tipo, _fecha);
        }

        /// <summary>
        /// Firma el contenido XML indicado.
        /// </summary>
        /// <param name="_contenidoXml"> Contenido XML a firmar </param>
        /// <param name="_tipo"> Tipo de documento </param>
        /// <param name="_fecha"> Fecha de firma </param>
        /// <returns> El array de bytes resultante. </returns>
        public byte[] Firmar(string _contenidoXml, TipoDocumento _tipo, DateTime _fecha)
        {
            _verificarPropiedades();

            var bytesXml = Encoding.UTF8.GetBytes(_contenidoXml);

            return _firmar(bytesXml, _tipo, _fecha);
        }

        /// <summary>
        /// Firma el array de bytes indicado.
        /// </summary>
        /// <param name="_bytesXml"> Bytes a firmar </param>
        /// <param name="_tipo"> Tipo de documento </param>
        /// <param name="_fecha"> Fecha de firma </param>
        /// <returns> El array de bytes resultante. </returns>
        public byte[] Firmar(byte[] _bytesXml, TipoDocumento _tipo, DateTime _fecha)
        {
            _verificarPropiedades();

            return _firmar(_bytesXml, _tipo, _fecha);
        }

        #endregion

        #region Métodos privados

        private void _verificarPropiedades()
        {
            if (string.IsNullOrEmpty(RutaCertificado) || !File.Exists(RutaCertificado))
            {
                throw new FileNotFoundException("No se encuentra el certificado .p12 (PKCS #12) a usar.");
            }
        }

        private byte[] _firmar(byte[] _bytesXml, TipoDocumento _tipo, DateTime _fecha)
        {
            var parameters = new SignatureParameters();
            parameters.SignatureMethod = SignatureMethod.RSAwithSHA1;
            parameters.DigestMethod = DigestMethod.SHA1;
            parameters.SigningDate = _fecha;
            parameters.SignerRole = new SignerRole();
            var signerRole = (RolFirmante == RolFirmante.FACTURANTE ? "supplier" : "third party");
            parameters.SignerRole.ClaimedRoles.Add(signerRole);

            parameters.SignatureDestination = new SignatureXPathExpression();
            parameters.SignatureDestination.Namespaces.Add("fe", "http://www.dian.gov.co/contratos/facturaelectronica/v1");
            parameters.SignatureDestination.Namespaces.Add("cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
            parameters.SignatureDestination.Namespaces.Add("cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2");
            parameters.SignatureDestination.Namespaces.Add("clm54217", "urn:un:unece:uncefact:codelist:specification:54217:2001");
            parameters.SignatureDestination.Namespaces.Add("clm66411", "urn:un:unece:uncefact:codelist:specification:66411:2001");
            parameters.SignatureDestination.Namespaces.Add("clmIANAMIMEMediaType", "urn:un:unece:uncefact:codelist:specification:IANAMIMEMediaType:2003");
            parameters.SignatureDestination.Namespaces.Add("ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
            parameters.SignatureDestination.Namespaces.Add("qdt", "urn:oasis:names:specification:ubl:schema:xsd:QualifiedDatatypes-2");
            parameters.SignatureDestination.Namespaces.Add("sts", "http://www.dian.gov.co/contratos/facturaelectronica/v1/Structures");
            parameters.SignatureDestination.Namespaces.Add("udt", "urn:un:unece:uncefact:data:specification:UnqualifiedDataTypesSchemaModule:2");
            parameters.SignatureDestination.Namespaces.Add("xsi", "http://www.w3.org/2001/XMLSchema-instance");

            if (_tipo == TipoDocumento.FACTURA)
                parameters.SignatureDestination.XPathExpression = "/fe:Invoice/ext:UBLExtensions/ext:UBLExtension[2]/ext:ExtensionContent";
            else if (_tipo == TipoDocumento.NOTA_DEBITO)
                parameters.SignatureDestination.XPathExpression = "/fe:DebitNote/ext:UBLExtensions/ext:UBLExtension[2]/ext:ExtensionContent";
            else if (_tipo == TipoDocumento.NOTA_CREDITO)
                parameters.SignatureDestination.XPathExpression = "/fe:CreditNote/ext:UBLExtensions/ext:UBLExtension[2]/ext:ExtensionContent";

            parameters.SignaturePolicyInfo = new SignaturePolicyInfo();
            parameters.SignaturePolicyInfo.PolicyIdentifier = "https://facturaelectronica.dian.gov.co/politicadefirma/v2/politicadefirmav2.pdf";
            parameters.SignaturePolicyInfo.PolicyDescription = "Política\u00a0de\u00a0firma\u00a0para\u00a0facturas\u00a0electrónicas\u00a0de\u00a0la\u00a0República\u00a0de Colombia";
            parameters.SignaturePolicyInfo.PolicyHash = "sbcECQ7v+y/m3OcBCJyvmkBhtFs=";
            parameters.SignaturePackaging = SignaturePackaging.ENVELOPED;
            parameters.InputMimeType = "text/xml";

            var certificate = new X509Certificate2(RutaCertificado, ClaveCertificado);
            parameters.Signer = new Signer(certificate);
            parameters.CertificateIssuerName = EmisorCertificado;

            using (var input = new MemoryStream(_bytesXml))
            {
                var xades = new XadesService();
                var signatureDocument = xades.Sign(input, parameters);

                var output = new MemoryStream();
                signatureDocument.Save(output);

                return output.ToArray();
            }
        }

        #endregion
    }

}