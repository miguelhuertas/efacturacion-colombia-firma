# eFacturacionColombia.Firma (C#)

[![version](https://img.shields.io/badge/version-0.9.0-blue.svg)](#) [![status](https://img.shields.io/badge/status-working-brightgreen.svg)](#)

**eFacturacionColombia.Firma** es una librería *no oficial* desarrollada en C#, que permite firmar los documentos XML (facturas y notas de débito/crédito) que se presentan a la DIAN de Colombia para el proceso de facturación electrónica.



### Motivación

Desde el 1 de enero del 2019 la facturación electrónica para los contribuyentes en Colombia será obligatoria, y en la actualidad muchas empresas y personas obligadas no la han implementado. 

Aunque la información técnica proveída por la DIAN debería ser suficiente, encontrar recursos en .NET para este proceso resulta ser bastante difícil. La generación de documentos XML y consumo de servicios web puede ser laborioso pero se puede hacer sin inconvenientes, en cambio la firma requerida por la DIAN puede ser extremadamente difícil de hacer, hasta el punto de ser necesario adquirir soluciones costosas.

Se libera esta librería con el objetivo de facilitar la implementación en plataformas .NET.



### Requisitos

Para poder generar, firmar y emitir documentos electrónicos (facturas y notas de débito/crédito) ante la DIAN, se deben cumplir los siguientes requisitos:

* Estar registrado como facturador electrónico
* Disponer de un certificado digital para la facturación electrónica

Para mayor información ver los recursos disponibles en [DIAN - Facturación Electrónica](https://www.dian.gov.co/fizcalizacioncontrol/herramienconsulta/FacturaElectronica/).



### Uso

La clase `FirmaElectronica` contiene un sencillo método (en tres variantes) para firmar los documentos electrónicos, que retorna el array de bytes resultante:

```csharp
using eFacturacionColombia;
using eFacturacionColombia.Firma;

// crear instancia
var firma = new FirmaElectronica
{
	RolFirmante = RolFirmante.FACTURANTE,
	RutaCertificado = "path/to/certificate.p12",
	ClaveCertificado = "password here"
};

// usar horario colombiano
var fecha = DateTimeHelper.GetColombianDate();

// variante 1:
// firmar archivo
var archivoXml = new FileInfo("path/to/unsigned-factura.xml");
var bytesArchivoFirmado = firma.Firmar(archivoXml, TipoDocumento.FACTURA, fecha);

// variante 2:
// firmar contenido
var contenidoXml = "<?xml ...";
var bytesContenidoFirmado = firma.Firmar(contenidoXml, TipoDocumento.FACTURA, fecha);

// variante 3:
// firmar bytes
var bytesXml = new byte[13042];
var bytesXmlFirmado = firma.Firmar(bytesXml, TipoDocumento.FACTURA, fecha);

// guardar xml (opcional)
File.WriteAllBytes("path/to/signed-factura.xml", bytesXmlFirmado);
```

Si la validación técnica de la firma genera el siguiente error (desde el servicio web):

```
com.indra.mmdd.signature.exceptions.ValidateException: xades4j.verification.CertRefUtils$1: Verification failed for property 'SigningCertificate': Invalid issue name
```

Significa que el *CertificateIssuerName* ‒ generado por la librería ‒ de la firma no es válido, en este caso solicitar al proveedor del certificado la cadena válida, y asignarla *manualmente* usando la propiedad `EmisorCertificado` de la clase `FirmaElectronica`:

```csharp
var firma = new FirmaElectronica
{
	RolFirmante = RolFirmante.FACTURANTE,
	RutaCertificado = "path/to/certificate.p12",
	ClaveCertificado = "password here",
	EmisorCertificado = "C=CO,L=Bogota D.C.,O=..."
};
```



**Nota:** Los bytes resultantes del proceso no se deben modificar (pasándolos a otra codificación o cargándolos en un `XmlDocument`) antes de guardarlos o comprimirlos para enviarlos a la DIAN porque invalidarán la firma.



### Reconocimientos

Este proyecto utiliza las siguientes librerías:

- [Microsoft.Xades](#reconocimientos) por *Microsoft France*
- [BouncyCastle.Crypto](https://www.bouncycastle.org/csharp/) por *The Legion Of The Bouncy Castle*
- [FirmaXadesNet](https://github.com/ctt-gob-es/FirmaXadesNet) por *el Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena*



### Contribuir

Aunque este repositorio no es de *Open-Contribution*, se puede aportar:

- Reportando detalladamente algún problema
- Enviando correcciones o actualizaciones necesarias
- Haciendo una donación al autor de este proyecto



### Autor

Miguel Huertas <contacto@miguel-huertas.net>



### Licencia

Revisar detalles en el archivo [LICENCE](LICENCE).





> El autor de este proyecto, por cuestiones de tiempo, no brindará soporte para la implementación al menos que se trate de algo simple (sin estar obligado).
>
> **Por otra parte, el autor de este proyecto, pone a su disposición una solución .NET de paga para todo el proceso de facturación electrónica así como asesoría para su implementación**.
