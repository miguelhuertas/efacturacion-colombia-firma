using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace FirmaXades.Clients
{
    public class OcspClient
    {
        public byte[] QueryBinary(X509Certificate eeCert, X509Certificate issuerCert, string url)
        {
            OcspReq ocspReq = GenerateOcspRequest(issuerCert, eeCert.SerialNumber);
            return PostData(url, ocspReq.GetEncoded(), "application/ocsp-request", "application/ocsp-response");
        }

        public string GetAuthorityInformationAccessOcspUrl(X509Certificate cert)
        {
            List<string> list = new List<string>();
            try
            {
                Asn1Object extensionValue = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);
                if (extensionValue == null)
                {
                    return null;
                }
                Asn1Sequence asn1Sequence = (Asn1Sequence)extensionValue;
                IEnumerator enumerator = asn1Sequence.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    Asn1Sequence asn1Sequence2 = (Asn1Sequence)enumerator.Current;
                    DerObjectIdentifier derObjectIdentifier = (DerObjectIdentifier)asn1Sequence2[0];
                    if (derObjectIdentifier.Id.Equals("1.3.6.1.5.5.7.48.1"))
                    {
                        Asn1TaggedObject obj = (Asn1TaggedObject)asn1Sequence2[1];
                        GeneralName instance = GeneralName.GetInstance(obj);
                        list.Add(DerIA5String.GetInstance(instance.Name).GetString());
                    }
                }
            }
            catch (Exception)
            {
                return null;
            }
            return list[0];
        }

        public FirmaXades.Clients.CertificateStatus ProcessOcspResponse(byte[] binaryResp)
        {
            if (binaryResp.Length != 0)
            {
                OcspResp ocspResp = new OcspResp(binaryResp);
                FirmaXades.Clients.CertificateStatus result = FirmaXades.Clients.CertificateStatus.Unknown;
                if (ocspResp.Status != 0)
                {
                    throw new Exception("Unknow status '" + ocspResp.Status + "'.");
                }
                BasicOcspResp basicOcspResp = (BasicOcspResp)ocspResp.GetResponseObject();
                if (basicOcspResp.Responses.Length == 1)
                {
                    SingleResp singleResp = basicOcspResp.Responses[0];
                    object certStatus = singleResp.GetCertStatus();
                    if (certStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                    {
                        result = FirmaXades.Clients.CertificateStatus.Good;
                    }
                    else if (certStatus is RevokedStatus)
                    {
                        result = FirmaXades.Clients.CertificateStatus.Revoked;
                    }
                    else if (certStatus is UnknownStatus)
                    {
                        result = FirmaXades.Clients.CertificateStatus.Unknown;
                    }
                }
                return result;
            }
            return FirmaXades.Clients.CertificateStatus.Unknown;
        }

        private byte[] PostData(string url, byte[] data, string contentType, string accept)
        {
            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(url);
            httpWebRequest.Method = "POST";
            httpWebRequest.ContentType = contentType;
            httpWebRequest.ContentLength = data.Length;
            httpWebRequest.Accept = accept;
            Stream requestStream = httpWebRequest.GetRequestStream();
            requestStream.Write(data, 0, data.Length);
            requestStream.Close();
            HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            Stream responseStream = httpWebResponse.GetResponseStream();
            byte[] result;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                responseStream.CopyTo(memoryStream);
                result = memoryStream.ToArray();
                responseStream.Close();
            }
            return result;
        }

        protected static Asn1Object GetExtensionValue(X509Certificate cert, string oid)
        {
            if (cert != null)
            {
                byte[] octets = cert.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();
                if (octets != null)
                {
                    Asn1InputStream asn1InputStream = new Asn1InputStream(octets);
                    return asn1InputStream.ReadObject();
                }
                return null;
            }
            return null;
        }

        private OcspReq GenerateOcspRequest(X509Certificate issuerCert, BigInteger serialNumber)
        {
            CertificateID id = new CertificateID("1.3.14.3.2.26", issuerCert, serialNumber);
            return GenerateOcspRequest(id);
        }

        private OcspReq GenerateOcspRequest(CertificateID id)
        {
            OcspReqGenerator ocspReqGenerator = new OcspReqGenerator();
            ocspReqGenerator.AddRequest(id);
            BigInteger bigInteger = BigInteger.ValueOf(default(DateTime).Ticks);
            var arrayList = new List<object>();
            Hashtable hashtable = new Hashtable();
            arrayList.Add(OcspObjectIdentifiers.PkixOcsp);
            Asn1OctetString value = new DerOctetString(new DerOctetString(new byte[10]
            {
            1,
            3,
            6,
            1,
            5,
            5,
            7,
            48,
            1,
            1
            }));
            hashtable.Add(OcspObjectIdentifiers.PkixOcsp, new X509Extension(false, value));
            ocspReqGenerator.SetRequestExtensions(new X509Extensions(arrayList, hashtable));
            return ocspReqGenerator.Generate();
        }
    }
}
