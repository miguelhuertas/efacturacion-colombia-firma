using FirmaXades.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using System;
using System.IO;
using System.Net;
using System.Text;

namespace FirmaXades.Clients
{
    public class TimeStampClient
    {
        private string _url;

        private string _user;

        private string _password;

        public TimeStampClient(string url)
        {
            _url = url;
        }

        public TimeStampClient(string url, string user, string password)
            : this(url)
        {
            _user = user;
            _password = password;
        }

        public byte[] GetTimeStamp(byte[] hash, DigestMethod digestMethod, bool certReq)
        {
            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
            timeStampRequestGenerator.SetCertReq(certReq);
            BigInteger nonce = BigInteger.ValueOf(DateTime.Now.Ticks);
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.Generate(digestMethod.Oid, hash, nonce);
            byte[] encoded = timeStampRequest.GetEncoded();
            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(_url);
            httpWebRequest.Method = "POST";
            httpWebRequest.ContentType = "application/timestamp-query";
            httpWebRequest.ContentLength = encoded.Length;
            if (!string.IsNullOrEmpty(_user) && !string.IsNullOrEmpty(_password))
            {
                string s = $"{_user}:{_password}";
                httpWebRequest.Headers["Authorization"] = "Basic " + Convert.ToBase64String(Encoding.Default.GetBytes(s), Base64FormattingOptions.None);
            }
            Stream requestStream = httpWebRequest.GetRequestStream();
            requestStream.Write(encoded, 0, encoded.Length);
            requestStream.Close();
            HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            if (httpWebResponse.StatusCode != HttpStatusCode.OK)
            {
                throw new Exception("El servidor ha devuelto una respuesta no válida");
            }
            Stream stream = new BufferedStream(httpWebResponse.GetResponseStream());
            TimeStampResponse timeStampResponse = new TimeStampResponse(stream);
            stream.Close();
            timeStampResponse.Validate(timeStampRequest);
            if (timeStampResponse.TimeStampToken == null)
            {
                throw new Exception("El servidor no ha devuelto ningún sello de tiempo");
            }
            return timeStampResponse.TimeStampToken.GetEncoded();
        }
    }
}
