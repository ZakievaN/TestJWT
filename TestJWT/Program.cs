using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Jose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using RestSharp;

class Program
{
    static void Main(string[] args)
    {
        var serviceAccountId = "ajes3qvv8ov6ip2klaag";
        var keyId = "aje00oqd487fphhl7e7s";
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var headers = new Dictionary<string, object>()
        {
            { "kid", keyId }
        };

        var payload = new Dictionary<string, object>()
        {
            { "aud", "https://iam.api.cloud.yandex.net/iam/v1/tokens" },
            { "iss", serviceAccountId },
            { "iat", now },
            { "exp", now + 3600 }
        };

        RsaPrivateCrtKeyParameters privateKeyParams;
        var pathToPrivateKey = Path.Combine(Directory.GetParent(System.IO.Directory.GetCurrentDirectory()).Parent.Parent.FullName, "private_key_creatio.txt");
        using (var pemStream = File.OpenText(pathToPrivateKey))
        {
            privateKeyParams = new PemReader(pemStream).ReadObject() as RsaPrivateCrtKeyParameters;
        }

        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(DotNetUtilities.ToRSAParameters(privateKeyParams));
            string encodedToken = JWT.Encode(payload, rsa, JwsAlgorithm.PS256, headers);
            var response = GetRestClient((string)payload["aud"], encodedToken);
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var responceContent = (JObject)JsonConvert.DeserializeObject(response.Content);
                var token = responceContent?["iamToken"].Value<string>();
            }
        }
    }

    private static RestResponse GetRestClient(string requestUrl, string token)
    {
        var client = new RestClient(requestUrl);
        var request = new RestRequest("/", Method.Post);
        string jsonToSend = JsonConvert.SerializeObject(new { jwt = token });

        request.AddParameter("application/json", jsonToSend, ParameterType.RequestBody);
        request.RequestFormat = DataFormat.Json;

        return client.Execute(request);
    }
}