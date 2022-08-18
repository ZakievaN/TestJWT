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
    private static readonly string TokenUrl = "https://iam.api.cloud.yandex.net/iam/v1/tokens";
    //private static readonly string ProductUrl = "https://functions.yandexcloud.net/d4epidpa3save57i2a97";
    private static readonly string ProductUrl = "https://d5dg6l00nb1job0ia1k8.apigw.yandexcloud.net/apig/products";


    static void Main(string[] args)
    {
        var jwt = GetJwtToken();

        var response = GetRestClientToken(TokenUrl, jwt);
        if (response.StatusCode == System.Net.HttpStatusCode.OK)
        {
            var responceContent = (JObject)JsonConvert.DeserializeObject(response.Content);
            var token = responceContent?["iamToken"].Value<string>();

            if (token != null)
            {
                var products = GetProducts(token);
            }
        }
    }

    private static string GetProducts(string token)
    {
        var responceContent = string.Empty;
        var response = GetRestClient(ProductUrl, token);
        if (response.StatusCode == System.Net.HttpStatusCode.OK)
        {
            responceContent = (string)JsonConvert.DeserializeObject(response.Content);
        }
        return responceContent;
    }

    private static string GetJwtToken()
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
            { "aud", TokenUrl },
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

        var encodedToken = string.Empty;

        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(DotNetUtilities.ToRSAParameters(privateKeyParams));
            encodedToken = JWT.Encode(payload, rsa, JwsAlgorithm.PS256, headers);
        }

        return encodedToken;
    }

    private static RestResponse GetRestClientToken(string requestUrl, string token)
    {
        var client = new RestClient(requestUrl);
        var request = new RestRequest("/", Method.Post);
        string jsonToSend = JsonConvert.SerializeObject(new { jwt = token });

        request.AddParameter("application/json", jsonToSend, ParameterType.RequestBody);
        request.RequestFormat = DataFormat.Json;

        return client.Execute(request);
    }
    
    private static RestResponse GetRestClient(string requestUrl, string token)
    {
        var client = new RestClient(requestUrl);
        var request = new RestRequest("", Method.Get);
        
        request.AddParameter("dtfrom", "2022-07-01T00:00:01.0000001Z");
        request.AddParameter("page_number", 1);
        request.AddParameter("page_size", 10);
        request.AddHeader("Authorization", $"Bearer {token}");

        return client.Execute(request);
    }
}