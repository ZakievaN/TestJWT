using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Jose;
using Newtonsoft.Json;
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

        var privateKey = "-----BEGIN PRIVATE KEY-----\r\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDHRxLcN+V/SnoJ\r\njKJUd0O9qvaKqySYbOjdvZPDyhjiOpEBxG34ISvB/0Hh8GKiS6h3f9szzi8rgDTg\r\nH37eczdy0BrP2qV7E2VTGmIujaJLUq8J8eVkaSsuGzXwdqmKZkvAdb0/WsMR95LS\r\nwFUl+GPsLEXjBDmh9uCyvZyfmXIpFaJm5vK3O4uYRAyF/H0fOjbhAEkI08rpwGBl\r\n7/25jtF1OEy8uJb8e6mBm1URa0tFGaXvygTq3Er4DCpErSpdJelImQ+bIb9Y1D30\r\nZochEC+VDPULFGsCxa/fJKoQOWWjqzlQip1YSgcVEEcEhySjrjZ2qc3fIiAESgB0\r\nbIfJHSzBAgMBAAECggEAJRTJoqbYEqamLM65iiQjO9DrTYRpK9/gORrEu0MI/FfP\r\nkdeeavSpMtEvzj4v7GlNsObewDYWuu6BaE8UCYrA/6FPy+uwrUU/roYTTPxX/dIl\r\n9iDIAbY8LbksgVFjXPiKEgcWrwpRkC9UZ9kYPxeIaHMYkhTAMK5Cw5/a3CvufUxQ\r\nI26hY5z7xmkoS7O81azaEo5vlZrSvfrOChIxpltD6BXrnY97enx3MU3BGYO5gfH8\r\nNsG01TmoUcvvjBZ5gWqJKB7TMrHZgpG5U+UBpZUSoMk5ASDUvFVCLRqXonhm8JZ9\r\naqSp1oLUwlfrDj4DZJxj3l8UkgeneVpEDZxJxjedfQKBgQDs7S/InN9MxSEHSabt\r\ncUmkLMDxvkZPZs+sD34C+8MqyIqRpEf767Lyrn7CfMk+v/Q7eaZlqbxRpmNr2Xbm\r\nbWBqvJGTf8ZLNfcJGyonlmB4/6J+71gvACPO+a3i3NrUKzWmYH9AITT1o6pRTP8S\r\n3iJRXDYp3uy2muMmiC5luMMX0wKBgQDXUftp9MbF0T+5FDJIdxf7EZwvwxTVPH/5\r\n0xIypzBNnkK4BUA9JabGyJh7Kyv8/ifpHOcm8xDI/EHqsN0ZWIAv4Bp53utvV1b2\r\noruomm+5e8maOoNpTtrstRTwXXVAkRhY9FM7OaEZ+65FBam/oxTxaOaS/qvm90sn\r\nbbyKQjNAmwKBgFHDlR79jE55JWnXcCU3WHuw+jEzQh5606aEfi9XZUYpiTCz6ie1\r\ncr8vmw1RdT4TjpzL4bHp/tSKwHrixJbHHmQXiYHGsc8Y45Uf689XpRl81z5JKTyn\r\nJrRyFCFbqKVZ+Bzf5mpiS12OSuPd15VSVbOQSBzxEu39y/BrRN/UAHgDAoGAF03L\r\nLSON49kK0YgrDQa+tLCqO80cUxvSKgK7JHpN0wi+5dXDpxqNG1SYlDQO9bm4LhWv\r\nutpxxZ7vr2vm8hhO/1983hXPW2STh+wC7XORhfyszCFrGZmsPhQ3KPCkgRFzFiWT\r\nYISTOBGyQcwkHBaVbK9SzTP8/Olk2+aXkksp6uMCgYAp8/6KVDcSOZ7/mTZd/F+/\r\nRP4A6lwcVbMp2s4d+kkYLBPs9GpIpk8AWfGxvfilRbJRMrRwuJLJTAGBY3QPEW9v\r\nWoki2O8Qd4HCcMXyO2Lxkw2bfGB+CRy7j3LYM7yDKW3heI+DQAW+Y7/nkqzw4M5d\r\nXUqCdUqtciUcvj+YYKcA1w==\r\n-----END PRIVATE KEY-----";

        RsaPrivateCrtKeyParameters privateKeyParams;
        using (var pemStream = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(privateKey))))
        {
            privateKeyParams = new PemReader(pemStream).ReadObject() as RsaPrivateCrtKeyParameters;
        }

        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(DotNetUtilities.ToRSAParameters(privateKeyParams));
            string encodedToken = JWT.Encode(payload, rsa, JwsAlgorithm.PS256, headers);
            var response = GetRestClient((string)payload["aud"], encodedToken);
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