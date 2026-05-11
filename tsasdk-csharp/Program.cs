using System;
using SignDoc.TsaSdk.Crypto;
using SignDoc.TsaSdk.Tsp;

namespace tsasdk_csharp
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // SHA-256 demo
                Console.WriteLine("--- SHA-256 Demo ---");
                var client = new TSAClient(
                    tsaUrl: "http://test1.tsa.cn/tsa",
                    username: "tsademo",
                    password: "tsademo",
                    defaultAlgorithm: DigestAlgorithm.SHA256
                );

                byte[] hash = HashUtil.ComputeHash("hello tsa", DigestAlgorithm.SHA256);
                Console.WriteLine($"SHA-256 hash: {BitConverter.ToString(hash).Replace("-", "").ToLower()}");

                byte[] token = client.TimestampHash(hash, DigestAlgorithm.SHA256);
                string time = client.GetTime(token);
                Console.WriteLine($"Timestamp: {time}");

                // SM3 demo
                Console.WriteLine("\n--- SM3 Demo ---");
                var sm3Client = new TSAClient(
                    tsaUrl: "http://test1.tsa.cn/tsa",
                    username: "tsademo",
                    password: "tsademo",
                    defaultAlgorithm: DigestAlgorithm.SM3
                );

                byte[] sm3Hash = HashUtil.ComputeHash("hello tsa sm3", DigestAlgorithm.SM3);
                Console.WriteLine($"SM3 hash: {BitConverter.ToString(sm3Hash).Replace("-", "").ToLower()}");

                byte[] sm3Token = sm3Client.TimestampHash(sm3Hash, DigestAlgorithm.SM3);
                string sm3Time = sm3Client.GetTime(sm3Token);
                Console.WriteLine($"SM3 Timestamp: {sm3Time}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }
    }
}
