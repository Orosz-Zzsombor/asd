using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ServerConsoleApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Starting server...");
            await StartServer();
        }

        private static async Task StartServer()
        {
            var listener = new TcpListener(IPAddress.Loopback, 5000);
            listener.Start();
            Console.WriteLine("Server started. Listening for connections...");

            while (true)
            {
                try
                {
                    var client = await listener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleClient(client));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Server error: {ex.Message}");
                }
            }
        }

        private static async Task HandleClient(TcpClient client)
        {
            try
            {
                using var networkStream = client.GetStream();
                using var reader = new StreamReader(networkStream, Encoding.UTF8);

                // Read the incoming data from the client
                var json = await reader.ReadToEndAsync();
                var vulnerabilityReport = JsonSerializer.Deserialize<VulnerabilityReport>(json);

                Console.WriteLine("\nReceived Vulnerability Report:");
                foreach (var vulnerability in vulnerabilityReport.Findings)
                {
                    Console.WriteLine($"Title: {vulnerability.Title}");
                    foreach (var detail in vulnerability.Details)
                    {
                        Console.WriteLine($"{detail.Key}: {detail.Value}");
                    }
                }

                // Assigning a category to each vulnerability finding
                foreach (var vulnerability in vulnerabilityReport.Findings)
                {
                    vulnerability.Category = "Category Example"; // Assign an example category here
                }

                // Send the updated findings back to the client
                var responseJson = JsonSerializer.Serialize(vulnerabilityReport);
                var responseBuffer = Encoding.UTF8.GetBytes(responseJson);
                await networkStream.WriteAsync(responseBuffer, 0, responseBuffer.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling client: {ex.Message}");
            }
        }
    }

    public class VulnerabilityFinding
    {
        public string Title { get; set; }
        public Dictionary<string, string> Details { get; set; } = new Dictionary<string, string>();
        public string Category { get; set; } // Added for category
    }

    public class VulnerabilityReport
    {
        public DateTime ScanDate { get; set; }
        public string ScannerVersion { get; set; }
        public string TargetInformation { get; set; }
        public List<VulnerabilityFinding> Findings { get; set; } = new List<VulnerabilityFinding>();
    }
}
