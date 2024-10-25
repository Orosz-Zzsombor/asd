using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using Microsoft.Win32;
using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Canvas.Parser;
using iText.Kernel.Pdf.Canvas.Parser.Listener;
using System.IO;

namespace WpfPdfReader
{
    public partial class MainWindow : Window
    {
        private VulnerabilityReport _report;

        public MainWindow()
        {
            InitializeComponent();
            _report = new VulnerabilityReport();
        }

        private void ReadPdf(string filePath)
        {
            try
            {
                _report = new VulnerabilityReport
                {
                    ScanDate = DateTime.Now,
                    ScannerVersion = "1.0",
                    TargetInformation = "Sample Network"
                };

                VulnerabilityFinding currentFinding = null;
                string currentSection = null;

                using (PdfReader reader = new PdfReader(filePath))
                using (PdfDocument pdf = new PdfDocument(reader))
                {
                    for (int page = 1; page <= pdf.GetNumberOfPages(); page++)
                    {
                        var strategy = new LocationTextExtractionStrategy();
                        PdfCanvasProcessor parser = new PdfCanvasProcessor(strategy);
                        parser.ProcessPageContent(pdf.GetPage(page));
                        string text = strategy.GetResultantText();
                        var lines = text.Split(new[] { "\n", "\r\n" }, StringSplitOptions.RemoveEmptyEntries);

                        foreach (var line in lines)
                        {
                            string trimmedLine = line.Trim();

                            // Detects the start of a new finding
                            if (Regex.IsMatch(trimmedLine, @"^\d+ - .+"))
                            {
                                if (currentFinding != null)
                                {
                                    _report.Findings.Add(currentFinding);
                                }
                                currentFinding = new VulnerabilityFinding { Title = trimmedLine };
                                currentSection = null;
                            }
                            else if (currentFinding != null)
                            {
                                var sectionMatch = Regex.Match(trimmedLine, @"^(Synopsis|Description|Solution|Risk Factor|See Also|Plugin Information|Plugin Output):?\s*$", RegexOptions.IgnoreCase);
                                if (sectionMatch.Success)
                                {
                                    currentSection = sectionMatch.Groups[1].Value;
                                    currentFinding.AddDetail(currentSection, "");
                                }
                                else if (!string.IsNullOrWhiteSpace(trimmedLine) && currentSection != null)
                                {
                                    if (!trimmedLine.Equals("N/A", StringComparison.OrdinalIgnoreCase) ||
                                        currentSection.Equals("Solution", StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentFinding.AppendToDetail(currentSection, trimmedLine);
                                    }
                                }
                            }
                        }

                        if (currentFinding != null)
                        {
                            _report.Findings.Add(currentFinding);
                        }
                    }
                }

                DisplayFindings(_report.Findings);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error reading PDF: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DisplayFindings(List<VulnerabilityFinding> findings)
        {
            FindingsItemsControl.ItemsSource = null;
            FindingsItemsControl.ItemsSource = findings;
        }

        private void ReadPdfButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "PDF files (*.pdf)|*.pdf|All files (*.*)|*.*",
                Title = "Select a PDF file"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                ReadPdf(openFileDialog.FileName);
            }
        }

        private async void SendInfoButton_Click(object sender, RoutedEventArgs e)
        {
            if (_report.Findings.Count == 0)
            {
                MessageBox.Show("No findings to send.", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Set a category for the report
            string category = "Critical"; // Example category; you can change it based on your logic
            foreach (var finding in _report.Findings)
            {
                finding.Category = category; // This sets the category
            }

            try
            {
                using (var client = new TcpClient("127.0.0.1", 5000))
                using (var networkStream = client.GetStream())
                {
                    var json = JsonSerializer.Serialize(_report);
                    var buffer = Encoding.UTF8.GetBytes(json);
                    await networkStream.WriteAsync(buffer, 0, buffer.Length);
                    MessageBox.Show("Data sent to server.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error sending data: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        private void Button_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
