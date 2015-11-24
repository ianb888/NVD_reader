using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml.Serialization;
using JNIsolutions.Core.Tools.CommandLine;
using SerializerLib;

namespace NVD_reader
{
    class Program
    {
        const string docDir = @"H:\My Documents\NVD\";

        static List<CVE_entry> CVE_data = new List<CVE_entry>();
        static int countRemoved = 0;

        static void Main(string[] args)
        {
            string binaryDataFile = docDir + "nvdcve-consolidated.dat";

            Console.WriteLine("Loading saved data from file...");

            using (var spin = new ConsoleSpinner())
            {
                spin.Start();
                LoadBinaryData(binaryDataFile);
                spin.Stop();
            }

            Console.WriteLine("Loading completed.");

            // If the number of years is specified on the command line
            // then download the historical data first.
            if (args.Length != 0)
            {
                int numYears;
                bool test = int.TryParse(args[0], out numYears);

                if (test)
                {
                    if (numYears >= 0)
                    {
                        UpdateHistoricalData(numYears);
                    }
                }
            }

            DownloadModifiedData();

            if (countRemoved > 0)
            {
                Console.WriteLine("Removed {0} duplicate records from consolidated data.", countRemoved);
            }

            Console.WriteLine("Saving data to file...");
            using (var spin = new ConsoleSpinner())
            {
                spin.Start();
                SaveBinaryData(binaryDataFile);
                spin.Stop();
            }
            Console.WriteLine("Saving completed.");
#if DEBUG
            Console.WriteLine("Press the ANY key to exit!");
            Console.ReadLine();
#endif
        }

        private static void UpdateHistoricalData(int numOfYears)
        {
            try
            {
                bool useCacheFile;

                DateTime thisDay = DateTime.Today;

                for (int i = thisDay.Year - numOfYears; i <= thisDay.Year; i++)
                {
                    string downloadURL = string.Format("{0}\\nvdcve-{1}.xml", docDir, i);

                    if (File.Exists(downloadURL))
                    {
                        useCacheFile = true;
                        Console.WriteLine("Using cached historical CVE data from: {0}", downloadURL);
                    }
                    else
                    {
                        downloadURL = string.Format(@"https://nvd.nist.gov/download/nvdcve-{0}.xml.zip", i);
                        useCacheFile = false;
                        Console.WriteLine("Starting Download of Historical CVE data from: {0}", downloadURL);
                    }

                    ParseXmlData(DownloadDataStream(downloadURL, string.Format("nvdcve-{0}.xml", i), useCacheFile));
                    Console.WriteLine("Completed processing historical CVE data from: {0}", downloadURL);
                    Console.WriteLine("==================================================================================================");
                }
                Console.WriteLine("Downloading of historical data is complete. {0} CVE definitions parsed successfully.", CVE_data.Count);

                //SaveNewXmlData(@"D:\NVD\nvdcve-2.0-historical-reformatted.xml");
                Console.WriteLine("Historical data are saved successfully.");
                Console.WriteLine("=======================================");
            }
            catch (Exception Ex)
            {
                Console.Error.WriteLine(Ex);
            }
        }

        private static void DownloadModifiedData()
        {
            try
            {
                bool useCacheFile;
#if DEBUG
                string downloadURL = docDir + "nvdcve-2.0-modified-Debug.xml";
#else
                string downloadURL = docDir + "nvdcve-2.0-modified.xml";
#endif

                if (File.Exists(downloadURL))
                {
                    useCacheFile = true;
                    Console.WriteLine("Using cached historical CVE data from: {0}", downloadURL);
                }
                else
                {
                    downloadURL = @"https://nvd.nist.gov/download/nvdcve-Modified.xml.zip";
                    useCacheFile = false;
                    Console.WriteLine("Downloading CVE data from {0}", downloadURL);
                }

                ParseXmlData(DownloadDataStream(downloadURL, "nvdcve-modified.xml", useCacheFile));
                Console.WriteLine("Completed Download of Modified CVE data from: {0}", downloadURL);
                Console.WriteLine("=======================================================================================================");
                Console.WriteLine("Downloading of modified data is complete. {0} CVE definitions parsed successfully.", CVE_data.Count);

                //SaveNewXmlData(@"D:\NVD\nvdcve-2.0-modified-reformatted.xml");
                Console.WriteLine("Reformatted data are saved successfully.");
                Console.WriteLine("========================================");
            }
            catch (Exception Ex)
            {
                Console.Error.WriteLine(Ex);
            }
        }

        private static string CreateTmpFile()
        {
            string fileName = string.Empty;

            try
            {
                // Get the full name of the newly created Temporary file. 
                // Note that the GetTempFileName() method actually creates
                // a 0-byte file and returns the name of the created file.
                fileName = Path.GetTempFileName();

                // Create a FileInfo object to set the file's attributes
                FileInfo fileInfo = new FileInfo(fileName);

                // Set the Attribute property of this file to Temporary. 
                // Although this is not completely necessary, the .NET Framework is able 
                // to optimize the use of Temporary files by keeping them cached in memory.
                fileInfo.Attributes = FileAttributes.Temporary;
#if DEBUG
                Console.WriteLine("TEMP file created at: " + fileName);
#endif
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Unable to create TEMP file or set its attributes: " + Environment.NewLine + ex);
            }

            return fileName;
        }

        private static string DownloadDataStream(string xmlFeedUrl, string xmlFileName, bool useCacheFile)
        {
            string xmlDataLocation = string.Empty;
            string expandedFilePath = docDir;
            string expandedFileName = expandedFilePath + xmlFileName;

            try
            {
                if (!useCacheFile)
                {
                    // Download the compressed data file to a temporary location
                    string spoolFile = CreateTmpFile();

                    using (WebClient wc = new WebClient())
                    {
                        IWebProxy iwpxy = WebRequest.GetSystemWebProxy();
                        wc.Proxy = iwpxy;
                        wc.Credentials = CredentialCache.DefaultCredentials;
                        wc.Proxy.Credentials = CredentialCache.DefaultCredentials;
                        Console.WriteLine("  Please Wait. Downloading compressed XML data...");
                        wc.DownloadFile(xmlFeedUrl, spoolFile);
                    }

                    // Now unzip the dowloaded file
                    if (File.Exists(expandedFileName))
                    {
                        File.Delete(expandedFileName);
                    }
                    ZipFile.ExtractToDirectory(spoolFile, expandedFilePath);
                    xmlDataLocation = expandedFileName;
                }
#if DEBUG
                Console.WriteLine("Saved uncompressed data as: {0}", expandedFileName);
#endif
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
            }
            return expandedFileName;
        }

        private static void LoadBinaryData(string dataFilePath)
        {
            try
            {
                using (Stream fileStream = File.Open(dataFilePath, FileMode.Open))
                {
                    BinaryFormatter bFormatter = new BinaryFormatter();
                    CVE_data = (List<CVE_entry>)bFormatter.Deserialize(fileStream);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
            }
        }

        private static void SaveBinaryData(string dataFilePath)
        {
            try
            {
                using (Stream fileStream = File.Open(dataFilePath, FileMode.Create))
                {
                    BinaryFormatter bFormatter = new BinaryFormatter();
                    bFormatter.Serialize(fileStream, CVE_data);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
            }
        }

        private static void ParseXmlData(string xmlFilePath)
        {
            try
            {
                nvd nvdData = null;

                XmlSerializer xs = new XmlSerializer(typeof(nvd));
                using (StreamReader sr = new StreamReader(xmlFilePath))
                {
                    nvdData = (nvd)xs.Deserialize(sr);
                }

                // Now iterate over the list for each entry
                foreach (entryType entry in nvdData.entry)
                {
                    CVE_entry cveEntry = new CVE_entry(entry);

                    for (int i = 0; i < CVE_data.Count; i++)
                    {
                        // Check for a duplicate entry
                        if (cveEntry == CVE_data[i])
                        {
                            CVE_data.RemoveAt(i);
#if DEBUG
                            Console.WriteLine("Removed duplicate entry {0} from list at index {1}.", entry.name, i);
#endif
                            ++countRemoved;
                        }
                    }
                    CVE_data.Add(cveEntry);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
            }
#if DEBUG
            Console.WriteLine("Processed {0} records.", CVE_data.Count);
            Console.WriteLine("Finished parsing NVD data");
#endif
        }
    }
}
