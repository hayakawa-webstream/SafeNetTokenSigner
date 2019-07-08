using CommandLine;
using SafenetSign;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SafenetSignDotnet
{
    class Program
    {
        #region Options

        class Options
        {
            #region Standard Option Attribute

            [Option("hash")]
            public string hash { get; set; }

            [Option("container")]
            public string container { get; set; }

            [Option("store")]
            public string store { get; set; }

            [Option("pin")]
            public string pin { get; set; }

            [Option("timestamp_url")]
            public string timestamp_url { get; set; }

            [Option("timestamp_argorithm")]
            public string timestamp_argorithm { get; set; }

            [Option("file")]
            public string file { get; set; }

            [Option("verbose")]
            public bool verbose { get; set; }

            #endregion
        }

        static Options options;

        static void InitOptions(string[] args)
        {
            options = new Options();
            bool case_sensitive = false;
            var parser = new Parser((ps) => { ps.CaseSensitive = case_sensitive; });
            if (!parser.ParseArguments(args, options))
            {
                Console.Error.WriteLine("invalid parameter(s)");
                Environment.Exit(1);
            }

            if (string.IsNullOrEmpty(options.hash))
            {
                Console.Error.WriteLine("missing hash");
                Environment.Exit(1);
            }
            if (string.IsNullOrEmpty(options.pin))
            {
                Console.Error.WriteLine("missing pin");
                Environment.Exit(1);
            }
            if (string.IsNullOrEmpty(options.file))
            {
                Console.Error.WriteLine("missing file");
                Environment.Exit(1);
            }

        }

        #endregion

        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine(@"Usage: SafenetSigner --hash <certificate thumbprint> --pin <token PIN> --file <path to file to sign> [--timestamp_url <timestamp URL>] [--timestamp_argorithm <timestamp RFC3161 argorithm>]");
                return 1;
            }
            InitOptions(args);

            var certHash = options.hash;
            var containerName = options.container ?? @"\\.\AKS ifdh 0";
            var targetStore = options.store ?? "user";
            var tokenPin = options.pin;
            var timestampUrl = options.timestamp_url;
            var mode = "appx";
            var fileToSign = options.file;
            var verbose = options.verbose;
            var timestampAlgorithm = options.timestamp_argorithm;

            try
            {
                var signMode = ParseMode(mode);
                var store = ParseStore(targetStore);

                // string szOID_NIST_sha256 = "2.16.840.1.101.3.4.2.1";
                CodeSigner.SignFile(certHash, tokenPin, containerName, store, fileToSign, timestampUrl,
                    signMode, null, new Logger(verbose), timestampAlgorithm);

                return 0;
            }
            catch (SigningException ex)
            {
                Console.Error.WriteLine("Signing operation failed. Error details:");
                Console.Error.WriteLine(ex.GetBaseException().Message);

                return 2;
            }
        }

        private static CertificateStore ParseStore(string storeString)
        {
            CertificateStore store;
            switch (storeString.ToLowerInvariant())
            {
                case "user":
                    store = CertificateStore.User;
                    break;
                case "machine":
                    store = CertificateStore.Machine;
                    break;
                default:
                    throw new SigningException($"Unknown store specified: {storeString}");
            }

            return store;
        }

        private static SignMode ParseMode(string mode)
        {
            SignMode signMode;
            switch (mode.ToLowerInvariant())
            {
                case "pe":
                    signMode = SignMode.PE;
                    break;
                case "appx":
                    signMode = SignMode.APPX;
                    break;
                default:
                    throw new SigningException($"Unknown storeString specified: {mode}");
            }

            return signMode;
        }
    }
}
