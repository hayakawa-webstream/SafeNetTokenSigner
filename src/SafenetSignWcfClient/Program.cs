using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace SafenetSignWcfClient
{
    class Program
    {
        #region Options

        class Options
        {
            #region Standard Option Attribute

            [Option("server")]
            public string server { get; set; }

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

            [Option("mode")]
            public string mode { get; set; }

            [Option("timestamp_argorithm")]
            public string timestamp_argorithm { get; set; }

            [Option("file")]
            public string file { get; set; }

            [Option("create_new")]
            public bool create_new { get; set; }

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
                Console.WriteLine(@"Usage: SafenetClient --server <server ip> --hash <certificate thumbprint> --pin <token PIN> --file <path to file to sign> [--timestamp_url <timestamp URL>] [--timestamp_argorithm <timestamp RFC3161 argorithm>]");
                return 1;
            }
            InitOptions(args);

#if DEBUG
            Console.WriteLine("Press <ENTER> when service is ready");
            Console.ReadLine();
#endif
            int result = 0;
            try
            {
                var dic = new Dictionary<string, string>();
                if (options.hash != null) { dic.Add("hash", options.hash); }
                if (options.container != null) { dic.Add("container", options.container); }
                if (options.store != null) { dic.Add("store", options.store); }
                if (options.pin != null) { dic.Add("pin", options.pin); }
                if (options.timestamp_url != null) { dic.Add("timestamp_url", options.timestamp_url); }
                if (options.mode != null) { dic.Add("mode", options.mode); }
                if (options.timestamp_argorithm != null) { dic.Add("timestamp_argorithm", options.timestamp_argorithm); }
                var jss = new JavaScriptSerializer();
                var sign_params_json = jss.Serialize(dic);

                var server = options.server ?? "localhost";
                var remote_address = string.Format("http://{0}:8733/SafenetSign/", server);

                var src_path = options.file;
                var dst_path = options.file + ".signed";

                // Create an instance of the WCF proxy.
                var service_client = new ServiceClient("BasicHttpBinding_IService", remote_address);
                using (var src_fs = new FileStream(src_path, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var dst_fs = new FileStream(dst_path, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var ms = new MemoryStream())
                {
                    using (var bw = new BinaryWriter(ms, Encoding.UTF8, true))
                    {
                        bw.Write(sign_params_json);
                    }
                    ms.Seek(0, SeekOrigin.Begin);
                    var cs = new ConcatenatedStream(new Stream[] { ms, src_fs });
                    using (var result_fs = service_client.Sign(cs))
                    {
                        result_fs.CopyTo(dst_fs);
                    }
                }
                service_client.Close();

                if (!options.create_new)
                {
                    File.Delete(src_path);
                    File.Move(dst_path, src_path);
                }
#if DEBUG
                Console.WriteLine("\nPress <Enter> to terminate the client.");
                Console.ReadLine();
#endif
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: {0}", ex.ToString());
                result = 1;
            }
            return result;
        }
    }
}
