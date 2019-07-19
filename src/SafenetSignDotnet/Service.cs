using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.ServiceModel;
using System.Text;
using System.Web.Script.Serialization;

namespace SafenetSignDotnet
{
    // メモ: [リファクター] メニューの [名前の変更] コマンドを使用すると、コードと config ファイルの両方で同時にクラス名 "Service" を変更できます。
    public class Service : IService
    {
        public string GetPublicKey()
        {
            return rsa.ToXmlString(false);
        }

        public Stream Sign(Stream fs)
        {
            SignParams signParams;
            {
                using (var br = new BinaryReader(fs, Encoding.UTF8, true))
                {
                    var signParamsJson = br.ReadString();
#if DEBUG
                    Console.WriteLine("signParamsJson: {0}", signParamsJson);
#endif
                    signParams = jss.Deserialize<SignParams>(signParamsJson);
                }
            }
            var filePath = Path.Combine(System.Environment.CurrentDirectory, Guid.NewGuid().ToString() + ".bin");
            try
            {
                if (verbose)
                {
                    Console.WriteLine("Saving to file {0}", filePath);
                }
                using (var outFs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                {
                    fs.CopyTo(outFs);
                }
                fs.Close();

                // sign
                if (verbose)
                {
                    Console.WriteLine("sign to file {0}", filePath);
                }
                var result = Program.SignFile(signParams.hash, signParams.container, signParams.store, signParams.pin, signParams.timestamp_url, signParams.mode, filePath, signParams.timestamp_argorithm);
                if (result != 0)
                {
                    throw new Exception("Sign failed");
                }

                //now open the file for reading
                //and return the stream
                if (verbose)
                {
                    Console.WriteLine("Sending file {0}", filePath);
                }
                var resultFs = new FileStream(filePath,
                       FileMode.Open, FileAccess.Read, FileShare.None,
                       4096, FileOptions.RandomAccess | FileOptions.DeleteOnClose);
                return resultFs;
            }
            catch (IOException ex)
            {
                Console.WriteLine(
                    String.Format("An exception was thrown while opening or writing to file {0}", filePath));
                Console.WriteLine("Exception is: ");
                Console.WriteLine(ex.ToString());
                throw ex;
            }
        }

        public static bool verbose;
        static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
        static JavaScriptSerializer jss = new JavaScriptSerializer();

        class SignParams
        {
            public string hash { get; set; }
            public string container { get; set; }
            public string store { get; set; }
            public string pin { get; set; }
            public string timestamp_url { get; set; }
            public string mode { get; set; }
            public string timestamp_argorithm { get; set; }
        }
    }
}
