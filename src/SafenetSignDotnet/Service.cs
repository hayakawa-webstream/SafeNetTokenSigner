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
        public string GetEncryptInfo()
        {
            var public_key = rsa.ToXmlString(false);
            var ticks = DateTime.UtcNow.Ticks;
            var dic = new Dictionary<string, object>();
            dic.Add("public_key", public_key);
            dic.Add("ticks", ticks);
            return jss.Serialize(dic);
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
                    if (!string.IsNullOrEmpty(signParams.cipher))
                    {
                        var decryptedStr = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(signParams.cipher), false));
                        var decryptedParams = jss.Deserialize<DecryptedParams>(decryptedStr);
                        var ticks = DateTime.UtcNow.Ticks - decryptedParams.ticks;
                        if (0 <= ticks && ticks <= 60 * TimeSpan.TicksPerSecond)
                        {
                            signParams.pin = decryptedParams.pin;
                            signParams.sha1 = decryptedParams.sha1;
                        }
                    }
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

                if (!string.IsNullOrEmpty(signParams.sha1))
                {
                    var sha1 = CalcSha1Hash(filePath);
                    if (0 != string.Compare(signParams.sha1, sha1, true))
                    {
                        throw new Exception("SHA1 hash mismatched");
                    }
                }

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

        static string CalcSha1Hash(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var sha1 = new SHA1Managed();
                var hash = sha1.ComputeHash(fs);
                return BitConverter.ToString(hash).Replace("-", string.Empty);
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
            public string cipher { get; set; }
            public string sha1 { get; set; }
        }

        class DecryptedParams
        {
            public string pin { get; set; }
            public long ticks { get; set; }
            public string sha1 { get; set; }
        }
    }
}
