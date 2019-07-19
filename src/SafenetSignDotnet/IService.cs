using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.Text;

namespace SafenetSignDotnet
{
    // メモ: [リファクター] メニューの [名前の変更] コマンドを使用すると、コードと config ファイルの両方で同時にインターフェイス名 "IService" を変更できます。
    [ServiceContract]
    public interface IService
    {
        [OperationContract]
        Stream Sign(Stream fs);

        [OperationContract]
        string GetPublicKey();
    }
}
