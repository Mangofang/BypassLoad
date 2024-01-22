using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            string path = System.AppDomain.CurrentDomain.SetupInformation.ApplicationBase;
            string shellcode = File.ReadAllText(path + "shellcode.txt", Encoding.UTF8);
            shellcode = new string(xor(shellcode));
            string D_shellcode = AesEncrypt(shellcode, "BsijVUv2v+Ql/NM3pQv8uQ==");
            /*using (Aes aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.GenerateKey();
                Console.WriteLine(Convert.ToBase64String(aes.Key));
            }*/
            Console.WriteLine(D_shellcode);
            Console.ReadLine();
        }
        private static char[] xor(string str)
        {
            char[] data = str.ToArray();
            char[] key = "qwertyuiopasdfghjklzxcvbnm".ToArray();
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= key[i % key.Length];
            }

            return data;
        }
        private static string AesEncrypt(string str, string key)
        {
            if (string.IsNullOrEmpty(str)) return null;
            Byte[] toEncryptArray = Encoding.UTF8.GetBytes(str);

            RijndaelManaged rm = new RijndaelManaged
            {
                Key = Encoding.UTF8.GetBytes(key),
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };

            ICryptoTransform cTransform = rm.CreateEncryptor();
            Byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            return Convert.ToBase64String(resultArray);
        }
    }
}
