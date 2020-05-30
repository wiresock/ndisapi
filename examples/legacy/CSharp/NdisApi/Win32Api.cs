using System;
using System.Runtime.InteropServices;

namespace NdisApiWrapper
{
    public struct Win32Api
    {
        public const int MAX_PATH = 260;

        public const int VER_PLATFORM_WIN32s = 0;
        public const int VER_PLATFORM_WIN32_WINDOWS = 1;
        public const int VER_PLATFORM_WIN32_NT = 2;

        public const uint INFINITE = 4294967295;

        [DllImport("kernel32", EntryPoint = "GetVersionExA")]
        public static extern int GetVersionEx(ref OSVERSIONINFO lpVersionInformation);
        [System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint = "CreateEventA")]
        public static extern int CreateEvent(ref SECURITY_ATTRIBUTES lpEventAttributes, int bManualReset, int bInitialState, string lpName);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern int ResetEvent(int hEvent);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern int CloseHandle(int hObject);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern int WaitForSingleObject(int hHandle, int dwMilliseconds);

        //[System.Runtime.InteropServices.DllImport("kernel32", EntryPoint = "RtlMoveMemory")]
        //public static extern void CopyMemory(ref object pDst, ref object pSrc, int ByteLen);

        [DllImport("kernel32", EntryPoint = "RtlZeroMemory")]
        public static extern void ZeroMemory(IntPtr Destination, int Length);
        public static void ZeroMemory(object obj)
        {
            GCHandle gc = GCHandle.Alloc(obj);
            ZeroMemory(GCHandle.ToIntPtr(gc), Marshal.SizeOf(obj));
            gc.Free();
        }

        [System.Runtime.InteropServices.DllImport("kernel32")]
        public static extern void Sleep(int dwMilliseconds);
        [System.Runtime.InteropServices.DllImport("ws2_32.dll")]
        public static extern short htons(short hostshort);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct OSVERSIONINFO
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] szCSDVersion;

        public static OSVERSIONINFO GetVersion()
        {
            OSVERSIONINFO res = new OSVERSIONINFO();
            res.dwOSVersionInfoSize = Marshal.SizeOf(res);
            Win32Api.GetVersionEx(ref res);
            return res;
        }
    }
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public int lpSecurityDescriptor;
        public int bInheritHandle;
    }

}
