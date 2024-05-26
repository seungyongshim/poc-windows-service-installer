
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LoaderWindowService;

internal class WorkerHostedService
(

) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var hToken = IntPtr.Zero;
        var hDupToken = IntPtr.Zero;
        var hPToken = IntPtr.Zero;
        var hProcess = IntPtr.Zero;

        try
        {
            // 현재 콘솔 세션의 ID를 가져옴
            uint dwSessionId = WTSGetActiveConsoleSessionId();

            // 시스템 프로세스의 핸들을 가져옴
            hProcess = OpenProcess(ProcessAccessFlags.QueryInformation, false, 4); // 4는 시스템 프로세스 ID

            // 시스템 프로세스의 토큰을 가져옴
            if (!OpenProcessToken(hProcess, TokenAccessLevels.Duplicate, out hToken))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            // 토큰을 복제함
            if (!DuplicateTokenEx(hToken, TokenAccessLevels.MaximumAllowed, IntPtr.Zero, SecurityImpersonationLevel.Impersonation, TokenType.Primary, out hDupToken))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            // 세션 토큰을 설정함
            if (!SetTokenInformation(hDupToken, TokenInformationClass.TokenSessionId, ref dwSessionId, (uint)IntPtr.Size))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            // 세션 토큰을 사용하여 프로세스를 시작함
            var si = new STARTUPINFO();
            var pi = new PROCESS_INFORMATION();
            si.cb = Marshal.SizeOf(si);

            if (!CreateProcessAsUser(hDupToken, null, "cmd.exe", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            // 리소스 해제
            if (hToken != IntPtr.Zero)
                CloseHandle(hToken);
            if (hDupToken != IntPtr.Zero)
                CloseHandle(hDupToken);
            if (hProcess != IntPtr.Zero)
                CloseHandle(hProcess);
        }

        Process.Start("notepad.exe");
        return Task.CompletedTask;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, TokenAccessLevels DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool DuplicateTokenEx(IntPtr hExistingToken, TokenAccessLevels dwDesiredAccess, IntPtr lpTokenAttributes, SecurityImpersonationLevel ImpersonationLevel, TokenType TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(IntPtr TokenHandle, TokenInformationClass TokenInformationClass, ref uint TokenInformation, uint TokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    private enum ProcessAccessFlags : uint
    {
        QueryInformation = 0x0400
    }

    private enum TokenAccessLevels
    {
        Duplicate = 0x0002,
        MaximumAllowed = 0x02000000
    }

    private enum SecurityImpersonationLevel
    {
        Anonymous = 0,
        Identification = 1,
        Impersonation = 2,
        Delegation = 3
    }

    private enum TokenType
    {
        Primary = 1,
        Impersonation = 2
    }

    private enum TokenInformationClass
    {
        TokenSessionId = 12
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
}
