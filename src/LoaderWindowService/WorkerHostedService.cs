
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;

namespace LoaderWindowService;

internal class WorkerHostedService
(

) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var ret = StartProcessAndBypassUAC(applicationName: "notepad.exe", out var procInfo);
        return Task.CompletedTask;
    }

    public static bool StartProcessAndBypassUAC(String applicationName, out PROCESS_INFORMATION procInfo)
    {
        uint winlogonPid = 0;
        IntPtr hUserTokenDup = IntPtr.Zero, hPToken = IntPtr.Zero, hProcess = IntPtr.Zero;
        procInfo = new PROCESS_INFORMATION();

        // 현재 활성 세션 ID를 얻습니다; 시스템에 로그인한 모든 사용자는 고유한 세션 ID를 가집니다.
        uint dwSessionId = WTSGetActiveConsoleSessionId();

        // 현재 활성 세션에서 실행 중인 winlogon 프로세스의 프로세스 ID를 얻습니다.
        var processes = Process.GetProcessesByName("winlogon");
        foreach (var p in processes)
        {
            if ((uint)p.SessionId == dwSessionId)
            {
                winlogonPid = (uint)p.Id;
            }
        }

        // winlogon 프로세스에 대한 핸들을 얻습니다.
        hProcess = OpenProcess(MAXIMUM_ALLOWED, false, winlogonPid);

        // winlogon 프로세스의 액세스 토큰에 대한 핸들을 얻습니다.
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, ref hPToken))
        {
            CloseHandle(hProcess);
            return false;
        }

        // DuplicateTokenEx 및 CreateProcessAsUser에서 사용되는 보안 속성 구조체
        // 보안 속성 변수를 사용하지 않고 단순히 null을 전달하여 기존 토큰의 보안 속성을 상속받고 싶습니다.
        // 그러나 C# 구조체는 값 형식이므로 null 값을 할당할 수 없습니다.
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.Length = Marshal.SizeOf(sa);

        // winlogon 프로세스의 액세스 토큰을 복사합니다; 새로 생성된 토큰은 기본 토큰이 됩니다.
        if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, ref hUserTokenDup))
        {
            CloseHandle(hProcess);
            CloseHandle(hPToken);
            return false;
        }

        var si = new STARTUPINFO();
        si.cb = (int)Marshal.SizeOf(si);
        si.lpDesktop = @"winsta0\default";

        // 프로세스의 우선 순위 및 생성 방법을 지정하는 플래그
        int dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;

        // 현재 사용자의 로그인 세션에서 새 프로세스를 생성합니다.
        bool result = CreateProcessAsUser
        (
            hUserTokenDup,        // 클라이언트의 액세스 토큰
            null,                   // 실행할 파일
            applicationName,        // 명령줄
            ref sa,                 // 프로세스 SECURITY_ATTRIBUTES에 대한 포인터
            ref sa,                 // 스레드 SECURITY_ATTRIBUTES에 대한 포인터
            false,                  // 핸들은 상속되지 않습니다.
            dwCreationFlags,        // 생성 플래그
            IntPtr.Zero,            // 새 환경 블록에 대한 포인터
            null,                   // 현재 디렉터리 이름
            ref si,                 // STARTUPINFO 구조체에 대한 포인터
            out procInfo            // 새 프로세스에 대한 정보를 받습니다.
        );

        if (!result)
        {
            int error = Marshal.GetLastWin32Error();
            Console.WriteLine($"프로세스 생성에 실패했습니다. 오류 코드: {error}");
            Console.WriteLine($"오류 메시지: {new System.ComponentModel.Win32Exception(error).Message}");
        }

        // 핸들을 무효화합니다.
        CloseHandle(hProcess);
        CloseHandle(hPToken);
        CloseHandle(hUserTokenDup);

        return result; // 결과를 반환합니다.

    }

    #region 구조체

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    #endregion

    #region 열거형

    enum TOKEN_TYPE : int
    {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }

    enum SECURITY_IMPERSONATION_LEVEL : int
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3,
    }

    #endregion

    #region 상수

    public const int TOKEN_DUPLICATE = 0x0002;
    public const uint MAXIMUM_ALLOWED = 0x2000000;
    public const int CREATE_NEW_CONSOLE = 0x00000010;

    public const int IDLE_PRIORITY_CLASS = 0x40;
    public const int NORMAL_PRIORITY_CLASS = 0x20;
    public const int HIGH_PRIORITY_CLASS = 0x80;
    public const int REALTIME_PRIORITY_CLASS = 0x100;

    #endregion

    #region Win32 API 가져오기

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hSnapshot);

    [DllImport("kernel32.dll")]
    static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
        String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    static extern bool ProcessIdToSessionId(uint dwProcessId, ref uint pSessionId);

    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
    public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
        ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType,
        int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("advapi32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

    #endregion
}
