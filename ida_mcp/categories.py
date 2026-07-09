"""导入 API 分类表（确定性名称匹配，不做启发式）。

见 DESIGN.md：分类只作为提示信号，不含置信分；语义结论交给 LLM。
"""

IMPORT_CATEGORIES = {
    "CRYPTO": {
        "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptCreateHash",
        "CryptDeriveKey", "CryptGenKey", "CryptImportKey", "CryptExportKey",
        "CryptAcquireContext", "CryptReleaseContext", "CryptGenRandom",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptCreateHash", "BCryptHashData",
        "BCryptGenerateSymmetricKey", "BCryptOpenAlgorithmProvider",
    },
    "NETWORK": {
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "sendto", "recvfrom", "closesocket", "gethostbyname", "getaddrinfo",
        "inet_addr", "htons", "ntohs",
        "WSAStartup", "WSASocketA", "WSASocketW", "WSACleanup",
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "InternetReadFile", "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA",
        "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    },
    "FILE": {
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA",
        "DeleteFileW", "MoveFileA", "MoveFileW", "CopyFileA", "CopyFileW",
        "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
        "GetTempPathA", "GetTempPathW", "SetFilePointer", "CloseHandle",
        "GetFileSize", "CreateDirectoryA", "CreateDirectoryW",
    },
    "PROCESS": {
        "CreateProcessA", "CreateProcessW", "OpenProcess", "TerminateProcess",
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "CreateThread", "NtCreateThreadEx", "ResumeThread", "SuspendThread",
        "OpenThread", "GetThreadContext", "SetThreadContext", "QueueUserAPC",
        "ShellExecuteA", "ShellExecuteW", "WinExec",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    },
    "REGISTRY": {
        "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
        "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
        "RegQueryValueA", "RegQueryValueW", "RegQueryValueExA", "RegQueryValueExW",
        "RegDeleteKeyA", "RegDeleteKeyW", "RegCreateKeyA", "RegCreateKeyW",
        "RegCreateKeyExA", "RegCreateKeyExW", "RegCloseKey",
    },
    "ANTI_DEBUG": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
        "GetTickCount", "QueryPerformanceCounter", "NtSetInformationThread",
        "NtQuerySystemInformation",
    },
}


# 前缀匹配表（确定性规则；顺序敏感，更具体的前缀在前）。
# 覆盖成族命名的 API，避免精确表逐个枚举遗漏（如 BCryptExportKey）。
IMPORT_PREFIXES = [
    # 加密族：BCrypt*/NCrypt*/Crypt*/SymCrypt*
    ("BCrypt", "CRYPTO"),
    ("NCrypt", "CRYPTO"),
    ("SymCrypt", "CRYPTO"),
    ("Crypt", "CRYPTO"),
    # 内核事务管理器（KTM）
    ("Tm", "KERNEL_TRANSACTION"),
    ("NtCreateTransaction", "KERNEL_TRANSACTION"),
    ("NtCommitTransaction", "KERNEL_TRANSACTION"),
    ("NtRollbackTransaction", "KERNEL_TRANSACTION"),
    ("NtOpenTransaction", "KERNEL_TRANSACTION"),
    ("NtCreateEnlistment", "KERNEL_TRANSACTION"),
    # 通用日志文件系统
    ("Clfs", "KERNEL_LOGGING"),
    # 平台硬件错误驱动 / WHEA
    ("Pshed", "KERNEL_HW_ERROR"),
    # 内核调试传输
    ("Kd", "KERNEL_DEBUG"),
]


def categorize_import(name):
    """返回 name 所属类别，未匹配返回 None。

    确定性规则（DESIGN 允许"精确匹配或前缀匹配"）：
    1. 先精确匹配 IMPORT_CATEGORIES；
    2. 再按 IMPORT_PREFIXES 做前缀匹配（覆盖 BCrypt*/Crypt* 等成族 API）。
    不做模糊启发式，不含置信分。
    """
    for category, names in IMPORT_CATEGORIES.items():
        if name in names:
            return category
    for prefix, category in IMPORT_PREFIXES:
        if name.startswith(prefix):
            return category
    return None
