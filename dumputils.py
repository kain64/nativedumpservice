import ctypes
import os
import win32security
import win32api
import datetime
import zipfile
import psutil
import win32con
import win32file

dbghelp = ctypes.windll.dbghelp

MiniDumpNormal = 0x00000000
MiniDumpWithDataSegs = 0x00000001
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpFilterMemory = 0x00000008
MiniDumpScanMemory = 0x00000010
MiniDumpWithUnloadedModules = 0x00000020
MiniDumpWithIndirectlyReferencedMemory = 0x00000040
MiniDumpFilterModulePaths = 0x00000080
MiniDumpWithProcessThreadData = 0x00000100
MiniDumpWithPrivateReadWriteMemory = 0x00000200
MiniDumpWithoutOptionalData = 0x00000400
MiniDumpWithFullMemoryInfo = 0x00000800
MiniDumpWithThreadInfo = 0x00001000
MiniDumpWithCodeSegs = 0x00002000
MiniDumpWithoutAuxiliaryState = 0x00004000
MiniDumpWithFullAuxiliaryState = 0x00008000
MiniDumpWithPrivateWriteCopyMemory = 0x00010000
MiniDumpIgnoreInaccessibleMemory = 0x00020000
MiniDumpWithTokenInformation = 0x00040000
MiniDumpWithModuleHeaders = 0x00080000
MiniDumpFilterTriage = 0x00100000
MiniDumpValidTypeFlags = 0x001fffff

EXCEPTION_MAXIMUM_PARAMETERS = 15


class DumpUtils:
    def __init__(self, pid):
        self.pid = pid

    def generate_file_name(self):
        process = psutil.Process(self.pid)
        return os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            process.name() + datetime.datetime.now().strftime("_%Y_%m_%d__%H_%M_%S") + '.dmp')

    def create_mini_dump(self):
        file_name = self.generate_file_name()
        if os.path.isfile(file_name):
            os.remove(file_name)
        # Adjust privileges.
        self.adjust_privilege(win32security.SE_DEBUG_NAME)
        process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 0,
                                              self.pid)
        print('process_handle Status: ', win32api.FormatMessage(win32api.GetLastError()))
        file_handle = win32file.CreateFile(file_name,
                                           win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                           win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                           None,
                                           win32file.CREATE_ALWAYS,
                                           win32file.FILE_ATTRIBUTE_NORMAL,
                                           None)

        print('file_handle Status: ', win32api.FormatMessage(win32api.GetLastError()))
        mini_dump = MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData | MiniDumpWithHandleData | MiniDumpWithDataSegs
        full_info_dump = (
            mini_dump | MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory | MiniDumpWithFullMemory)

        success = dbghelp.MiniDumpWriteDump(process_handle.handle,  # Process handle
                                            self.pid,  # Process ID
                                            file_handle.handle,  # File handle
                                            full_info_dump,  # Dump type - MiniDumpNormal
                                            None,  # Exception parameter
                                            None,  # User stream parameter
                                            None,  # Callback parameter
                                            )

        print('MiniDump Status: ', win32api.FormatMessage(win32api.GetLastError()))
        win32file.CloseHandle(file_handle)
        return self.zip_and_delete_file(file_name)
        #return file_name

    def zip_and_delete_file(self, file_name):
        zip_file_name = "%s.zip" % file_name
        with zipfile.ZipFile(zip_file_name, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.write(file_name)
        os.remove(file_name)
        return zip_file_name

    def adjust_privilege(self, priv):
        flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
        id = win32security.LookupPrivilegeValue(None, priv)
        new_privileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
        win32security.AdjustTokenPrivileges(htoken, 0, new_privileges)


if __name__ == "__main__":
    print(os.path.dirname(os.path.realpath(__file__)))
    utils = DumpUtils(11244)
    print(utils.generate_file_name())
    utils.create_mini_dump()
