import ctypes
from ctypes import wintypes, c_size_t, c_ulonglong
import re
from typing import List, Tuple
import os

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PAGE_EXECUTE_READWRITE = 0x40

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

# Define proper types for 64-bit addresses
SIZE_T = c_size_t
ULONG_PTR = c_ulonglong

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ('lpBaseOfDll', ULONG_PTR),
        ('SizeOfImage', wintypes.DWORD),
        ('EntryPoint', ULONG_PTR)
    ]

class MemoryPatcher:
    def __init__(self):
        self.patches = self.parse_patches()
        
    def parse_patches(self) -> List[Tuple[int, bytes]]:
        """Parse the patch data from the provided hex patches"""
        patch_data = '''
0000000000037F33:84->85
        '''.strip().splitlines()
        
        patches = []
        for line in patch_data:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            match = re.match(r'([0-9A-F]+):([0-9A-F]{2})->([0-9A-F]{2})', line)
            if match:
                offset = int(match.group(1), 16)
                new_byte = int(match.group(3), 16)
                patches.append((offset, bytes([new_byte])))
        return patches

    def get_process_handle(self, pid: int, access: int) -> wintypes.HANDLE:
        h_process = kernel32.OpenProcess(access, False, pid)
        if not h_process:
            raise ctypes.WinError(ctypes.get_last_error())
        return h_process

    def get_image_base(self, pid: int) -> int:
        h_process = self.get_process_handle(
            pid, 
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        )
        
        try:
            h_mod = wintypes.HMODULE()
            cb_needed = wintypes.DWORD()
            
            if not psapi.EnumProcessModules(
                h_process, 
                ctypes.byref(h_mod), 
                ctypes.sizeof(h_mod), 
                ctypes.byref(cb_needed)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
                
            modinfo = MODULEINFO()
            if not psapi.GetModuleInformation(
                h_process, 
                h_mod, 
                ctypes.byref(modinfo), 
                ctypes.sizeof(modinfo)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
                
            return modinfo.lpBaseOfDll
            
        finally:
            kernel32.CloseHandle(h_process)

    def apply_patches(self, pid: int) -> None:
        image_base = self.get_image_base(pid)
        print(f"[+] Image base: 0x{image_base:016X}")
        
        h_process = self.get_process_handle(
            pid,
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        )
        
        try:
            for offset, new_bytes in self.patches:
                address = image_base + offset
                written = SIZE_T()
                old_protect = wintypes.DWORD()
                
                # Change memory protection
                if not kernel32.VirtualProtectEx(
                    h_process,
                    ctypes.c_void_p(address),
                    len(new_bytes),
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect)
                ):
                    print(f"[-] Failed to change protection at 0x{address:016X}")
                    continue
                
                # Apply patch
                if not kernel32.WriteProcessMemory(
                    h_process,
                    ctypes.c_void_p(address),
                    new_bytes,
                    len(new_bytes),
                    ctypes.byref(written)
                ):
                    print(f"[-] Failed to patch at 0x{address:016X}")
                else:
                    print(f"[+] Patched 0x{address:016X}: {new_bytes.hex()}")
                
                # Restore original protection
                kernel32.VirtualProtectEx(
                    h_process,
                    ctypes.c_void_p(address),
                    len(new_bytes),
                    old_protect,
                    ctypes.byref(wintypes.DWORD())
                )
                
        finally:
            kernel32.CloseHandle(h_process)

def display_banner():
    """Display CRACKFRM banner in ASCII art"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner = """
  
  ____ ____      _    ____ _  _______ ____  __  __   ___  ____   ____ 
 / ___|  _ \    / \  / ___| |/ /  ___|  _ \|  \/  | / _ \|  _ \ / ___|
| |   | |_) |  / _ \| |   | ' /| |_  | |_) | |\/| || | | | |_) | |  _ 
| |___|  _ <  / ___ \ |___| . \|  _| |  _ <| |  | || |_| |  _ <| |_| |
 \____|_| \_\/_/   \_\____|_|\_\_|   |_| \_\_|  |_(_)___/|_| \_\\____|

    """
    print(banner)
    print(" " * 30 + "VMP PYTHON MEMORY PATCHER")
    print("=" * 80)

def main():
    display_banner()
    
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] Administrator privileges required!")
        print("[-] Please run this program as Administrator")
        input("Press Enter to exit...")
        return
        
    try:
        pid = int(input("Enter target PID: "))
        patcher = MemoryPatcher()
        patcher.apply_patches(pid)
        print("[+] Patching completed successfully!")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()