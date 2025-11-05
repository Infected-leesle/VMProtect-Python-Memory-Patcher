# VMProtect-Python-Memory-Patcher
Author:Cambaz 

Fork from https://crackfrm.org/topic/509-source-code-vmprotect-python-memory-patcher 

<img width="983" height="517" alt="trre PNG 0109d4b41e7d0478f32b84986cd25509" src="https://github.com/user-attachments/assets/ac94b34f-6ac2-4eba-b950-16953f685595" />

## What Does This Code Do? 
This Python code bypasses protection mechanisms of VMProtect (VMP) protected software by making runtime modifications in memory. The code directly writes to the target process's memory space, changing bytes at predetermined memory addresses.

## How It Works? 
 THIS PROGRAM ALLOWS YOU TO PERFORM PATCH PROCESS WITHOUT NEEDING THE .1337 FILE

Open the .py file with notepad and replace the sample patch addresses with the patch addresses you made in your target application. 
1. Process Access: Obtains the target process's PID and gains access with read and write permissions.
2. Image Base Detection: Finds the base address where the process's main module (usually the .exe file) is loaded in memory.
3. Memory Protection Change: Alters the protection levels of target memory regions to make them writable.
4. Byte Patching: Changes bytes at predefined offset addresses with new values.
5. Protection Restoration: Restores the original protection levels of the modified memory regions.

## Usage
```python .\memory_patcher.py PID```
