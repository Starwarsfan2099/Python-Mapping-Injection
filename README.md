### Python-Mapping-Injection

Python ctypes implementation of [Mapping-Injection](https://github.com/antonioCoco/Mapping-Injection).
Utilizes `CreateFileMapping`, `MapViewOfFile`, `memcpy`, `MapViewOfFile2`, and `CreateRemoteThread` to inject shellcode. 
For a technical description of how it works, visit the link above or look at the comments in the source code.
Requires 64-bit Pyhton 2.7.