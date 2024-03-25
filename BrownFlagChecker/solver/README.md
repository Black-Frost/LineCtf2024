# Brown's flag checker
- We are given a Windows executable (`BrownFlagChecker.exe`) and a driver (`BrownProtector.sys`).
- Program flow:
    - The executable will starts 2 processes (the father and child process). The father will attach to the child process (as an anti debug method)
    - The father process will load the driver into kernel space.
    - The father and child process will send their pid to the driver. The driver will perform some checks on the 2 process: debugger check, .text section's crc32 check, check if 2 processes have father-child relationship,...
    - The father creates 20 buffers using VirtualAlloc and write some data on these buffers. User input is written in 1 of the 20 buffers.
    - The driver will map these 20 buffers to the child process's address space by modifying its page table.
    - The user input and data in these 20 buffers will be used by the child as key and iv for a series of AES-CBC encryption (9 times). After that, the result is compared with a hardcoded value (also written in 1 of the 20 buffers). If the input passes the check, it will be used as the key to decrypt the flag.
    - Player must find out which of the 20 buffers are key, iv and the order in which they are used ==> get the correct input.