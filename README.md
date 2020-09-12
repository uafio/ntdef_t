# ntdef_t
- [x] Generate function definitions for all ntdll exported syscalls
- [x] Generate SSDT enum header
- [ ] Support 32bit version of ntdll.dll
- [ ] Support sysenter

## Generated files
- `ntdefs.h` contains `Nt` version of all exported syscalls
- `ssdt_t.h` contains SSDT indices for all ntdll exported user-land syscalls

## Notes
- The generated `ssdt_t.h` header only contains the available syscalls through the NTAPI. It might not contain absolutely all indices for syscall handlers. For example, on Windows 10 Build 19041.508 the `ntdll!NtQuerySystemTime` syscall is replaced with RTL function `ntdll!RtlQuerySystemTime`. The SSDT index is for it is `0x5a` but it is not available throught the NTAPI, therefore it is not included in the `ssdt_t.h`

```
0:000> u ntdll!NtQuerySystemTime
ntdll!NtQuerySystemTime:
00007ffb`58c6c8f0 e9bb86fdff      jmp     ntdll!RtlQuerySystemTime (00007ffb`58c44fb0)

0:000> u 00007ffb`58c44fb0
ntdll!RtlQuerySystemTime:
00007ffb`58c44fb0 488b04251400fe7f mov     rax,qword ptr [SharedUserData+0x14 (00000000`7ffe0014)]
00007ffb`58c44fb8 488901          mov     qword ptr [rcx],rax
00007ffb`58c44fbb eb02            jmp     ntdll!RtlQuerySystemTime+0xf (00007ffb`58c44fbf)
00007ffb`58c44fbd eb02            jmp     ntdll!RtlQuerySystemTime+0x11 (00007ffb`58c44fc1)
00007ffb`58c44fbf 33c0            xor     eax,eax
00007ffb`58c44fc1 c3              ret
```
