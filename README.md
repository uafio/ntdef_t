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

- The generated `ntdefs.h` does not include the WDK headers for the argument definitions.

## Output
```
➜  ntdef_t git:(master) ✗ python3 ./ntdef.py ntdll.dll

[!] Windows version: 10.0.19041.423 (WinBuild.160101.0800)

---------------------------------------------------------------------
          NTAPI                                             | SYSCALL
---------------------------------------------------------------------
NtAcceptConnectPort.........................................: 0x2    
NtAccessCheck...............................................: 0x0    
NtAccessCheckAndAuditAlarm..................................: 0x29   
NtAccessCheckByType.........................................: 0x63
...
NtYieldExecution............................................: 0x46
NTAPI DEFINITION NOT FOUND: NtAcquireCrossVmMutant
NTAPI DEFINITION NOT FOUND: NtAcquireProcessActivityReference
NTAPI DEFINITION NOT FOUND: NtAllocateUserPhysicalPagesEx
NTAPI DEFINITION NOT FOUND: NtAllocateVirtualMemoryEx
NTAPI DEFINITION NOT FOUND: NtApphelpCacheControl
NTAPI DEFINITION NOT FOUND: NtCommitRegistryTransaction
NTAPI DEFINITION NOT FOUND: NtCompareSigningLevels
NTAPI DEFINITION NOT FOUND: NtContinueEx
NTAPI DEFINITION NOT FOUND: NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
NTAPI DEFINITION NOT FOUND: NtCreateCrossVmEvent
NTAPI DEFINITION NOT FOUND: NtCreateCrossVmMutant
NTAPI DEFINITION NOT FOUND: NtCreateRegistryTransaction
NTAPI DEFINITION NOT FOUND: NtDirectGraphicsCall
NTAPI DEFINITION NOT FOUND: NtFlushVirtualMemory
NTAPI DEFINITION NOT FOUND: NtGetCurrentProcessorNumberEx
NTAPI DEFINITION NOT FOUND: NtLoadKey3
NTAPI DEFINITION NOT FOUND: NtManageHotPatch
NTAPI DEFINITION NOT FOUND: NtMapViewOfSectionEx
NTAPI DEFINITION NOT FOUND: NtOpenRegistryTransaction
NTAPI DEFINITION NOT FOUND: NtPssCaptureVaSpaceBulk
NTAPI DEFINITION NOT FOUND: NtQueryAuxiliaryCounterFrequency
NTAPI DEFINITION NOT FOUND: NtQuerySecurityPolicy
NTAPI DEFINITION NOT FOUND: NtRollbackRegistryTransaction
NTAPI DEFINITION NOT FOUND: NtSetCachedSigningLevel2
NTAPI DEFINITION NOT FOUND: NtSetInformationSymbolicLink
```
