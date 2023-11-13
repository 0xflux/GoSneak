;EXTERN wNtAllocateVirtualMemory:DWORD               ; Extern keyword indicates that the symbol is defined in another module.
;EXTERN wNtWriteVirtualMemory:DWORD                  ; Syscall number for NtWriteVirtualMemory.
;EXTERN wNtCreateThreadEx:DWORD                      ; Syscall number for NtCreateThreadEx.
;EXTERN wNtWaitForSingleObject:DWORD                 ; Syscall number for NtWaitForSingleObject.
EXTERN wNtOpenProcess:DWORD                         ; Syscall number for NtOpenProcess.

.code 

public NtCreateThreadEx
NtCreateThreadEx PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10. This is necessary because the syscall instruction in 64-bit Windows expects the parameters to be in the r10 and rdx registers.
    mov eax, 0C7h                                   ; Move the syscall number into the eax register.
    syscall                                         ; Execute syscall.
    ret                                             ; Return from the procedure.
NtCreateThreadEx ENDP

public NtOpenProcess
NtOpenProcess PROC
    mov r10, rcx
    mov eax, wNtOpenProcess
    syscall
    ret
NtOpenProcess ENDP

public NtAllocateVirtualMemory
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h
    syscall
    ret
NtAllocateVirtualMemory ENDP

public NtWriteVirtualMemory
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, 3Ah
    syscall
    ret
NtWriteVirtualMemory ENDP

; to implement
public NtWaitForSingleObject
NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, 4h
    syscall
    ret
NtWaitForSingleObject ENDP

public NtClose
NtClose PROC
    mov r10, rcx
    mov eax, 0Fh
    syscall
    ret
NtClose ENDP

end
