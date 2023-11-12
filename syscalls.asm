.code 

public NtCreateThreadEx
NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, 0C7h
    syscall
    ret
NtCreateThreadEx ENDP

public NtOpenProcess
NtOpenProcess PROC
    mov r10, rcx
    mov eax, 26h
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
