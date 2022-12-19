.code

EXTERN SW3_GetSyscallNumber: PROC

NtReadFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 01C421CD8h        ; Load function hash into ECX.
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	DB 73h                     ; "s"
	DB 0h                     ; "0"
	DB 0h                     ; "0"
	DB 6eh                     ; "n"
	DB 73h                     ; "s"
	DB 0h                     ; "0"
	DB 0h                     ; "0"
	DB 6eh                     ; "n"
	ret
NtReadFile ENDP

NtClose PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0425F2F97h        ; Load function hash into ECX.
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	DB 73h                     ; "s"
	DB 0h                     ; "0"
	DB 0h                     ; "0"
	DB 6eh                     ; "n"
	DB 73h                     ; "s"
	DB 0h                     ; "0"
	DB 0h                     ; "0"
	DB 6eh                     ; "n"
	ret
NtClose ENDP

NtCreateFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 02593B2A3h        ; Load function hash into ECX.
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	DB 73h                     ; "s"
	DB 0h                     ; "0"
	DB 0h                     ; "0"
	DB 6eh                     ; "n"
	DB 73h                     ; "s"
	DB 0h                     ; "0"
	DB 0h                     ; "0"
	DB 6eh                     ; "n"
	ret
NtCreateFile ENDP

NtProtectVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 07FE94947h        ; Load function hash into ECX.
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	DB 73h                     ; "s"
	DB 0h                     ; "0"
	DB 0h                     ; "0"
	DB 6eh                     ; "n"
	DB 73h                     ; "s"
	DB 0h                     ; "0"
	DB 0h                     ; "0"
	DB 6eh                     ; "n"
	ret
NtProtectVirtualMemory ENDP

end