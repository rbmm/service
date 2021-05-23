_TEXT segment 'CODE'

?strnchr@NT@@YAPEAD_KPEBXD@Z proc
	jrcxz @@0
	mov rax,r8
	xchg rdi,rdx
	repne scasb
	mov rax,rdi
	mov rdi,rdx
	cmovne rax,rcx
	ret
@@0:
	mov eax,ecx
	ret
?strnchr@NT@@YAPEAD_KPEBXD@Z endp

?strnrchr@NT@@YAPEAD_KPEBXD@Z proc
	jrcxz @@0
	mov rax,r8
	xchg rdi,rdx
	add rdi,rcx
	dec rdi
	std
	repne scasb
	cld
	mov rax,rdi
	mov rdi,rdx
	lea rax,[rax+2]
	cmovne rax,rcx
	ret
@@0:
	mov eax,ecx
	ret
?strnrchr@NT@@YAPEAD_KPEBXD@Z endp

_TEXT ENDS
END