	.file	"test.c"
	.intel_syntax noprefix
	.text
	.section	.rodata
.LC0:
	.string	"127.0.0.1"
	.text
	.globl	main
	.type	main, @function
main:
.LFB6:
	endbr64
	push	rbp
	mov	rbp, rsp
	sub	rsp, 1072
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR -8[rbp], rax
	xor	eax, eax
	mov	edx, 0
	mov	esi, 1
	mov	edi, 2
	call	socket@PLT
	mov	DWORD PTR -1072[rbp], eax
	mov	WORD PTR -1056[rbp], 2
	mov	edi, 4919
	call	htons@PLT
	mov	WORD PTR -1054[rbp], ax
	lea	rax, .LC0[rip]
	mov	rdi, rax
	call	inet_addr@PLT
	mov	DWORD PTR -1052[rbp], eax
	lea	rcx, -1056[rbp]
	mov	eax, DWORD PTR -1072[rbp]
	mov	edx, 16
	mov	rsi, rcx
	mov	edi, eax
	call	connect@PLT
	mov	DWORD PTR -1068[rbp], eax
	lea	rsi, -1040[rbp]
	mov	eax, DWORD PTR -1072[rbp]
	mov	ecx, 0
	mov	edx, 1024
	mov	edi, eax
	call	recv@PLT
	mov	QWORD PTR -1064[rbp], rax
	lea	rdx, -1040[rbp]
	mov	rax, QWORD PTR -1064[rbp]
	add	rax, rdx
	mov	BYTE PTR [rax], 0
	mov	eax, DWORD PTR -1072[rbp]
	mov	edi, eax
	call	close@PLT
	mov	eax, 0
	mov	rdx, QWORD PTR -8[rbp]
	sub	rdx, QWORD PTR fs:40
	je	.L3
	call	__stack_chk_fail@PLT
.L3:
	leave
	ret