quickSort:
.LFB0:
	endbr64
	push	r12
	mov	r10d, edx
	mov	r12, rdi
	push	rbp
	mov	ebp, ecx
	push	rbx
	cmp	esi, -1
	je	.L12
	lea	ebp, -1[rsi]
	xor	r10d, r10d
.L12:
	lea	edx, 0[rbp+r10]
	mov	ecx, ebp
	mov	ebx, r10d
	mov	eax, edx
	shr	eax, 31
	add	eax, edx
	sar	eax
	cdqe
	mov	rdi, QWORD PTR [r12+rax*8]
.L7:
	cmp	ebx, ecx
	jg	.L8
.L28:
	movsx	rax, ebx
	movsx	r11, ecx
	sal	rax, 3
	lea	r9, [r12+r11*8]
	lea	rdx, [r12+rax]
	mov	r8, QWORD PTR [r9]
	lea	rax, 8[r12+rax]
	mov	rsi, QWORD PTR [rdx]
	cmp	rsi, rdi
	jge	.L27
.L4:
	mov	rdx, rax
	mov	rsi, QWORD PTR [rax]
	lea	rax, 8[rax]
	add	ebx, 1
	cmp	rsi, rdi
	jl	.L4
	cmp	rdi, r8
	jge	.L5
.L13:
	lea	rax, -8[r12+r11*8]
.L6:
	mov	r9, rax
	mov	r8, QWORD PTR [rax]
	sub	rax, 8
	sub	ecx, 1
	cmp	r8, rdi
	jg	.L6
.L5:
	cmp	ecx, ebx
	jl	.L7
	mov	QWORD PTR [rdx], r8
	add	ebx, 1
	sub	ecx, 1
	mov	QWORD PTR [r9], rsi
.L31:
	cmp	ebx, ecx
	jle	.L28
.L8:
	cmp	ecx, r10d
	jg	.L29
.L11:
	cmp	ebx, ebp
	jge	.L30
	mov	r10d, ebx
	jmp	.L12
.L27:
	cmp	rdi, r8
	jl	.L13
	mov	QWORD PTR [rdx], r8
	add	ebx, 1
	sub	ecx, 1
	mov	QWORD PTR [r9], rsi
	jmp	.L31
.L30:
	pop	rbx
	pop	rbp
	pop	r12
	ret
.L29:
	mov	edx, r10d
	mov	esi, -1
	mov	rdi, r12
	call	quickSort
	jmp	.L11