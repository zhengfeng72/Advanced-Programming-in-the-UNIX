
guess:     file format elf64-x86-64


Disassembly of section .interp:

0000000000000238 <.interp>:
 238:	2f                   	(bad)  
 239:	6c                   	ins    BYTE PTR es:[rdi],dx
 23a:	69 62 36 34 2f 6c 64 	imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
 241:	2d 6c 69 6e 75       	sub    eax,0x756e696c
 246:	78 2d                	js     275 <_init-0x4ab>
 248:	78 38                	js     282 <_init-0x49e>
 24a:	36 2d 36 34 2e 73    	ss sub eax,0x732e3436
 250:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 251:	2e 32 00             	xor    al,BYTE PTR cs:[rax]

Disassembly of section .note.ABI-tag:

0000000000000254 <.note.ABI-tag>:
 254:	04 00                	add    al,0x0
 256:	00 00                	add    BYTE PTR [rax],al
 258:	10 00                	adc    BYTE PTR [rax],al
 25a:	00 00                	add    BYTE PTR [rax],al
 25c:	01 00                	add    DWORD PTR [rax],eax
 25e:	00 00                	add    BYTE PTR [rax],al
 260:	47                   	rex.RXB
 261:	4e 55                	rex.WRX push rbp
 263:	00 00                	add    BYTE PTR [rax],al
 265:	00 00                	add    BYTE PTR [rax],al
 267:	00 03                	add    BYTE PTR [rbx],al
 269:	00 00                	add    BYTE PTR [rax],al
 26b:	00 02                	add    BYTE PTR [rdx],al
 26d:	00 00                	add    BYTE PTR [rax],al
 26f:	00 00                	add    BYTE PTR [rax],al
 271:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .note.gnu.build-id:

0000000000000274 <.note.gnu.build-id>:
 274:	04 00                	add    al,0x0
 276:	00 00                	add    BYTE PTR [rax],al
 278:	14 00                	adc    al,0x0
 27a:	00 00                	add    BYTE PTR [rax],al
 27c:	03 00                	add    eax,DWORD PTR [rax]
 27e:	00 00                	add    BYTE PTR [rax],al
 280:	47                   	rex.RXB
 281:	4e 55                	rex.WRX push rbp
 283:	00 8f 1c 4f df 70    	add    BYTE PTR [rdi+0x70df4f1c],cl
 289:	48 fd                	rex.W std 
 28b:	75 be                	jne    24b <_init-0x4d5>
 28d:	82                   	(bad)  
 28e:	0a 0e                	or     cl,BYTE PTR [rsi]
 290:	5b                   	pop    rbx
 291:	a1                   	.byte 0xa1
 292:	db b9 d6 fe 9e af    	fstp   TBYTE PTR [rcx-0x5061012a]

Disassembly of section .gnu.hash:

0000000000000298 <.gnu.hash>:
 298:	02 00                	add    al,BYTE PTR [rax]
 29a:	00 00                	add    BYTE PTR [rax],al
 29c:	0f 00 00             	sldt   WORD PTR [rax]
 29f:	00 01                	add    BYTE PTR [rcx],al
 2a1:	00 00                	add    BYTE PTR [rax],al
 2a3:	00 06                	add    BYTE PTR [rsi],al
 2a5:	00 00                	add    BYTE PTR [rax],al
 2a7:	00 00                	add    BYTE PTR [rax],al
 2a9:	00 20                	add    BYTE PTR [rax],ah
 2ab:	00 80 01 10 00 0f    	add    BYTE PTR [rax+0xf001001],al
 2b1:	00 00                	add    BYTE PTR [rax],al
 2b3:	00 10                	add    BYTE PTR [rax],dl
 2b5:	00 00                	add    BYTE PTR [rax],al
 2b7:	00 29                	add    BYTE PTR [rcx],ch
 2b9:	1d 8c 1c 67 55       	sbb    eax,0x55671c8c
 2be:	61                   	(bad)  
 2bf:	10                   	.byte 0x10

Disassembly of section .dynsym:

00000000000002c0 <.dynsym>:
	...
 2d8:	78 00                	js     2da <_init-0x446>
 2da:	00 00                	add    BYTE PTR [rax],al
 2dc:	20 00                	and    BYTE PTR [rax],al
	...
 2ee:	00 00                	add    BYTE PTR [rax],al
 2f0:	11 00                	adc    DWORD PTR [rax],eax
 2f2:	00 00                	add    BYTE PTR [rax],al
 2f4:	12 00                	adc    al,BYTE PTR [rax]
	...
 306:	00 00                	add    BYTE PTR [rax],al
 308:	21 00                	and    DWORD PTR [rax],eax
 30a:	00 00                	add    BYTE PTR [rax],al
 30c:	12 00                	adc    al,BYTE PTR [rax]
	...
 31e:	00 00                	add    BYTE PTR [rax],al
 320:	28 00                	sub    BYTE PTR [rax],al
 322:	00 00                	add    BYTE PTR [rax],al
 324:	12 00                	adc    al,BYTE PTR [rax]
	...
 336:	00 00                	add    BYTE PTR [rax],al
 338:	5a                   	pop    rdx
 339:	00 00                	add    BYTE PTR [rax],al
 33b:	00 12                	add    BYTE PTR [rdx],dl
	...
 34d:	00 00                	add    BYTE PTR [rax],al
 34f:	00 0b                	add    BYTE PTR [rbx],cl
 351:	00 00                	add    BYTE PTR [rax],al
 353:	00 12                	add    BYTE PTR [rdx],dl
	...
 365:	00 00                	add    BYTE PTR [rax],al
 367:	00 36                	add    BYTE PTR [rsi],dh
 369:	00 00                	add    BYTE PTR [rax],al
 36b:	00 12                	add    BYTE PTR [rdx],dl
	...
 37d:	00 00                	add    BYTE PTR [rax],al
 37f:	00 94 00 00 00 20 00 	add    BYTE PTR [rax+rax*1+0x200000],dl
	...
 396:	00 00                	add    BYTE PTR [rax],al
 398:	2f                   	(bad)  
 399:	00 00                	add    BYTE PTR [rax],al
 39b:	00 12                	add    BYTE PTR [rdx],dl
	...
 3ad:	00 00                	add    BYTE PTR [rax],al
 3af:	00 16                	add    BYTE PTR [rsi],dl
 3b1:	00 00                	add    BYTE PTR [rax],al
 3b3:	00 12                	add    BYTE PTR [rdx],dl
	...
 3c5:	00 00                	add    BYTE PTR [rax],al
 3c7:	00 52 00             	add    BYTE PTR [rdx+0x0],dl
 3ca:	00 00                	add    BYTE PTR [rax],al
 3cc:	12 00                	adc    al,BYTE PTR [rax]
	...
 3de:	00 00                	add    BYTE PTR [rax],al
 3e0:	a3 00 00 00 20 00 00 	movabs ds:0x20000000,eax
 3e7:	00 00 
	...
 3f5:	00 00                	add    BYTE PTR [rax],al
 3f7:	00 43 00             	add    BYTE PTR [rbx+0x0],al
 3fa:	00 00                	add    BYTE PTR [rax],al
 3fc:	22 00                	and    al,BYTE PTR [rax]
	...
 40e:	00 00                	add    BYTE PTR [rax],al
 410:	0c 00                	or     al,0x0
 412:	00 00                	add    BYTE PTR [rax],al
 414:	12 00                	adc    al,BYTE PTR [rax]
	...
 426:	00 00                	add    BYTE PTR [rax],al
 428:	3c 00                	cmp    al,0x0
 42a:	00 00                	add    BYTE PTR [rax],al
 42c:	11 00                	adc    DWORD PTR [rax],eax
 42e:	18 00                	sbb    BYTE PTR [rax],al
 430:	10 10                	adc    BYTE PTR [rax],dl
 432:	20 00                	and    BYTE PTR [rax],al
 434:	00 00                	add    BYTE PTR [rax],al
 436:	00 00                	add    BYTE PTR [rax],al
 438:	08 00                	or     BYTE PTR [rax],al
 43a:	00 00                	add    BYTE PTR [rax],al
 43c:	00 00                	add    BYTE PTR [rax],al
 43e:	00 00                	add    BYTE PTR [rax],al
 440:	1b 00                	sbb    eax,DWORD PTR [rax]
 442:	00 00                	add    BYTE PTR [rax],al
 444:	11 00                	adc    DWORD PTR [rax],eax
 446:	18 00                	sbb    BYTE PTR [rax],al
 448:	20 10                	and    BYTE PTR [rax],dl
 44a:	20 00                	and    BYTE PTR [rax],al
 44c:	00 00                	add    BYTE PTR [rax],al
 44e:	00 00                	add    BYTE PTR [rax],al
 450:	08 00                	or     BYTE PTR [rax],al
 452:	00 00                	add    BYTE PTR [rax],al
 454:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynstr:

0000000000000458 <.dynstr>:
 458:	00 6c 69 62          	add    BYTE PTR [rcx+rbp*2+0x62],ch
 45c:	63 2e                	movsxd ebp,DWORD PTR [rsi]
 45e:	73 6f                	jae    4cf <_init-0x251>
 460:	2e 36 00 73 72       	cs add BYTE PTR ss:[rbx+0x72],dh
 465:	61                   	(bad)  
 466:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 467:	64 00 70 75          	add    BYTE PTR fs:[rax+0x75],dh
 46b:	74 73                	je     4e0 <_init-0x240>
 46d:	00 74 69 6d          	add    BYTE PTR [rcx+rbp*2+0x6d],dh
 471:	65 00 73 74          	add    BYTE PTR gs:[rbx+0x74],dh
 475:	64 69 6e 00 67 65 74 	imul   ebp,DWORD PTR fs:[rsi+0x0],0x70746567
 47c:	70 
 47d:	69 64 00 70 72 69 6e 	imul   esp,DWORD PTR [rax+rax*1+0x70],0x746e6972
 484:	74 
 485:	66 00 73 74          	data16 add BYTE PTR [rbx+0x74],dh
 489:	72 74                	jb     4ff <_init-0x221>
 48b:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 48c:	6c                   	ins    BYTE PTR es:[rdi],dx
 48d:	00 66 67             	add    BYTE PTR [rsi+0x67],ah
 490:	65 74 73             	gs je  506 <_init-0x21a>
 493:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
 496:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
 498:	75 74                	jne    50e <_init-0x212>
 49a:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 49d:	63 78 61             	movsxd edi,DWORD PTR [rax+0x61]
 4a0:	5f                   	pop    rdi
 4a1:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
 4a7:	7a 65                	jp     50e <_init-0x212>
 4a9:	00 73 65             	add    BYTE PTR [rbx+0x65],dh
 4ac:	74 76                	je     524 <_init-0x1fc>
 4ae:	62                   	(bad)  
 4af:	75 66                	jne    517 <_init-0x209>
 4b1:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 4b4:	6c                   	ins    BYTE PTR es:[rdi],dx
 4b5:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
 4bc:	72 74                	jb     532 <_init-0x1ee>
 4be:	5f                   	pop    rdi
 4bf:	6d                   	ins    DWORD PTR es:[rdi],dx
 4c0:	61                   	(bad)  
 4c1:	69 6e 00 47 4c 49 42 	imul   ebp,DWORD PTR [rsi+0x0],0x42494c47
 4c8:	43 5f                	rex.XB pop r15
 4ca:	32 2e                	xor    ch,BYTE PTR [rsi]
 4cc:	32 2e                	xor    ch,BYTE PTR [rsi]
 4ce:	35 00 5f 49 54       	xor    eax,0x54495f00
 4d3:	4d 5f                	rex.WRB pop r15
 4d5:	64 65 72 65          	fs gs jb 53e <_init-0x1e2>
 4d9:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 4e0:	4d 
 4e1:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 4e3:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 4e4:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 4e5:	65 54                	gs push rsp
 4e7:	61                   	(bad)  
 4e8:	62                   	(bad)  
 4e9:	6c                   	ins    BYTE PTR es:[rdi],dx
 4ea:	65 00 5f 5f          	add    BYTE PTR gs:[rdi+0x5f],bl
 4ee:	67 6d                	ins    DWORD PTR es:[edi],dx
 4f0:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 4f1:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 4f2:	5f                   	pop    rdi
 4f3:	73 74                	jae    569 <_init-0x1b7>
 4f5:	61                   	(bad)  
 4f6:	72 74                	jb     56c <_init-0x1b4>
 4f8:	5f                   	pop    rdi
 4f9:	5f                   	pop    rdi
 4fa:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 4fd:	54                   	push   rsp
 4fe:	4d 5f                	rex.WRB pop r15
 500:	72 65                	jb     567 <_init-0x1b9>
 502:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 509:	4d 
 50a:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 50c:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 50d:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 50e:	65 54                	gs push rsp
 510:	61                   	(bad)  
 511:	62                   	.byte 0x62
 512:	6c                   	ins    BYTE PTR es:[rdi],dx
 513:	65                   	gs
	...

Disassembly of section .gnu.version:

0000000000000516 <.gnu.version>:
 516:	00 00                	add    BYTE PTR [rax],al
 518:	00 00                	add    BYTE PTR [rax],al
 51a:	02 00                	add    al,BYTE PTR [rax]
 51c:	02 00                	add    al,BYTE PTR [rax]
 51e:	02 00                	add    al,BYTE PTR [rax]
 520:	02 00                	add    al,BYTE PTR [rax]
 522:	02 00                	add    al,BYTE PTR [rax]
 524:	02 00                	add    al,BYTE PTR [rax]
 526:	00 00                	add    BYTE PTR [rax],al
 528:	02 00                	add    al,BYTE PTR [rax]
 52a:	02 00                	add    al,BYTE PTR [rax]
 52c:	02 00                	add    al,BYTE PTR [rax]
 52e:	00 00                	add    BYTE PTR [rax],al
 530:	02 00                	add    al,BYTE PTR [rax]
 532:	02 00                	add    al,BYTE PTR [rax]
 534:	02 00                	add    al,BYTE PTR [rax]
 536:	02 00                	add    al,BYTE PTR [rax]

Disassembly of section .gnu.version_r:

0000000000000538 <.gnu.version_r>:
 538:	01 00                	add    DWORD PTR [rax],eax
 53a:	01 00                	add    DWORD PTR [rax],eax
 53c:	01 00                	add    DWORD PTR [rax],eax
 53e:	00 00                	add    BYTE PTR [rax],al
 540:	10 00                	adc    BYTE PTR [rax],al
 542:	00 00                	add    BYTE PTR [rax],al
 544:	00 00                	add    BYTE PTR [rax],al
 546:	00 00                	add    BYTE PTR [rax],al
 548:	75 1a                	jne    564 <_init-0x1bc>
 54a:	69 09 00 00 02 00    	imul   ecx,DWORD PTR [rcx],0x20000
 550:	6c                   	ins    BYTE PTR es:[rdi],dx
 551:	00 00                	add    BYTE PTR [rax],al
 553:	00 00                	add    BYTE PTR [rax],al
 555:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .rela.dyn:

0000000000000558 <.rela.dyn>:
 558:	78 0d                	js     567 <_init-0x1b9>
 55a:	20 00                	and    BYTE PTR [rax],al
 55c:	00 00                	add    BYTE PTR [rax],al
 55e:	00 00                	add    BYTE PTR [rax],al
 560:	08 00                	or     BYTE PTR [rax],al
 562:	00 00                	add    BYTE PTR [rax],al
 564:	00 00                	add    BYTE PTR [rax],al
 566:	00 00                	add    BYTE PTR [rax],al
 568:	f0 08 00             	lock or BYTE PTR [rax],al
 56b:	00 00                	add    BYTE PTR [rax],al
 56d:	00 00                	add    BYTE PTR [rax],al
 56f:	00 80 0d 20 00 00    	add    BYTE PTR [rax+0x200d],al
 575:	00 00                	add    BYTE PTR [rax],al
 577:	00 08                	add    BYTE PTR [rax],cl
 579:	00 00                	add    BYTE PTR [rax],al
 57b:	00 00                	add    BYTE PTR [rax],al
 57d:	00 00                	add    BYTE PTR [rax],al
 57f:	00 b0 08 00 00 00    	add    BYTE PTR [rax+0x8],dh
 585:	00 00                	add    BYTE PTR [rax],al
 587:	00 08                	add    BYTE PTR [rax],cl
 589:	10 20                	adc    BYTE PTR [rax],ah
 58b:	00 00                	add    BYTE PTR [rax],al
 58d:	00 00                	add    BYTE PTR [rax],al
 58f:	00 08                	add    BYTE PTR [rax],cl
 591:	00 00                	add    BYTE PTR [rax],al
 593:	00 00                	add    BYTE PTR [rax],al
 595:	00 00                	add    BYTE PTR [rax],al
 597:	00 08                	add    BYTE PTR [rax],cl
 599:	10 20                	adc    BYTE PTR [rax],ah
 59b:	00 00                	add    BYTE PTR [rax],al
 59d:	00 00                	add    BYTE PTR [rax],al
 59f:	00 d8                	add    al,bl
 5a1:	0f 20 00             	mov    rax,cr0
 5a4:	00 00                	add    BYTE PTR [rax],al
 5a6:	00 00                	add    BYTE PTR [rax],al
 5a8:	06                   	(bad)  
 5a9:	00 00                	add    BYTE PTR [rax],al
 5ab:	00 01                	add    BYTE PTR [rcx],al
	...
 5b5:	00 00                	add    BYTE PTR [rax],al
 5b7:	00 e0                	add    al,ah
 5b9:	0f 20 00             	mov    rax,cr0
 5bc:	00 00                	add    BYTE PTR [rax],al
 5be:	00 00                	add    BYTE PTR [rax],al
 5c0:	06                   	(bad)  
 5c1:	00 00                	add    BYTE PTR [rax],al
 5c3:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 5c9 <_init-0x157>
 5c9:	00 00                	add    BYTE PTR [rax],al
 5cb:	00 00                	add    BYTE PTR [rax],al
 5cd:	00 00                	add    BYTE PTR [rax],al
 5cf:	00 e8                	add    al,ch
 5d1:	0f 20 00             	mov    rax,cr0
 5d4:	00 00                	add    BYTE PTR [rax],al
 5d6:	00 00                	add    BYTE PTR [rax],al
 5d8:	06                   	(bad)  
 5d9:	00 00                	add    BYTE PTR [rax],al
 5db:	00 08                	add    BYTE PTR [rax],cl
	...
 5e5:	00 00                	add    BYTE PTR [rax],al
 5e7:	00 f0                	add    al,dh
 5e9:	0f 20 00             	mov    rax,cr0
 5ec:	00 00                	add    BYTE PTR [rax],al
 5ee:	00 00                	add    BYTE PTR [rax],al
 5f0:	06                   	(bad)  
 5f1:	00 00                	add    BYTE PTR [rax],al
 5f3:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
	...
 5fe:	00 00                	add    BYTE PTR [rax],al
 600:	f8                   	clc    
 601:	0f 20 00             	mov    rax,cr0
 604:	00 00                	add    BYTE PTR [rax],al
 606:	00 00                	add    BYTE PTR [rax],al
 608:	06                   	(bad)  
 609:	00 00                	add    BYTE PTR [rax],al
 60b:	00 0d 00 00 00 00    	add    BYTE PTR [rip+0x0],cl        # 611 <_init-0x10f>
 611:	00 00                	add    BYTE PTR [rax],al
 613:	00 00                	add    BYTE PTR [rax],al
 615:	00 00                	add    BYTE PTR [rax],al
 617:	00 10                	add    BYTE PTR [rax],dl
 619:	10 20                	adc    BYTE PTR [rax],ah
 61b:	00 00                	add    BYTE PTR [rax],al
 61d:	00 00                	add    BYTE PTR [rax],al
 61f:	00 05 00 00 00 0f    	add    BYTE PTR [rip+0xf000000],al        # f000625 <_end+0xedff5f5>
	...
 62d:	00 00                	add    BYTE PTR [rax],al
 62f:	00 20                	add    BYTE PTR [rax],ah
 631:	10 20                	adc    BYTE PTR [rax],ah
 633:	00 00                	add    BYTE PTR [rax],al
 635:	00 00                	add    BYTE PTR [rax],al
 637:	00 05 00 00 00 10    	add    BYTE PTR [rip+0x10000000],al        # 1000063d <_end+0xfdff60d>
	...

Disassembly of section .rela.plt:

0000000000000648 <.rela.plt>:
 648:	90                   	nop
 649:	0f 20 00             	mov    rax,cr0
 64c:	00 00                	add    BYTE PTR [rax],al
 64e:	00 00                	add    BYTE PTR [rax],al
 650:	07                   	(bad)  
 651:	00 00                	add    BYTE PTR [rax],al
 653:	00 02                	add    BYTE PTR [rdx],al
	...
 65d:	00 00                	add    BYTE PTR [rax],al
 65f:	00 98 0f 20 00 00    	add    BYTE PTR [rax+0x200f],bl
 665:	00 00                	add    BYTE PTR [rax],al
 667:	00 07                	add    BYTE PTR [rdi],al
 669:	00 00                	add    BYTE PTR [rax],al
 66b:	00 03                	add    BYTE PTR [rbx],al
	...
 675:	00 00                	add    BYTE PTR [rax],al
 677:	00 a0 0f 20 00 00    	add    BYTE PTR [rax+0x200f],ah
 67d:	00 00                	add    BYTE PTR [rax],al
 67f:	00 07                	add    BYTE PTR [rdi],al
 681:	00 00                	add    BYTE PTR [rax],al
 683:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
 68e:	00 00                	add    BYTE PTR [rax],al
 690:	a8 0f                	test   al,0xf
 692:	20 00                	and    BYTE PTR [rax],al
 694:	00 00                	add    BYTE PTR [rax],al
 696:	00 00                	add    BYTE PTR [rax],al
 698:	07                   	(bad)  
 699:	00 00                	add    BYTE PTR [rax],al
 69b:	00 06                	add    BYTE PTR [rsi],al
	...
 6a5:	00 00                	add    BYTE PTR [rax],al
 6a7:	00 b0 0f 20 00 00    	add    BYTE PTR [rax+0x200f],dh
 6ad:	00 00                	add    BYTE PTR [rax],al
 6af:	00 07                	add    BYTE PTR [rdi],al
 6b1:	00 00                	add    BYTE PTR [rax],al
 6b3:	00 07                	add    BYTE PTR [rdi],al
	...
 6bd:	00 00                	add    BYTE PTR [rax],al
 6bf:	00 b8 0f 20 00 00    	add    BYTE PTR [rax+0x200f],bh
 6c5:	00 00                	add    BYTE PTR [rax],al
 6c7:	00 07                	add    BYTE PTR [rdi],al
 6c9:	00 00                	add    BYTE PTR [rax],al
 6cb:	00 09                	add    BYTE PTR [rcx],cl
	...
 6d5:	00 00                	add    BYTE PTR [rax],al
 6d7:	00 c0                	add    al,al
 6d9:	0f 20 00             	mov    rax,cr0
 6dc:	00 00                	add    BYTE PTR [rax],al
 6de:	00 00                	add    BYTE PTR [rax],al
 6e0:	07                   	(bad)  
 6e1:	00 00                	add    BYTE PTR [rax],al
 6e3:	00 0a                	add    BYTE PTR [rdx],cl
	...
 6ed:	00 00                	add    BYTE PTR [rax],al
 6ef:	00 c8                	add    al,cl
 6f1:	0f 20 00             	mov    rax,cr0
 6f4:	00 00                	add    BYTE PTR [rax],al
 6f6:	00 00                	add    BYTE PTR [rax],al
 6f8:	07                   	(bad)  
 6f9:	00 00                	add    BYTE PTR [rax],al
 6fb:	00 0b                	add    BYTE PTR [rbx],cl
	...
 705:	00 00                	add    BYTE PTR [rax],al
 707:	00 d0                	add    al,dl
 709:	0f 20 00             	mov    rax,cr0
 70c:	00 00                	add    BYTE PTR [rax],al
 70e:	00 00                	add    BYTE PTR [rax],al
 710:	07                   	(bad)  
 711:	00 00                	add    BYTE PTR [rax],al
 713:	00 0e                	add    BYTE PTR [rsi],cl
	...

Disassembly of section .init:

0000000000000720 <_init>:
 720:	48 83 ec 08          	sub    rsp,0x8
 724:	48 8b 05 bd 08 20 00 	mov    rax,QWORD PTR [rip+0x2008bd]        # 200fe8 <__gmon_start__>
 72b:	48 85 c0             	test   rax,rax
 72e:	74 02                	je     732 <_init+0x12>
 730:	ff d0                	call   rax
 732:	48 83 c4 08          	add    rsp,0x8
 736:	c3                   	ret    

Disassembly of section .plt:

0000000000000740 <.plt>:
 740:	ff 35 3a 08 20 00    	push   QWORD PTR [rip+0x20083a]        # 200f80 <_GLOBAL_OFFSET_TABLE_+0x8>
 746:	ff 25 3c 08 20 00    	jmp    QWORD PTR [rip+0x20083c]        # 200f88 <_GLOBAL_OFFSET_TABLE_+0x10>
 74c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000000750 <puts@plt>:
 750:	ff 25 3a 08 20 00    	jmp    QWORD PTR [rip+0x20083a]        # 200f90 <puts@GLIBC_2.2.5>
 756:	68 00 00 00 00       	push   0x0
 75b:	e9 e0 ff ff ff       	jmp    740 <.plt>

0000000000000760 <getpid@plt>:
 760:	ff 25 32 08 20 00    	jmp    QWORD PTR [rip+0x200832]        # 200f98 <getpid@GLIBC_2.2.5>
 766:	68 01 00 00 00       	push   0x1
 76b:	e9 d0 ff ff ff       	jmp    740 <.plt>

0000000000000770 <printf@plt>:
 770:	ff 25 2a 08 20 00    	jmp    QWORD PTR [rip+0x20082a]        # 200fa0 <printf@GLIBC_2.2.5>
 776:	68 02 00 00 00       	push   0x2
 77b:	e9 c0 ff ff ff       	jmp    740 <.plt>

0000000000000780 <srand@plt>:
 780:	ff 25 22 08 20 00    	jmp    QWORD PTR [rip+0x200822]        # 200fa8 <srand@GLIBC_2.2.5>
 786:	68 03 00 00 00       	push   0x3
 78b:	e9 b0 ff ff ff       	jmp    740 <.plt>

0000000000000790 <fgets@plt>:
 790:	ff 25 1a 08 20 00    	jmp    QWORD PTR [rip+0x20081a]        # 200fb0 <fgets@GLIBC_2.2.5>
 796:	68 04 00 00 00       	push   0x4
 79b:	e9 a0 ff ff ff       	jmp    740 <.plt>

00000000000007a0 <strtol@plt>:
 7a0:	ff 25 12 08 20 00    	jmp    QWORD PTR [rip+0x200812]        # 200fb8 <strtol@GLIBC_2.2.5>
 7a6:	68 05 00 00 00       	push   0x5
 7ab:	e9 90 ff ff ff       	jmp    740 <.plt>

00000000000007b0 <time@plt>:
 7b0:	ff 25 0a 08 20 00    	jmp    QWORD PTR [rip+0x20080a]        # 200fc0 <time@GLIBC_2.2.5>
 7b6:	68 06 00 00 00       	push   0x6
 7bb:	e9 80 ff ff ff       	jmp    740 <.plt>

00000000000007c0 <setvbuf@plt>:
 7c0:	ff 25 02 08 20 00    	jmp    QWORD PTR [rip+0x200802]        # 200fc8 <setvbuf@GLIBC_2.2.5>
 7c6:	68 07 00 00 00       	push   0x7
 7cb:	e9 70 ff ff ff       	jmp    740 <.plt>

00000000000007d0 <rand@plt>:
 7d0:	ff 25 fa 07 20 00    	jmp    QWORD PTR [rip+0x2007fa]        # 200fd0 <rand@GLIBC_2.2.5>
 7d6:	68 08 00 00 00       	push   0x8
 7db:	e9 60 ff ff ff       	jmp    740 <.plt>

Disassembly of section .plt.got:

00000000000007e0 <__cxa_finalize@plt>:
 7e0:	ff 25 12 08 20 00    	jmp    QWORD PTR [rip+0x200812]        # 200ff8 <__cxa_finalize@GLIBC_2.2.5>
 7e6:	66 90                	xchg   ax,ax

Disassembly of section .text:

00000000000007f0 <_start>:
 7f0:	31 ed                	xor    ebp,ebp
 7f2:	49 89 d1             	mov    r9,rdx
 7f5:	5e                   	pop    rsi
 7f6:	48 89 e2             	mov    rdx,rsp
 7f9:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
 7fd:	50                   	push   rax
 7fe:	54                   	push   rsp
 7ff:	4c 8d 05 6a 02 00 00 	lea    r8,[rip+0x26a]        # a70 <__libc_csu_fini>
 806:	48 8d 0d f3 01 00 00 	lea    rcx,[rip+0x1f3]        # a00 <__libc_csu_init>
 80d:	48 8d 3d e6 00 00 00 	lea    rdi,[rip+0xe6]        # 8fa <main>
 814:	ff 15 c6 07 20 00    	call   QWORD PTR [rip+0x2007c6]        # 200fe0 <__libc_start_main@GLIBC_2.2.5>
 81a:	f4                   	hlt    
 81b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000000820 <deregister_tm_clones>:
 820:	48 8d 3d e9 07 20 00 	lea    rdi,[rip+0x2007e9]        # 201010 <stdout@@GLIBC_2.2.5>
 827:	55                   	push   rbp
 828:	48 8d 05 e1 07 20 00 	lea    rax,[rip+0x2007e1]        # 201010 <stdout@@GLIBC_2.2.5>
 82f:	48 39 f8             	cmp    rax,rdi
 832:	48 89 e5             	mov    rbp,rsp
 835:	74 19                	je     850 <deregister_tm_clones+0x30>
 837:	48 8b 05 9a 07 20 00 	mov    rax,QWORD PTR [rip+0x20079a]        # 200fd8 <_ITM_deregisterTMCloneTable>
 83e:	48 85 c0             	test   rax,rax
 841:	74 0d                	je     850 <deregister_tm_clones+0x30>
 843:	5d                   	pop    rbp
 844:	ff e0                	jmp    rax
 846:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 84d:	00 00 00 
 850:	5d                   	pop    rbp
 851:	c3                   	ret    
 852:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
 856:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 85d:	00 00 00 

0000000000000860 <register_tm_clones>:
 860:	48 8d 3d a9 07 20 00 	lea    rdi,[rip+0x2007a9]        # 201010 <stdout@@GLIBC_2.2.5>
 867:	48 8d 35 a2 07 20 00 	lea    rsi,[rip+0x2007a2]        # 201010 <stdout@@GLIBC_2.2.5>
 86e:	55                   	push   rbp
 86f:	48 29 fe             	sub    rsi,rdi
 872:	48 89 e5             	mov    rbp,rsp
 875:	48 c1 fe 03          	sar    rsi,0x3
 879:	48 89 f0             	mov    rax,rsi
 87c:	48 c1 e8 3f          	shr    rax,0x3f
 880:	48 01 c6             	add    rsi,rax
 883:	48 d1 fe             	sar    rsi,1
 886:	74 18                	je     8a0 <register_tm_clones+0x40>
 888:	48 8b 05 61 07 20 00 	mov    rax,QWORD PTR [rip+0x200761]        # 200ff0 <_ITM_registerTMCloneTable>
 88f:	48 85 c0             	test   rax,rax
 892:	74 0c                	je     8a0 <register_tm_clones+0x40>
 894:	5d                   	pop    rbp
 895:	ff e0                	jmp    rax
 897:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
 89e:	00 00 
 8a0:	5d                   	pop    rbp
 8a1:	c3                   	ret    
 8a2:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
 8a6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 8ad:	00 00 00 

00000000000008b0 <__do_global_dtors_aux>:
 8b0:	80 3d 71 07 20 00 00 	cmp    BYTE PTR [rip+0x200771],0x0        # 201028 <completed.7698>
 8b7:	75 2f                	jne    8e8 <__do_global_dtors_aux+0x38>
 8b9:	48 83 3d 37 07 20 00 	cmp    QWORD PTR [rip+0x200737],0x0        # 200ff8 <__cxa_finalize@GLIBC_2.2.5>
 8c0:	00 
 8c1:	55                   	push   rbp
 8c2:	48 89 e5             	mov    rbp,rsp
 8c5:	74 0c                	je     8d3 <__do_global_dtors_aux+0x23>
 8c7:	48 8b 3d 3a 07 20 00 	mov    rdi,QWORD PTR [rip+0x20073a]        # 201008 <__dso_handle>
 8ce:	e8 0d ff ff ff       	call   7e0 <__cxa_finalize@plt>
 8d3:	e8 48 ff ff ff       	call   820 <deregister_tm_clones>
 8d8:	c6 05 49 07 20 00 01 	mov    BYTE PTR [rip+0x200749],0x1        # 201028 <completed.7698>
 8df:	5d                   	pop    rbp
 8e0:	c3                   	ret    
 8e1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
 8e8:	f3 c3                	repz ret 
 8ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000008f0 <frame_dummy>:
 8f0:	55                   	push   rbp
 8f1:	48 89 e5             	mov    rbp,rsp
 8f4:	5d                   	pop    rbp
 8f5:	e9 66 ff ff ff       	jmp    860 <register_tm_clones>

00000000000008fa <main>:
 8fa:	55                   	push   rbp
 8fb:	48 89 e5             	mov    rbp,rsp
 8fe:	53                   	push   rbx
 8ff:	48 83 ec 28          	sub    rsp,0x28
 903:	48 8b 05 06 07 20 00 	mov    rax,QWORD PTR [rip+0x200706]        # 201010 <stdout@@GLIBC_2.2.5>
 90a:	b9 00 00 00 00       	mov    ecx,0x0
 90f:	ba 02 00 00 00       	mov    edx,0x2
 914:	be 00 00 00 00       	mov    esi,0x0
 919:	48 89 c7             	mov    rdi,rax
 91c:	e8 9f fe ff ff       	call   7c0 <setvbuf@plt>
 921:	bf 00 00 00 00       	mov    edi,0x0
 926:	e8 85 fe ff ff       	call   7b0 <time@plt>
 92b:	89 c3                	mov    ebx,eax
 92d:	e8 2e fe ff ff       	call   760 <getpid@plt>
 932:	31 d8                	xor    eax,ebx
 934:	89 c7                	mov    edi,eax
 936:	e8 45 fe ff ff       	call   780 <srand@plt>
 93b:	e8 90 fe ff ff       	call   7d0 <rand@plt>
 940:	89 c1                	mov    ecx,eax
 942:	ba ad 8b db 68       	mov    edx,0x68db8bad
 947:	89 c8                	mov    eax,ecx
 949:	f7 ea                	imul   edx
 94b:	c1 fa 0c             	sar    edx,0xc
 94e:	89 c8                	mov    eax,ecx
 950:	c1 f8 1f             	sar    eax,0x1f
 953:	29 c2                	sub    edx,eax
 955:	89 d0                	mov    eax,edx
 957:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
 95a:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
 95d:	69 c0 10 27 00 00    	imul   eax,eax,0x2710
 963:	29 c1                	sub    ecx,eax
 965:	89 c8                	mov    eax,ecx
 967:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
 96a:	48 8d 3d 13 01 00 00 	lea    rdi,[rip+0x113]        # a84 <_IO_stdin_used+0x4>
 971:	b8 00 00 00 00       	mov    eax,0x0
 976:	e8 f5 fd ff ff       	call   770 <printf@plt>
 97b:	48 8b 15 9e 06 20 00 	mov    rdx,QWORD PTR [rip+0x20069e]        # 201020 <stdin@@GLIBC_2.2.5>
 982:	48 8d 45 d0          	lea    rax,[rbp-0x30]
 986:	be 20 00 00 00       	mov    esi,0x20
 98b:	48 89 c7             	mov    rdi,rax
 98e:	e8 fd fd ff ff       	call   790 <fgets@plt>
 993:	48 85 c0             	test   rax,rax
 996:	74 51                	je     9e9 <main+0xef>
 998:	48 8d 45 d0          	lea    rax,[rbp-0x30]
 99c:	ba 00 00 00 00       	mov    edx,0x0
 9a1:	be 00 00 00 00       	mov    esi,0x0
 9a6:	48 89 c7             	mov    rdi,rax
 9a9:	e8 f2 fd ff ff       	call   7a0 <strtol@plt>
 9ae:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
 9b1:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
 9b4:	89 c6                	mov    esi,eax
 9b6:	48 8d 3d da 00 00 00 	lea    rdi,[rip+0xda]        # a97 <_IO_stdin_used+0x17>
 9bd:	b8 00 00 00 00       	mov    eax,0x0
 9c2:	e8 a9 fd ff ff       	call   770 <printf@plt>
 9c7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
 9ca:	3b 45 ec             	cmp    eax,DWORD PTR [rbp-0x14]
 9cd:	75 0e                	jne    9dd <main+0xe3>
 9cf:	48 8d 3d d3 00 00 00 	lea    rdi,[rip+0xd3]        # aa9 <_IO_stdin_used+0x29>
 9d6:	e8 75 fd ff ff       	call   750 <puts@plt>
 9db:	eb 0c                	jmp    9e9 <main+0xef>
 9dd:	48 8d 3d cc 00 00 00 	lea    rdi,[rip+0xcc]        # ab0 <_IO_stdin_used+0x30>
 9e4:	e8 67 fd ff ff       	call   750 <puts@plt>
 9e9:	b8 00 00 00 00       	mov    eax,0x0
 9ee:	48 83 c4 28          	add    rsp,0x28
 9f2:	5b                   	pop    rbx
 9f3:	5d                   	pop    rbp
 9f4:	c3                   	ret    
 9f5:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 9fc:	00 00 00 
 9ff:	90                   	nop

0000000000000a00 <__libc_csu_init>:
 a00:	41 57                	push   r15
 a02:	41 56                	push   r14
 a04:	49 89 d7             	mov    r15,rdx
 a07:	41 55                	push   r13
 a09:	41 54                	push   r12
 a0b:	4c 8d 25 66 03 20 00 	lea    r12,[rip+0x200366]        # 200d78 <__frame_dummy_init_array_entry>
 a12:	55                   	push   rbp
 a13:	48 8d 2d 66 03 20 00 	lea    rbp,[rip+0x200366]        # 200d80 <__init_array_end>
 a1a:	53                   	push   rbx
 a1b:	41 89 fd             	mov    r13d,edi
 a1e:	49 89 f6             	mov    r14,rsi
 a21:	4c 29 e5             	sub    rbp,r12
 a24:	48 83 ec 08          	sub    rsp,0x8
 a28:	48 c1 fd 03          	sar    rbp,0x3
 a2c:	e8 ef fc ff ff       	call   720 <_init>
 a31:	48 85 ed             	test   rbp,rbp
 a34:	74 20                	je     a56 <__libc_csu_init+0x56>
 a36:	31 db                	xor    ebx,ebx
 a38:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
 a3f:	00 
 a40:	4c 89 fa             	mov    rdx,r15
 a43:	4c 89 f6             	mov    rsi,r14
 a46:	44 89 ef             	mov    edi,r13d
 a49:	41 ff 14 dc          	call   QWORD PTR [r12+rbx*8]
 a4d:	48 83 c3 01          	add    rbx,0x1
 a51:	48 39 dd             	cmp    rbp,rbx
 a54:	75 ea                	jne    a40 <__libc_csu_init+0x40>
 a56:	48 83 c4 08          	add    rsp,0x8
 a5a:	5b                   	pop    rbx
 a5b:	5d                   	pop    rbp
 a5c:	41 5c                	pop    r12
 a5e:	41 5d                	pop    r13
 a60:	41 5e                	pop    r14
 a62:	41 5f                	pop    r15
 a64:	c3                   	ret    
 a65:	90                   	nop
 a66:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 a6d:	00 00 00 

0000000000000a70 <__libc_csu_fini>:
 a70:	f3 c3                	repz ret 

Disassembly of section .fini:

0000000000000a74 <_fini>:
 a74:	48 83 ec 08          	sub    rsp,0x8
 a78:	48 83 c4 08          	add    rsp,0x8
 a7c:	c3                   	ret    

Disassembly of section .rodata:

0000000000000a80 <_IO_stdin_used>:
 a80:	01 00                	add    DWORD PTR [rax],eax
 a82:	02 00                	add    al,BYTE PTR [rax]
 a84:	47 75 65             	rex.RXB jne aec <__GNU_EH_FRAME_HDR+0x2c>
 a87:	73 73                	jae    afc <__GNU_EH_FRAME_HDR+0x3c>
 a89:	20 74 68 65          	and    BYTE PTR [rax+rbp*2+0x65],dh
 a8d:	20 6e 75             	and    BYTE PTR [rsi+0x75],ch
 a90:	6d                   	ins    DWORD PTR es:[rdi],dx
 a91:	62                   	(bad)  
 a92:	65 72 3a             	gs jb  acf <__GNU_EH_FRAME_HDR+0xf>
 a95:	20 00                	and    BYTE PTR [rax],al
 a97:	59                   	pop    rcx
 a98:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 a99:	75 72                	jne    b0d <__GNU_EH_FRAME_HDR+0x4d>
 a9b:	20 67 75             	and    BYTE PTR [rdi+0x75],ah
 a9e:	65 73 73             	gs jae b14 <__GNU_EH_FRAME_HDR+0x54>
 aa1:	20 69 73             	and    BYTE PTR [rcx+0x73],ch
 aa4:	20 25 64 0a 00 42    	and    BYTE PTR [rip+0x42000a64],ah        # 4200150e <_end+0x41e004de>
 aaa:	69 6e 67 6f 21 00 4e 	imul   ebp,DWORD PTR [rsi+0x67],0x4e00216f
 ab1:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 ab2:	20 6e 6f             	and    BYTE PTR [rsi+0x6f],ch
 ab5:	20 6e 6f             	and    BYTE PTR [rsi+0x6f],ch
 ab8:	20 2e                	and    BYTE PTR [rsi],ch
 aba:	2e                   	cs
 abb:	2e                   	cs
	...

Disassembly of section .eh_frame_hdr:

0000000000000ac0 <__GNU_EH_FRAME_HDR>:
 ac0:	01 1b                	add    DWORD PTR [rbx],ebx
 ac2:	03 3b                	add    edi,DWORD PTR [rbx]
 ac4:	3c 00                	cmp    al,0x0
 ac6:	00 00                	add    BYTE PTR [rax],al
 ac8:	06                   	(bad)  
 ac9:	00 00                	add    BYTE PTR [rax],al
 acb:	00 80 fc ff ff 88    	add    BYTE PTR [rax-0x77000004],al
 ad1:	00 00                	add    BYTE PTR [rax],al
 ad3:	00 20                	add    BYTE PTR [rax],ah
 ad5:	fd                   	std    
 ad6:	ff                   	(bad)  
 ad7:	ff b0 00 00 00 30    	push   QWORD PTR [rax+0x30000000]
 add:	fd                   	std    
 ade:	ff                   	(bad)  
 adf:	ff 58 00             	call   FWORD PTR [rax+0x0]
 ae2:	00 00                	add    BYTE PTR [rax],al
 ae4:	3a fe                	cmp    bh,dh
 ae6:	ff                   	(bad)  
 ae7:	ff c8                	dec    eax
 ae9:	00 00                	add    BYTE PTR [rax],al
 aeb:	00 40 ff             	add    BYTE PTR [rax-0x1],al
 aee:	ff                   	(bad)  
 aef:	ff f0                	push   rax
 af1:	00 00                	add    BYTE PTR [rax],al
 af3:	00 b0 ff ff ff 38    	add    BYTE PTR [rax+0x38ffffff],dh
 af9:	01 00                	add    DWORD PTR [rax],eax
	...

Disassembly of section .eh_frame:

0000000000000b00 <__FRAME_END__-0x10c>:
 b00:	14 00                	adc    al,0x0
 b02:	00 00                	add    BYTE PTR [rax],al
 b04:	00 00                	add    BYTE PTR [rax],al
 b06:	00 00                	add    BYTE PTR [rax],al
 b08:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
 b0b:	00 01                	add    BYTE PTR [rcx],al
 b0d:	78 10                	js     b1f <__GNU_EH_FRAME_HDR+0x5f>
 b0f:	01 1b                	add    DWORD PTR [rbx],ebx
 b11:	0c 07                	or     al,0x7
 b13:	08 90 01 07 10 14    	or     BYTE PTR [rax+0x14100701],dl
 b19:	00 00                	add    BYTE PTR [rax],al
 b1b:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
 b1e:	00 00                	add    BYTE PTR [rax],al
 b20:	d0 fc                	sar    ah,1
 b22:	ff                   	(bad)  
 b23:	ff 2b                	jmp    FWORD PTR [rbx]
	...
 b2d:	00 00                	add    BYTE PTR [rax],al
 b2f:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
 b32:	00 00                	add    BYTE PTR [rax],al
 b34:	00 00                	add    BYTE PTR [rax],al
 b36:	00 00                	add    BYTE PTR [rax],al
 b38:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
 b3b:	00 01                	add    BYTE PTR [rcx],al
 b3d:	78 10                	js     b4f <__GNU_EH_FRAME_HDR+0x8f>
 b3f:	01 1b                	add    DWORD PTR [rbx],ebx
 b41:	0c 07                	or     al,0x7
 b43:	08 90 01 00 00 24    	or     BYTE PTR [rax+0x24000001],dl
 b49:	00 00                	add    BYTE PTR [rax],al
 b4b:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
 b4e:	00 00                	add    BYTE PTR [rax],al
 b50:	f0 fb                	lock sti 
 b52:	ff                   	(bad)  
 b53:	ff a0 00 00 00 00    	jmp    QWORD PTR [rax+0x0]
 b59:	0e                   	(bad)  
 b5a:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
 b5d:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
 b60:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
 b63:	80 00 3f             	add    BYTE PTR [rax],0x3f
 b66:	1a 3b                	sbb    bh,BYTE PTR [rbx]
 b68:	2a 33                	sub    dh,BYTE PTR [rbx]
 b6a:	24 22                	and    al,0x22
 b6c:	00 00                	add    BYTE PTR [rax],al
 b6e:	00 00                	add    BYTE PTR [rax],al
 b70:	14 00                	adc    al,0x0
 b72:	00 00                	add    BYTE PTR [rax],al
 b74:	44 00 00             	add    BYTE PTR [rax],r8b
 b77:	00 68 fc             	add    BYTE PTR [rax-0x4],ch
 b7a:	ff                   	(bad)  
 b7b:	ff 08                	dec    DWORD PTR [rax]
	...
 b85:	00 00                	add    BYTE PTR [rax],al
 b87:	00 24 00             	add    BYTE PTR [rax+rax*1],ah
 b8a:	00 00                	add    BYTE PTR [rax],al
 b8c:	5c                   	pop    rsp
 b8d:	00 00                	add    BYTE PTR [rax],al
 b8f:	00 6a fd             	add    BYTE PTR [rdx-0x3],ch
 b92:	ff                   	(bad)  
 b93:	ff                   	(bad)  
 b94:	fb                   	sti    
 b95:	00 00                	add    BYTE PTR [rax],al
 b97:	00 00                	add    BYTE PTR [rax],al
 b99:	41 0e                	rex.B (bad) 
 b9b:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
 ba1:	45 83 03 02          	rex.RB add DWORD PTR [r11],0x2
 ba5:	f1                   	icebp  
 ba6:	0c 07                	or     al,0x7
 ba8:	08 00                	or     BYTE PTR [rax],al
 baa:	00 00                	add    BYTE PTR [rax],al
 bac:	00 00                	add    BYTE PTR [rax],al
 bae:	00 00                	add    BYTE PTR [rax],al
 bb0:	44 00 00             	add    BYTE PTR [rax],r8b
 bb3:	00 84 00 00 00 48 fe 	add    BYTE PTR [rax+rax*1-0x1b80000],al
 bba:	ff                   	(bad)  
 bbb:	ff 65 00             	jmp    QWORD PTR [rbp+0x0]
 bbe:	00 00                	add    BYTE PTR [rax],al
 bc0:	00 42 0e             	add    BYTE PTR [rdx+0xe],al
 bc3:	10 8f 02 42 0e 18    	adc    BYTE PTR [rdi+0x180e4202],cl
 bc9:	8e 03                	mov    es,WORD PTR [rbx]
 bcb:	45 0e                	rex.RB (bad) 
 bcd:	20 8d 04 42 0e 28    	and    BYTE PTR [rbp+0x280e4204],cl
 bd3:	8c 05 48 0e 30 86    	mov    WORD PTR [rip+0xffffffff86300e48],es        # ffffffff86301a21 <_end+0xffffffff861009f1>
 bd9:	06                   	(bad)  
 bda:	48 0e                	rex.W (bad) 
 bdc:	38 83 07 4d 0e 40    	cmp    BYTE PTR [rbx+0x400e4d07],al
 be2:	72 0e                	jb     bf2 <__GNU_EH_FRAME_HDR+0x132>
 be4:	38 41 0e             	cmp    BYTE PTR [rcx+0xe],al
 be7:	30 41 0e             	xor    BYTE PTR [rcx+0xe],al
 bea:	28 42 0e             	sub    BYTE PTR [rdx+0xe],al
 bed:	20 42 0e             	and    BYTE PTR [rdx+0xe],al
 bf0:	18 42 0e             	sbb    BYTE PTR [rdx+0xe],al
 bf3:	10 42 0e             	adc    BYTE PTR [rdx+0xe],al
 bf6:	08 00                	or     BYTE PTR [rax],al
 bf8:	10 00                	adc    BYTE PTR [rax],al
 bfa:	00 00                	add    BYTE PTR [rax],al
 bfc:	cc                   	int3   
 bfd:	00 00                	add    BYTE PTR [rax],al
 bff:	00 70 fe             	add    BYTE PTR [rax-0x2],dh
 c02:	ff                   	(bad)  
 c03:	ff 02                	inc    DWORD PTR [rdx]
 c05:	00 00                	add    BYTE PTR [rax],al
 c07:	00 00                	add    BYTE PTR [rax],al
 c09:	00 00                	add    BYTE PTR [rax],al
	...

0000000000000c0c <__FRAME_END__>:
 c0c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init_array:

0000000000200d78 <__frame_dummy_init_array_entry>:
  200d78:	f0 08 00             	lock or BYTE PTR [rax],al
  200d7b:	00 00                	add    BYTE PTR [rax],al
  200d7d:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .fini_array:

0000000000200d80 <__do_global_dtors_aux_fini_array_entry>:
  200d80:	b0 08                	mov    al,0x8
  200d82:	00 00                	add    BYTE PTR [rax],al
  200d84:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynamic:

0000000000200d88 <_DYNAMIC>:
  200d88:	01 00                	add    DWORD PTR [rax],eax
  200d8a:	00 00                	add    BYTE PTR [rax],al
  200d8c:	00 00                	add    BYTE PTR [rax],al
  200d8e:	00 00                	add    BYTE PTR [rax],al
  200d90:	01 00                	add    DWORD PTR [rax],eax
  200d92:	00 00                	add    BYTE PTR [rax],al
  200d94:	00 00                	add    BYTE PTR [rax],al
  200d96:	00 00                	add    BYTE PTR [rax],al
  200d98:	0c 00                	or     al,0x0
  200d9a:	00 00                	add    BYTE PTR [rax],al
  200d9c:	00 00                	add    BYTE PTR [rax],al
  200d9e:	00 00                	add    BYTE PTR [rax],al
  200da0:	20 07                	and    BYTE PTR [rdi],al
  200da2:	00 00                	add    BYTE PTR [rax],al
  200da4:	00 00                	add    BYTE PTR [rax],al
  200da6:	00 00                	add    BYTE PTR [rax],al
  200da8:	0d 00 00 00 00       	or     eax,0x0
  200dad:	00 00                	add    BYTE PTR [rax],al
  200daf:	00 74 0a 00          	add    BYTE PTR [rdx+rcx*1+0x0],dh
  200db3:	00 00                	add    BYTE PTR [rax],al
  200db5:	00 00                	add    BYTE PTR [rax],al
  200db7:	00 19                	add    BYTE PTR [rcx],bl
  200db9:	00 00                	add    BYTE PTR [rax],al
  200dbb:	00 00                	add    BYTE PTR [rax],al
  200dbd:	00 00                	add    BYTE PTR [rax],al
  200dbf:	00 78 0d             	add    BYTE PTR [rax+0xd],bh
  200dc2:	20 00                	and    BYTE PTR [rax],al
  200dc4:	00 00                	add    BYTE PTR [rax],al
  200dc6:	00 00                	add    BYTE PTR [rax],al
  200dc8:	1b 00                	sbb    eax,DWORD PTR [rax]
  200dca:	00 00                	add    BYTE PTR [rax],al
  200dcc:	00 00                	add    BYTE PTR [rax],al
  200dce:	00 00                	add    BYTE PTR [rax],al
  200dd0:	08 00                	or     BYTE PTR [rax],al
  200dd2:	00 00                	add    BYTE PTR [rax],al
  200dd4:	00 00                	add    BYTE PTR [rax],al
  200dd6:	00 00                	add    BYTE PTR [rax],al
  200dd8:	1a 00                	sbb    al,BYTE PTR [rax]
  200dda:	00 00                	add    BYTE PTR [rax],al
  200ddc:	00 00                	add    BYTE PTR [rax],al
  200dde:	00 00                	add    BYTE PTR [rax],al
  200de0:	80 0d 20 00 00 00 00 	or     BYTE PTR [rip+0x20],0x0        # 200e07 <_DYNAMIC+0x7f>
  200de7:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
  200dea:	00 00                	add    BYTE PTR [rax],al
  200dec:	00 00                	add    BYTE PTR [rax],al
  200dee:	00 00                	add    BYTE PTR [rax],al
  200df0:	08 00                	or     BYTE PTR [rax],al
  200df2:	00 00                	add    BYTE PTR [rax],al
  200df4:	00 00                	add    BYTE PTR [rax],al
  200df6:	00 00                	add    BYTE PTR [rax],al
  200df8:	f5                   	cmc    
  200df9:	fe                   	(bad)  
  200dfa:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200dfd:	00 00                	add    BYTE PTR [rax],al
  200dff:	00 98 02 00 00 00    	add    BYTE PTR [rax+0x2],bl
  200e05:	00 00                	add    BYTE PTR [rax],al
  200e07:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 200e0d <_DYNAMIC+0x85>
  200e0d:	00 00                	add    BYTE PTR [rax],al
  200e0f:	00 58 04             	add    BYTE PTR [rax+0x4],bl
  200e12:	00 00                	add    BYTE PTR [rax],al
  200e14:	00 00                	add    BYTE PTR [rax],al
  200e16:	00 00                	add    BYTE PTR [rax],al
  200e18:	06                   	(bad)  
  200e19:	00 00                	add    BYTE PTR [rax],al
  200e1b:	00 00                	add    BYTE PTR [rax],al
  200e1d:	00 00                	add    BYTE PTR [rax],al
  200e1f:	00 c0                	add    al,al
  200e21:	02 00                	add    al,BYTE PTR [rax]
  200e23:	00 00                	add    BYTE PTR [rax],al
  200e25:	00 00                	add    BYTE PTR [rax],al
  200e27:	00 0a                	add    BYTE PTR [rdx],cl
  200e29:	00 00                	add    BYTE PTR [rax],al
  200e2b:	00 00                	add    BYTE PTR [rax],al
  200e2d:	00 00                	add    BYTE PTR [rax],al
  200e2f:	00 bd 00 00 00 00    	add    BYTE PTR [rbp+0x0],bh
  200e35:	00 00                	add    BYTE PTR [rax],al
  200e37:	00 0b                	add    BYTE PTR [rbx],cl
  200e39:	00 00                	add    BYTE PTR [rax],al
  200e3b:	00 00                	add    BYTE PTR [rax],al
  200e3d:	00 00                	add    BYTE PTR [rax],al
  200e3f:	00 18                	add    BYTE PTR [rax],bl
  200e41:	00 00                	add    BYTE PTR [rax],al
  200e43:	00 00                	add    BYTE PTR [rax],al
  200e45:	00 00                	add    BYTE PTR [rax],al
  200e47:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 200e4d <_DYNAMIC+0xc5>
	...
  200e55:	00 00                	add    BYTE PTR [rax],al
  200e57:	00 03                	add    BYTE PTR [rbx],al
  200e59:	00 00                	add    BYTE PTR [rax],al
  200e5b:	00 00                	add    BYTE PTR [rax],al
  200e5d:	00 00                	add    BYTE PTR [rax],al
  200e5f:	00 78 0f             	add    BYTE PTR [rax+0xf],bh
  200e62:	20 00                	and    BYTE PTR [rax],al
  200e64:	00 00                	add    BYTE PTR [rax],al
  200e66:	00 00                	add    BYTE PTR [rax],al
  200e68:	02 00                	add    al,BYTE PTR [rax]
  200e6a:	00 00                	add    BYTE PTR [rax],al
  200e6c:	00 00                	add    BYTE PTR [rax],al
  200e6e:	00 00                	add    BYTE PTR [rax],al
  200e70:	d8 00                	fadd   DWORD PTR [rax]
  200e72:	00 00                	add    BYTE PTR [rax],al
  200e74:	00 00                	add    BYTE PTR [rax],al
  200e76:	00 00                	add    BYTE PTR [rax],al
  200e78:	14 00                	adc    al,0x0
  200e7a:	00 00                	add    BYTE PTR [rax],al
  200e7c:	00 00                	add    BYTE PTR [rax],al
  200e7e:	00 00                	add    BYTE PTR [rax],al
  200e80:	07                   	(bad)  
  200e81:	00 00                	add    BYTE PTR [rax],al
  200e83:	00 00                	add    BYTE PTR [rax],al
  200e85:	00 00                	add    BYTE PTR [rax],al
  200e87:	00 17                	add    BYTE PTR [rdi],dl
  200e89:	00 00                	add    BYTE PTR [rax],al
  200e8b:	00 00                	add    BYTE PTR [rax],al
  200e8d:	00 00                	add    BYTE PTR [rax],al
  200e8f:	00 48 06             	add    BYTE PTR [rax+0x6],cl
  200e92:	00 00                	add    BYTE PTR [rax],al
  200e94:	00 00                	add    BYTE PTR [rax],al
  200e96:	00 00                	add    BYTE PTR [rax],al
  200e98:	07                   	(bad)  
  200e99:	00 00                	add    BYTE PTR [rax],al
  200e9b:	00 00                	add    BYTE PTR [rax],al
  200e9d:	00 00                	add    BYTE PTR [rax],al
  200e9f:	00 58 05             	add    BYTE PTR [rax+0x5],bl
  200ea2:	00 00                	add    BYTE PTR [rax],al
  200ea4:	00 00                	add    BYTE PTR [rax],al
  200ea6:	00 00                	add    BYTE PTR [rax],al
  200ea8:	08 00                	or     BYTE PTR [rax],al
  200eaa:	00 00                	add    BYTE PTR [rax],al
  200eac:	00 00                	add    BYTE PTR [rax],al
  200eae:	00 00                	add    BYTE PTR [rax],al
  200eb0:	f0 00 00             	lock add BYTE PTR [rax],al
  200eb3:	00 00                	add    BYTE PTR [rax],al
  200eb5:	00 00                	add    BYTE PTR [rax],al
  200eb7:	00 09                	add    BYTE PTR [rcx],cl
  200eb9:	00 00                	add    BYTE PTR [rax],al
  200ebb:	00 00                	add    BYTE PTR [rax],al
  200ebd:	00 00                	add    BYTE PTR [rax],al
  200ebf:	00 18                	add    BYTE PTR [rax],bl
  200ec1:	00 00                	add    BYTE PTR [rax],al
  200ec3:	00 00                	add    BYTE PTR [rax],al
  200ec5:	00 00                	add    BYTE PTR [rax],al
  200ec7:	00 1e                	add    BYTE PTR [rsi],bl
  200ec9:	00 00                	add    BYTE PTR [rax],al
  200ecb:	00 00                	add    BYTE PTR [rax],al
  200ecd:	00 00                	add    BYTE PTR [rax],al
  200ecf:	00 08                	add    BYTE PTR [rax],cl
  200ed1:	00 00                	add    BYTE PTR [rax],al
  200ed3:	00 00                	add    BYTE PTR [rax],al
  200ed5:	00 00                	add    BYTE PTR [rax],al
  200ed7:	00 fb                	add    bl,bh
  200ed9:	ff                   	(bad)  
  200eda:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200edd:	00 00                	add    BYTE PTR [rax],al
  200edf:	00 01                	add    BYTE PTR [rcx],al
  200ee1:	00 00                	add    BYTE PTR [rax],al
  200ee3:	08 00                	or     BYTE PTR [rax],al
  200ee5:	00 00                	add    BYTE PTR [rax],al
  200ee7:	00 fe                	add    dh,bh
  200ee9:	ff                   	(bad)  
  200eea:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200eed:	00 00                	add    BYTE PTR [rax],al
  200eef:	00 38                	add    BYTE PTR [rax],bh
  200ef1:	05 00 00 00 00       	add    eax,0x0
  200ef6:	00 00                	add    BYTE PTR [rax],al
  200ef8:	ff                   	(bad)  
  200ef9:	ff                   	(bad)  
  200efa:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200efd:	00 00                	add    BYTE PTR [rax],al
  200eff:	00 01                	add    BYTE PTR [rcx],al
  200f01:	00 00                	add    BYTE PTR [rax],al
  200f03:	00 00                	add    BYTE PTR [rax],al
  200f05:	00 00                	add    BYTE PTR [rax],al
  200f07:	00 f0                	add    al,dh
  200f09:	ff                   	(bad)  
  200f0a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200f0d:	00 00                	add    BYTE PTR [rax],al
  200f0f:	00 16                	add    BYTE PTR [rsi],dl
  200f11:	05 00 00 00 00       	add    eax,0x0
  200f16:	00 00                	add    BYTE PTR [rax],al
  200f18:	f9                   	stc    
  200f19:	ff                   	(bad)  
  200f1a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200f1d:	00 00                	add    BYTE PTR [rax],al
  200f1f:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .got:

0000000000200f78 <_GLOBAL_OFFSET_TABLE_>:
  200f78:	88 0d 20 00 00 00    	mov    BYTE PTR [rip+0x20],cl        # 200f9e <_GLOBAL_OFFSET_TABLE_+0x26>
	...
  200f8e:	00 00                	add    BYTE PTR [rax],al
  200f90:	56                   	push   rsi
  200f91:	07                   	(bad)  
  200f92:	00 00                	add    BYTE PTR [rax],al
  200f94:	00 00                	add    BYTE PTR [rax],al
  200f96:	00 00                	add    BYTE PTR [rax],al
  200f98:	66 07                	data16 (bad) 
  200f9a:	00 00                	add    BYTE PTR [rax],al
  200f9c:	00 00                	add    BYTE PTR [rax],al
  200f9e:	00 00                	add    BYTE PTR [rax],al
  200fa0:	76 07                	jbe    200fa9 <_GLOBAL_OFFSET_TABLE_+0x31>
  200fa2:	00 00                	add    BYTE PTR [rax],al
  200fa4:	00 00                	add    BYTE PTR [rax],al
  200fa6:	00 00                	add    BYTE PTR [rax],al
  200fa8:	86 07                	xchg   BYTE PTR [rdi],al
  200faa:	00 00                	add    BYTE PTR [rax],al
  200fac:	00 00                	add    BYTE PTR [rax],al
  200fae:	00 00                	add    BYTE PTR [rax],al
  200fb0:	96                   	xchg   esi,eax
  200fb1:	07                   	(bad)  
  200fb2:	00 00                	add    BYTE PTR [rax],al
  200fb4:	00 00                	add    BYTE PTR [rax],al
  200fb6:	00 00                	add    BYTE PTR [rax],al
  200fb8:	a6                   	cmps   BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
  200fb9:	07                   	(bad)  
  200fba:	00 00                	add    BYTE PTR [rax],al
  200fbc:	00 00                	add    BYTE PTR [rax],al
  200fbe:	00 00                	add    BYTE PTR [rax],al
  200fc0:	b6 07                	mov    dh,0x7
  200fc2:	00 00                	add    BYTE PTR [rax],al
  200fc4:	00 00                	add    BYTE PTR [rax],al
  200fc6:	00 00                	add    BYTE PTR [rax],al
  200fc8:	c6 07 00             	mov    BYTE PTR [rdi],0x0
  200fcb:	00 00                	add    BYTE PTR [rax],al
  200fcd:	00 00                	add    BYTE PTR [rax],al
  200fcf:	00 d6                	add    dh,dl
  200fd1:	07                   	(bad)  
	...

Disassembly of section .data:

0000000000201000 <__data_start>:
	...

0000000000201008 <__dso_handle>:
  201008:	08 10                	or     BYTE PTR [rax],dl
  20100a:	20 00                	and    BYTE PTR [rax],al
  20100c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .bss:

0000000000201010 <stdout@@GLIBC_2.2.5>:
	...

0000000000201020 <stdin@@GLIBC_2.2.5>:
	...

0000000000201028 <completed.7698>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp spl,BYTE PTR [r8]
   5:	28 55 62             	sub    BYTE PTR [rbp+0x62],dl
   8:	75 6e                	jne    78 <_init-0x6a8>
   a:	74 75                	je     81 <_init-0x69f>
   c:	20 37                	and    BYTE PTR [rdi],dh
   e:	2e 35 2e 30 2d 33    	cs xor eax,0x332d302e
  14:	75 62                	jne    78 <_init-0x6a8>
  16:	75 6e                	jne    86 <_init-0x69a>
  18:	74 75                	je     8f <_init-0x691>
  1a:	31 7e 31             	xor    DWORD PTR [rsi+0x31],edi
  1d:	38 2e                	cmp    BYTE PTR [rsi],ch
  1f:	30 34 29             	xor    BYTE PTR [rcx+rbp*1],dh
  22:	20 37                	and    BYTE PTR [rdi],dh
  24:	2e                   	cs
  25:	35                   	.byte 0x35
  26:	2e 30 00             	xor    BYTE PTR cs:[rax],al

Disassembly of section .debug_aranges:

0000000000000000 <.debug_aranges>:
   0:	2c 00                	sub    al,0x0
   2:	00 00                	add    BYTE PTR [rax],al
   4:	02 00                	add    al,BYTE PTR [rax]
   6:	00 00                	add    BYTE PTR [rax],al
   8:	00 00                	add    BYTE PTR [rax],al
   a:	08 00                	or     BYTE PTR [rax],al
   c:	00 00                	add    BYTE PTR [rax],al
   e:	00 00                	add    BYTE PTR [rax],al
  10:	fa                   	cli    
  11:	08 00                	or     BYTE PTR [rax],al
  13:	00 00                	add    BYTE PTR [rax],al
  15:	00 00                	add    BYTE PTR [rax],al
  17:	00 fb                	add    bl,bh
	...

Disassembly of section .debug_info:

0000000000000000 <.debug_info>:
   0:	02 04 00             	add    al,BYTE PTR [rax+rax*1]
   3:	00 04 00             	add    BYTE PTR [rax+rax*1],al
   6:	00 00                	add    BYTE PTR [rax],al
   8:	00 00                	add    BYTE PTR [rax],al
   a:	08 01                	or     BYTE PTR [rcx],al
   c:	5f                   	pop    rdi
   d:	02 00                	add    al,BYTE PTR [rax]
   f:	00 0c d0             	add    BYTE PTR [rax+rdx*8],cl
  12:	02 00                	add    al,BYTE PTR [rax]
  14:	00 e1                	add    cl,ah
  16:	01 00                	add    DWORD PTR [rax],eax
  18:	00 fa                	add    dl,bh
  1a:	08 00                	or     BYTE PTR [rax],al
  1c:	00 00                	add    BYTE PTR [rax],al
  1e:	00 00                	add    BYTE PTR [rax],al
  20:	00 fb                	add    bl,bh
	...
  2a:	00 00                	add    BYTE PTR [rax],al
  2c:	00 02                	add    BYTE PTR [rdx],al
  2e:	37                   	(bad)  
  2f:	00 00                	add    BYTE PTR [rax],al
  31:	00 02                	add    BYTE PTR [rdx],al
  33:	d8 38                	fdivr  DWORD PTR [rax]
  35:	00 00                	add    BYTE PTR [rax],al
  37:	00 03                	add    BYTE PTR [rbx],al
  39:	08 07                	or     BYTE PTR [rdi],al
  3b:	20 01                	and    BYTE PTR [rcx],al
  3d:	00 00                	add    BYTE PTR [rax],al
  3f:	03 01                	add    eax,DWORD PTR [rcx]
  41:	08 0d 01 00 00 03    	or     BYTE PTR [rip+0x3000001],cl        # 3000048 <_end+0x2dff018>
  47:	02 07                	add    al,BYTE PTR [rdi]
  49:	a7                   	cmps   DWORD PTR ds:[rsi],DWORD PTR es:[rdi]
  4a:	01 00                	add    DWORD PTR [rax],eax
  4c:	00 03                	add    BYTE PTR [rbx],al
  4e:	04 07                	add    al,0x7
  50:	25 01 00 00 03       	and    eax,0x3000001
  55:	01 06                	add    DWORD PTR [rsi],eax
  57:	0f 01 00             	sgdt   [rax]
  5a:	00 03                	add    BYTE PTR [rbx],al
  5c:	02 05 2d 00 00 00    	add    al,BYTE PTR [rip+0x2d]        # 8f <_init-0x691>
  62:	04 04                	add    al,0x4
  64:	05 69 6e 74 00       	add    eax,0x746e69
  69:	03 08                	add    ecx,DWORD PTR [rax]
  6b:	05 98 00 00 00       	add    eax,0x98
  70:	02 09                	add    cl,BYTE PTR [rcx]
  72:	02 00                	add    al,BYTE PTR [rax]
  74:	00 03                	add    BYTE PTR [rbx],al
  76:	8c 69 00             	mov    WORD PTR [rcx+0x0],gs
  79:	00 00                	add    BYTE PTR [rax],al
  7b:	02 c8                	add    cl,al
  7d:	01 00                	add    DWORD PTR [rax],eax
  7f:	00 03                	add    BYTE PTR [rbx],al
  81:	8d 69 00             	lea    ebp,[rcx+0x0]
  84:	00 00                	add    BYTE PTR [rax],al
  86:	05 08 06 08 8e       	add    eax,0x8e080608
  8b:	00 00                	add    BYTE PTR [rax],al
  8d:	00 03                	add    BYTE PTR [rbx],al
  8f:	01 06                	add    DWORD PTR [rsi],eax
  91:	16                   	(bad)  
  92:	01 00                	add    DWORD PTR [rax],eax
  94:	00 07                	add    BYTE PTR [rdi],al
  96:	8e 00                	mov    es,WORD PTR [rax]
  98:	00 00                	add    BYTE PTR [rax],al
  9a:	08 0e                	or     BYTE PTR [rsi],cl
  9c:	00 00                	add    BYTE PTR [rax],al
  9e:	00 d8                	add    al,bl
  a0:	04 f5                	add    al,0xf5
  a2:	1a 02                	sbb    al,BYTE PTR [rdx]
  a4:	00 00                	add    BYTE PTR [rax],al
  a6:	09 55 00             	or     DWORD PTR [rbp+0x0],edx
  a9:	00 00                	add    BYTE PTR [rax],al
  ab:	04 f6                	add    al,0xf6
  ad:	62                   	(bad)  
  ae:	00 00                	add    BYTE PTR [rax],al
  b0:	00 00                	add    BYTE PTR [rax],al
  b2:	09 c3                	or     ebx,eax
  b4:	02 00                	add    al,BYTE PTR [rax]
  b6:	00 04 fb             	add    BYTE PTR [rbx+rdi*8],al
  b9:	88 00                	mov    BYTE PTR [rax],al
  bb:	00 00                	add    BYTE PTR [rax],al
  bd:	08 09                	or     BYTE PTR [rcx],cl
  bf:	7f 00                	jg     c1 <_init-0x65f>
  c1:	00 00                	add    BYTE PTR [rax],al
  c3:	04 fc                	add    al,0xfc
  c5:	88 00                	mov    BYTE PTR [rax],al
  c7:	00 00                	add    BYTE PTR [rax],al
  c9:	10 09                	adc    BYTE PTR [rcx],cl
  cb:	42 02 00             	rex.X add al,BYTE PTR [rax]
  ce:	00 04 fd 88 00 00 00 	add    BYTE PTR [rdi*8+0x88],al
  d5:	18 09                	sbb    BYTE PTR [rcx],cl
  d7:	ec                   	in     al,dx
  d8:	00 00                	add    BYTE PTR [rax],al
  da:	00 04 fe             	add    BYTE PTR [rsi+rdi*8],al
  dd:	88 00                	mov    BYTE PTR [rax],al
  df:	00 00                	add    BYTE PTR [rax],al
  e1:	20 09                	and    BYTE PTR [rcx],cl
  e3:	47 00 00             	rex.RXB add BYTE PTR [r8],r8b
  e6:	00 04 ff             	add    BYTE PTR [rdi+rdi*8],al
  e9:	88 00                	mov    BYTE PTR [rax],al
  eb:	00 00                	add    BYTE PTR [rax],al
  ed:	28 0a                	sub    BYTE PTR [rdx],cl
  ef:	ba 01 00 00 04       	mov    edx,0x4000001
  f4:	00 01                	add    BYTE PTR [rcx],al
  f6:	88 00                	mov    BYTE PTR [rax],al
  f8:	00 00                	add    BYTE PTR [rax],al
  fa:	30 0a                	xor    BYTE PTR [rdx],cl
  fc:	27                   	(bad)  
  fd:	02 00                	add    al,BYTE PTR [rax]
  ff:	00 04 01             	add    BYTE PTR [rcx+rax*1],al
 102:	01 88 00 00 00 38    	add    DWORD PTR [rax+0x38000000],ecx
 108:	0a 6d 01             	or     ch,BYTE PTR [rbp+0x1]
 10b:	00 00                	add    BYTE PTR [rax],al
 10d:	04 02                	add    al,0x2
 10f:	01 88 00 00 00 40    	add    DWORD PTR [rax+0x40000000],ecx
 115:	0a a2 02 00 00 04    	or     ah,BYTE PTR [rdx+0x4000002]
 11b:	04 01                	add    al,0x1
 11d:	88 00                	mov    BYTE PTR [rax],al
 11f:	00 00                	add    BYTE PTR [rax],al
 121:	48 0a 11             	rex.W or dl,BYTE PTR [rcx]
 124:	02 00                	add    al,BYTE PTR [rax]
 126:	00 04 05 01 88 00 00 	add    BYTE PTR [rax*1+0x8801],al
 12d:	00 50 0a             	add    BYTE PTR [rax+0xa],dl
 130:	20 00                	and    BYTE PTR [rax],al
 132:	00 00                	add    BYTE PTR [rax],al
 134:	04 06                	add    al,0x6
 136:	01 88 00 00 00 58    	add    DWORD PTR [rax+0x58000000],ecx
 13c:	0a 76 00             	or     dh,BYTE PTR [rsi+0x0]
 13f:	00 00                	add    BYTE PTR [rax],al
 141:	04 08                	add    al,0x8
 143:	01 52 02             	add    DWORD PTR [rdx+0x2],edx
 146:	00 00                	add    BYTE PTR [rax],al
 148:	60                   	(bad)  
 149:	0a da                	or     bl,dl
 14b:	01 00                	add    DWORD PTR [rax],eax
 14d:	00 04 0a             	add    BYTE PTR [rdx+rcx*1],al
 150:	01 58 02             	add    DWORD PTR [rax+0x2],ebx
 153:	00 00                	add    BYTE PTR [rax],al
 155:	68 0a d2 01 00       	push   0x1d20a
 15a:	00 04 0c             	add    BYTE PTR [rsp+rcx*1],al
 15d:	01 62 00             	add    DWORD PTR [rdx+0x0],esp
 160:	00 00                	add    BYTE PTR [rax],al
 162:	70 0a                	jo     16e <_init-0x5b2>
 164:	34 02                	xor    al,0x2
 166:	00 00                	add    BYTE PTR [rax],al
 168:	04 10                	add    al,0x10
 16a:	01 62 00             	add    DWORD PTR [rdx+0x0],esp
 16d:	00 00                	add    BYTE PTR [rax],al
 16f:	74 0a                	je     17b <_init-0x5a5>
 171:	01 01                	add    DWORD PTR [rcx],eax
 173:	00 00                	add    BYTE PTR [rax],al
 175:	04 12                	add    al,0x12
 177:	01 70 00             	add    DWORD PTR [rax+0x0],esi
 17a:	00 00                	add    BYTE PTR [rax],al
 17c:	78 0a                	js     188 <_init-0x598>
 17e:	bd 00 00 00 04       	mov    ebp,0x4000000
 183:	16                   	(bad)  
 184:	01 46 00             	add    DWORD PTR [rsi+0x0],eax
 187:	00 00                	add    BYTE PTR [rax],al
 189:	80 0a 50             	or     BYTE PTR [rdx],0x50
 18c:	02 00                	add    al,BYTE PTR [rax]
 18e:	00 04 17             	add    BYTE PTR [rdi+rdx*1],al
 191:	01 54 00 00          	add    DWORD PTR [rax+rax*1+0x0],edx
 195:	00 82 0a 4c 01 00    	add    BYTE PTR [rdx+0x14c0a],al
 19b:	00 04 18             	add    BYTE PTR [rax+rbx*1],al
 19e:	01 5e 02             	add    DWORD PTR [rsi+0x2],ebx
 1a1:	00 00                	add    BYTE PTR [rax],al
 1a3:	83 0a ac             	or     DWORD PTR [rdx],0xffffffac
 1a6:	00 00                	add    BYTE PTR [rax],al
 1a8:	00 04 1c             	add    BYTE PTR [rsp+rbx*1],al
 1ab:	01 6e 02             	add    DWORD PTR [rsi+0x2],ebp
 1ae:	00 00                	add    BYTE PTR [rax],al
 1b0:	88 0a                	mov    BYTE PTR [rdx],cl
 1b2:	05 01 00 00 04       	add    eax,0x4000001
 1b7:	25 01 7b 00 00       	and    eax,0x7b01
 1bc:	00 90 0a 56 01 00    	add    BYTE PTR [rax+0x1560a],dl
 1c2:	00 04 2d 01 86 00 00 	add    BYTE PTR [rbp*1+0x8601],al
 1c9:	00 98 0a 8b 01 00    	add    BYTE PTR [rax+0x18b0a],bl
 1cf:	00 04 2e             	add    BYTE PTR [rsi+rbp*1],al
 1d2:	01 86 00 00 00 a0    	add    DWORD PTR [rsi-0x60000000],eax
 1d8:	0a 92 01 00 00 04    	or     dl,BYTE PTR [rdx+0x4000001]
 1de:	2f                   	(bad)  
 1df:	01 86 00 00 00 a8    	add    DWORD PTR [rsi-0x58000000],eax
 1e5:	0a 99 01 00 00 04    	or     bl,BYTE PTR [rcx+0x4000001]
 1eb:	30 01                	xor    BYTE PTR [rcx],al
 1ed:	86 00                	xchg   BYTE PTR [rax],al
 1ef:	00 00                	add    BYTE PTR [rax],al
 1f1:	b0 0a                	mov    al,0xa
 1f3:	a0 01 00 00 04 32 01 	movabs al,ds:0x2d013204000001
 1fa:	2d 00 
 1fc:	00 00                	add    BYTE PTR [rax],al
 1fe:	b8 0a 3c 02 00       	mov    eax,0x23c0a
 203:	00 04 33             	add    BYTE PTR [rbx+rsi*1],al
 206:	01 62 00             	add    DWORD PTR [rdx+0x0],esp
 209:	00 00                	add    BYTE PTR [rax],al
 20b:	c0 0a 5d             	ror    BYTE PTR [rdx],0x5d
 20e:	01 00                	add    DWORD PTR [rax],eax
 210:	00 04 35 01 74 02 00 	add    BYTE PTR [rsi*1+0x27401],al
 217:	00 c4                	add    ah,al
 219:	00 0b                	add    BYTE PTR [rbx],cl
 21b:	df 02                	fild   WORD PTR [rdx]
 21d:	00 00                	add    BYTE PTR [rax],al
 21f:	04 9a                	add    al,0x9a
 221:	08 41 01             	or     BYTE PTR [rcx+0x1],al
 224:	00 00                	add    BYTE PTR [rax],al
 226:	18 04 a0             	sbb    BYTE PTR [rax+riz*4],al
 229:	52                   	push   rdx
 22a:	02 00                	add    al,BYTE PTR [rax]
 22c:	00 09                	add    BYTE PTR [rcx],cl
 22e:	7e 01                	jle    231 <_init-0x4ef>
 230:	00 00                	add    BYTE PTR [rax],al
 232:	04 a1                	add    al,0xa1
 234:	52                   	push   rdx
 235:	02 00                	add    al,BYTE PTR [rax]
 237:	00 00                	add    BYTE PTR [rax],al
 239:	09 fb                	or     ebx,edi
 23b:	00 00                	add    BYTE PTR [rax],al
 23d:	00 04 a2             	add    BYTE PTR [rdx+riz*4],al
 240:	58                   	pop    rax
 241:	02 00                	add    al,BYTE PTR [rax]
 243:	00 08                	add    BYTE PTR [rax],cl
 245:	09 e7                	or     edi,esp
 247:	00 00                	add    BYTE PTR [rax],al
 249:	00 04 a6             	add    BYTE PTR [rsi+riz*4],al
 24c:	62                   	(bad)  
 24d:	00 00                	add    BYTE PTR [rax],al
 24f:	00 10                	add    BYTE PTR [rax],dl
 251:	00 06                	add    BYTE PTR [rsi],al
 253:	08 21                	or     BYTE PTR [rcx],ah
 255:	02 00                	add    al,BYTE PTR [rax]
 257:	00 06                	add    BYTE PTR [rsi],al
 259:	08 9a 00 00 00 0c    	or     BYTE PTR [rdx+0xc000000],bl
 25f:	8e 00                	mov    es,WORD PTR [rax]
 261:	00 00                	add    BYTE PTR [rax],al
 263:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 264:	02 00                	add    al,BYTE PTR [rax]
 266:	00 0d 38 00 00 00    	add    BYTE PTR [rip+0x38],cl        # 2a4 <_init-0x47c>
 26c:	00 00                	add    BYTE PTR [rax],al
 26e:	06                   	(bad)  
 26f:	08 1a                	or     BYTE PTR [rdx],bl
 271:	02 00                	add    al,BYTE PTR [rax]
 273:	00 0c 8e             	add    BYTE PTR [rsi+rcx*4],cl
 276:	00 00                	add    BYTE PTR [rax],al
 278:	00 84 02 00 00 0d 38 	add    BYTE PTR [rdx+rax*1+0x380d0000],al
 27f:	00 00                	add    BYTE PTR [rax],al
 281:	00 13                	add    BYTE PTR [rbx],dl
 283:	00 0e                	add    BYTE PTR [rsi],cl
 285:	d9 00                	fld    DWORD PTR [rax]
 287:	00 00                	add    BYTE PTR [rax],al
 289:	0f 32                	rdmsr  
 28b:	01 00                	add    DWORD PTR [rax],eax
 28d:	00 04 3f             	add    BYTE PTR [rdi+rdi*1],al
 290:	01 84 02 00 00 0f 5c 	add    DWORD PTR [rdx+rax*1+0x5c0f0000],eax
 297:	00 00                	add    BYTE PTR [rax],al
 299:	00 04 40             	add    BYTE PTR [rax+rax*2],al
 29c:	01 84 02 00 00 0f c9 	add    DWORD PTR [rdx+rax*1-0x36f10000],eax
 2a3:	00 00                	add    BYTE PTR [rax],al
 2a5:	00 04 41             	add    BYTE PTR [rcx+rax*2],al
 2a8:	01 84 02 00 00 06 08 	add    DWORD PTR [rdx+rax*1+0x8060000],eax
 2af:	95                   	xchg   ebp,eax
 2b0:	00 00                	add    BYTE PTR [rax],al
 2b2:	00 07                	add    BYTE PTR [rdi],al
 2b4:	ad                   	lods   eax,DWORD PTR ds:[rsi]
 2b5:	02 00                	add    al,BYTE PTR [rax]
 2b7:	00 10                	add    BYTE PTR [rax],dl
 2b9:	21 02                	and    DWORD PTR [rdx],eax
 2bb:	00 00                	add    BYTE PTR [rax],al
 2bd:	05 87 58 02 00       	add    eax,0x25887
 2c2:	00 10                	add    BYTE PTR [rax],dl
 2c4:	d8 02                	fadd   DWORD PTR [rdx]
 2c6:	00 00                	add    BYTE PTR [rax],al
 2c8:	05 88 58 02 00       	add    eax,0x25888
 2cd:	00 10                	add    BYTE PTR [rax],dl
 2cf:	8c 00                	mov    WORD PTR [rax],es
 2d1:	00 00                	add    BYTE PTR [rax],al
 2d3:	05 89 58 02 00       	add    eax,0x25889
 2d8:	00 10                	add    BYTE PTR [rax],dl
 2da:	17                   	(bad)  
 2db:	00 00                	add    BYTE PTR [rax],al
 2dd:	00 06                	add    BYTE PTR [rsi],al
 2df:	1a 62 00             	sbb    ah,BYTE PTR [rdx+0x0]
 2e2:	00 00                	add    BYTE PTR [rax],al
 2e4:	0c b3                	or     al,0xb3
 2e6:	02 00                	add    al,BYTE PTR [rax]
 2e8:	00 ef                	add    bh,ch
 2ea:	02 00                	add    al,BYTE PTR [rax]
 2ec:	00 11                	add    BYTE PTR [rcx],dl
 2ee:	00 07                	add    BYTE PTR [rdi],al
 2f0:	e4 02                	in     al,0x2
 2f2:	00 00                	add    BYTE PTR [rax],al
 2f4:	10 b0 02 00 00 06    	adc    BYTE PTR [rax+0x6000002],dh
 2fa:	1b ef                	sbb    ebp,edi
 2fc:	02 00                	add    al,BYTE PTR [rax]
 2fe:	00 03                	add    BYTE PTR [rbx],al
 300:	08 05 93 00 00 00    	or     BYTE PTR [rip+0x93],al        # 399 <_init-0x387>
 306:	03 08                	add    ecx,DWORD PTR [rax]
 308:	07                   	(bad)  
 309:	1b 01                	sbb    eax,DWORD PTR [rcx]
 30b:	00 00                	add    BYTE PTR [rax],al
 30d:	0c 88                	or     al,0x88
 30f:	00 00                	add    BYTE PTR [rax],al
 311:	00 1d 03 00 00 0d    	add    BYTE PTR [rip+0xd000003],bl        # d00031a <_end+0xcdff2ea>
 317:	38 00                	cmp    BYTE PTR [rax],al
 319:	00 00                	add    BYTE PTR [rax],al
 31b:	01 00                	add    DWORD PTR [rax],eax
 31d:	10 3e                	adc    BYTE PTR [rsi],bh
 31f:	00 00                	add    BYTE PTR [rax],al
 321:	00 07                	add    BYTE PTR [rdi],al
 323:	9f                   	lahf   
 324:	0d 03 00 00 10       	or     eax,0x10000003
 329:	b2 00                	mov    dl,0x0
 32b:	00 00                	add    BYTE PTR [rax],al
 32d:	07                   	(bad)  
 32e:	a0 62 00 00 00 10 a1 	movabs al,ds:0xa11000000062
 335:	00 00 
 337:	00 07                	add    BYTE PTR [rdi],al
 339:	a1 69 00 00 00 10 40 	movabs eax,ds:0x401000000069
 340:	00 00 
 342:	00 07                	add    BYTE PTR [rdi],al
 344:	a6                   	cmps   BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
 345:	0d 03 00 00 10       	or     eax,0x10000003
 34a:	b4 00                	mov    ah,0x0
 34c:	00 00                	add    BYTE PTR [rax],al
 34e:	07                   	(bad)  
 34f:	ae                   	scas   al,BYTE PTR es:[rdi]
 350:	62                   	(bad)  
 351:	00 00                	add    BYTE PTR [rax],al
 353:	00 10                	add    BYTE PTR [rax],dl
 355:	a3 00 00 00 07 af 69 	movabs ds:0x69af07000000,eax
 35c:	00 00 
 35e:	00 0f                	add    BYTE PTR [rdi],cl
 360:	6c                   	ins    BYTE PTR es:[rdi],dx
 361:	00 00                	add    BYTE PTR [rax],al
 363:	00 08                	add    BYTE PTR [rax],cl
 365:	22 02                	and    al,BYTE PTR [rdx]
 367:	6b 03 00             	imul   eax,DWORD PTR [rbx],0x0
 36a:	00 06                	add    BYTE PTR [rsi],al
 36c:	08 88 00 00 00 10    	or     BYTE PTR [rax+0x10000000],cl
 372:	07                   	(bad)  
 373:	00 00                	add    BYTE PTR [rax],al
 375:	00 09                	add    BYTE PTR [rcx],cl
 377:	24 88                	and    al,0x88
 379:	00 00                	add    BYTE PTR [rax],al
 37b:	00 10                	add    BYTE PTR [rax],dl
 37d:	00 00                	add    BYTE PTR [rax],al
 37f:	00 00                	add    BYTE PTR [rax],al
 381:	09 32                	or     DWORD PTR [rdx],esi
 383:	62                   	(bad)  
 384:	00 00                	add    BYTE PTR [rax],al
 386:	00 10                	add    BYTE PTR [rax],dl
 388:	66 01 00             	add    WORD PTR [rax],ax
 38b:	00 09                	add    BYTE PTR [rcx],cl
 38d:	37                   	(bad)  
 38e:	62                   	(bad)  
 38f:	00 00                	add    BYTE PTR [rax],al
 391:	00 10                	add    BYTE PTR [rax],dl
 393:	bc 02 00 00 09       	mov    esp,0x9000002
 398:	3b 62 00             	cmp    esp,DWORD PTR [rdx+0x0]
 39b:	00 00                	add    BYTE PTR [rax],al
 39d:	12 79 01             	adc    bh,BYTE PTR [rcx+0x1]
 3a0:	00 00                	add    BYTE PTR [rax],al
 3a2:	01 07                	add    DWORD PTR [rdi],eax
 3a4:	62                   	(bad)  
 3a5:	00 00                	add    BYTE PTR [rax],al
 3a7:	00 fa                	add    dl,bh
 3a9:	08 00                	or     BYTE PTR [rax],al
 3ab:	00 00                	add    BYTE PTR [rax],al
 3ad:	00 00                	add    BYTE PTR [rax],al
 3af:	00 fb                	add    bl,bh
 3b1:	00 00                	add    BYTE PTR [rax],al
 3b3:	00 00                	add    BYTE PTR [rax],al
 3b5:	00 00                	add    BYTE PTR [rax],al
 3b7:	00 01                	add    BYTE PTR [rcx],al
 3b9:	9c                   	pushf  
 3ba:	f9                   	stc    
 3bb:	03 00                	add    eax,DWORD PTR [rax]
 3bd:	00 13                	add    BYTE PTR [rbx],dl
 3bf:	62                   	(bad)  
 3c0:	75 66                	jne    428 <_init-0x2f8>
 3c2:	00 01                	add    BYTE PTR [rcx],al
 3c4:	08 f9                	or     cl,bh
 3c6:	03 00                	add    eax,DWORD PTR [rax]
 3c8:	00 02                	add    BYTE PTR [rdx],al
 3ca:	91                   	xchg   ecx,eax
 3cb:	40 14 84             	adc    al,0x84
 3ce:	01 00                	add    DWORD PTR [rax],eax
 3d0:	00 01                	add    BYTE PTR [rcx],al
 3d2:	09 62 00             	or     DWORD PTR [rdx+0x0],esp
 3d5:	00 00                	add    BYTE PTR [rax],al
 3d7:	02 91 5c 15 98 09    	add    dl,BYTE PTR [rcx+0x998155c]
 3dd:	00 00                	add    BYTE PTR [rax],al
 3df:	00 00                	add    BYTE PTR [rax],al
 3e1:	00 00                	add    BYTE PTR [rax],al
 3e3:	51                   	push   rcx
 3e4:	00 00                	add    BYTE PTR [rax],al
 3e6:	00 00                	add    BYTE PTR [rax],al
 3e8:	00 00                	add    BYTE PTR [rax],al
 3ea:	00 13                	add    BYTE PTR [rbx],dl
 3ec:	67 00 01             	add    BYTE PTR [ecx],al
 3ef:	11 62 00             	adc    DWORD PTR [rdx+0x0],esp
 3f2:	00 00                	add    BYTE PTR [rax],al
 3f4:	02 91 58 00 00 16    	add    dl,BYTE PTR [rcx+0x16000058]
 3fa:	8e 00                	mov    es,WORD PTR [rax]
 3fc:	00 00                	add    BYTE PTR [rax],al
 3fe:	0d 38 00 00 00       	or     eax,0x38
 403:	0f 00 00             	sldt   WORD PTR [rax]

Disassembly of section .debug_abbrev:

0000000000000000 <.debug_abbrev>:
   0:	01 11                	add    DWORD PTR [rcx],edx
   2:	01 25 0e 13 0b 03    	add    DWORD PTR [rip+0x30b130e],esp        # 30b1316 <_end+0x2eb02e6>
   8:	0e                   	(bad)  
   9:	1b 0e                	sbb    ecx,DWORD PTR [rsi]
   b:	11 01                	adc    DWORD PTR [rcx],eax
   d:	12 07                	adc    al,BYTE PTR [rdi]
   f:	10 17                	adc    BYTE PTR [rdi],dl
  11:	00 00                	add    BYTE PTR [rax],al
  13:	02 16                	add    dl,BYTE PTR [rsi]
  15:	00 03                	add    BYTE PTR [rbx],al
  17:	0e                   	(bad)  
  18:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  1a:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  1c:	49 13 00             	adc    rax,QWORD PTR [r8]
  1f:	00 03                	add    BYTE PTR [rbx],al
  21:	24 00                	and    al,0x0
  23:	0b 0b                	or     ecx,DWORD PTR [rbx]
  25:	3e 0b 03             	or     eax,DWORD PTR ds:[rbx]
  28:	0e                   	(bad)  
  29:	00 00                	add    BYTE PTR [rax],al
  2b:	04 24                	add    al,0x24
  2d:	00 0b                	add    BYTE PTR [rbx],cl
  2f:	0b 3e                	or     edi,DWORD PTR [rsi]
  31:	0b 03                	or     eax,DWORD PTR [rbx]
  33:	08 00                	or     BYTE PTR [rax],al
  35:	00 05 0f 00 0b 0b    	add    BYTE PTR [rip+0xb0b000f],al        # b0b004a <_end+0xaeaf01a>
  3b:	00 00                	add    BYTE PTR [rax],al
  3d:	06                   	(bad)  
  3e:	0f 00 0b             	str    WORD PTR [rbx]
  41:	0b 49 13             	or     ecx,DWORD PTR [rcx+0x13]
  44:	00 00                	add    BYTE PTR [rax],al
  46:	07                   	(bad)  
  47:	26 00 49 13          	add    BYTE PTR es:[rcx+0x13],cl
  4b:	00 00                	add    BYTE PTR [rax],al
  4d:	08 13                	or     BYTE PTR [rbx],dl
  4f:	01 03                	add    DWORD PTR [rbx],eax
  51:	0e                   	(bad)  
  52:	0b 0b                	or     ecx,DWORD PTR [rbx]
  54:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  56:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  58:	01 13                	add    DWORD PTR [rbx],edx
  5a:	00 00                	add    BYTE PTR [rax],al
  5c:	09 0d 00 03 0e 3a    	or     DWORD PTR [rip+0x3a0e0300],ecx        # 3a0e0362 <_end+0x39edf332>
  62:	0b 3b                	or     edi,DWORD PTR [rbx]
  64:	0b 49 13             	or     ecx,DWORD PTR [rcx+0x13]
  67:	38 0b                	cmp    BYTE PTR [rbx],cl
  69:	00 00                	add    BYTE PTR [rax],al
  6b:	0a 0d 00 03 0e 3a    	or     cl,BYTE PTR [rip+0x3a0e0300]        # 3a0e0371 <_end+0x39edf341>
  71:	0b 3b                	or     edi,DWORD PTR [rbx]
  73:	05 49 13 38 0b       	add    eax,0xb381349
  78:	00 00                	add    BYTE PTR [rax],al
  7a:	0b 16                	or     edx,DWORD PTR [rsi]
  7c:	00 03                	add    BYTE PTR [rbx],al
  7e:	0e                   	(bad)  
  7f:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  81:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  83:	00 00                	add    BYTE PTR [rax],al
  85:	0c 01                	or     al,0x1
  87:	01 49 13             	add    DWORD PTR [rcx+0x13],ecx
  8a:	01 13                	add    DWORD PTR [rbx],edx
  8c:	00 00                	add    BYTE PTR [rax],al
  8e:	0d 21 00 49 13       	or     eax,0x13490021
  93:	2f                   	(bad)  
  94:	0b 00                	or     eax,DWORD PTR [rax]
  96:	00 0e                	add    BYTE PTR [rsi],cl
  98:	13 00                	adc    eax,DWORD PTR [rax]
  9a:	03 0e                	add    ecx,DWORD PTR [rsi]
  9c:	3c 19                	cmp    al,0x19
  9e:	00 00                	add    BYTE PTR [rax],al
  a0:	0f 34                	sysenter 
  a2:	00 03                	add    BYTE PTR [rbx],al
  a4:	0e                   	(bad)  
  a5:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  a7:	3b 05 49 13 3f 19    	cmp    eax,DWORD PTR [rip+0x193f1349]        # 193f13f6 <_end+0x191f03c6>
  ad:	3c 19                	cmp    al,0x19
  af:	00 00                	add    BYTE PTR [rax],al
  b1:	10 34 00             	adc    BYTE PTR [rax+rax*1],dh
  b4:	03 0e                	add    ecx,DWORD PTR [rsi]
  b6:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  b8:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  ba:	49 13 3f             	adc    rdi,QWORD PTR [r15]
  bd:	19 3c 19             	sbb    DWORD PTR [rcx+rbx*1],edi
  c0:	00 00                	add    BYTE PTR [rax],al
  c2:	11 21                	adc    DWORD PTR [rcx],esp
  c4:	00 00                	add    BYTE PTR [rax],al
  c6:	00 12                	add    BYTE PTR [rdx],dl
  c8:	2e 01 3f             	add    DWORD PTR cs:[rdi],edi
  cb:	19 03                	sbb    DWORD PTR [rbx],eax
  cd:	0e                   	(bad)  
  ce:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  d0:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  d2:	49 13 11             	adc    rdx,QWORD PTR [r9]
  d5:	01 12                	add    DWORD PTR [rdx],edx
  d7:	07                   	(bad)  
  d8:	40 18 96 42 19 01 13 	sbb    BYTE PTR [rsi+0x13011942],dl
  df:	00 00                	add    BYTE PTR [rax],al
  e1:	13 34 00             	adc    esi,DWORD PTR [rax+rax*1]
  e4:	03 08                	add    ecx,DWORD PTR [rax]
  e6:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  e8:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  ea:	49 13 02             	adc    rax,QWORD PTR [r10]
  ed:	18 00                	sbb    BYTE PTR [rax],al
  ef:	00 14 34             	add    BYTE PTR [rsp+rsi*1],dl
  f2:	00 03                	add    BYTE PTR [rbx],al
  f4:	0e                   	(bad)  
  f5:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  f7:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  f9:	49 13 02             	adc    rax,QWORD PTR [r10]
  fc:	18 00                	sbb    BYTE PTR [rax],al
  fe:	00 15 0b 01 11 01    	add    BYTE PTR [rip+0x111010b],dl        # 111020f <_end+0xf0f1df>
 104:	12 07                	adc    al,BYTE PTR [rdi]
 106:	00 00                	add    BYTE PTR [rax],al
 108:	16                   	(bad)  
 109:	01 01                	add    DWORD PTR [rcx],eax
 10b:	49 13 00             	adc    rax,QWORD PTR [r8]
	...

Disassembly of section .debug_line:

0000000000000000 <.debug_line>:
   0:	06                   	(bad)  
   1:	01 00                	add    DWORD PTR [rax],eax
   3:	00 02                	add    BYTE PTR [rdx],al
   5:	00 db                	add    bl,bl
   7:	00 00                	add    BYTE PTR [rax],al
   9:	00 01                	add    BYTE PTR [rcx],al
   b:	01 fb                	add    ebx,edi
   d:	0e                   	(bad)  
   e:	0d 00 01 01 01       	or     eax,0x1010100
  13:	01 00                	add    DWORD PTR [rax],eax
  15:	00 00                	add    BYTE PTR [rax],al
  17:	01 00                	add    DWORD PTR [rax],eax
  19:	00 01                	add    BYTE PTR [rcx],al
  1b:	2f                   	(bad)  
  1c:	75 73                	jne    91 <_init-0x68f>
  1e:	72 2f                	jb     4f <_init-0x6d1>
  20:	6c                   	ins    BYTE PTR es:[rdi],dx
  21:	69 62 2f 67 63 63 2f 	imul   esp,DWORD PTR [rdx+0x2f],0x2f636367
  28:	78 38                	js     62 <_init-0x6be>
  2a:	36 5f                	ss pop rdi
  2c:	36 34 2d             	ss xor al,0x2d
  2f:	6c                   	ins    BYTE PTR es:[rdi],dx
  30:	69 6e 75 78 2d 67 6e 	imul   ebp,DWORD PTR [rsi+0x75],0x6e672d78
  37:	75 2f                	jne    68 <_init-0x6b8>
  39:	37                   	(bad)  
  3a:	2f                   	(bad)  
  3b:	69 6e 63 6c 75 64 65 	imul   ebp,DWORD PTR [rsi+0x63],0x6564756c
  42:	00 2f                	add    BYTE PTR [rdi],ch
  44:	75 73                	jne    b9 <_init-0x667>
  46:	72 2f                	jb     77 <_init-0x6a9>
  48:	69 6e 63 6c 75 64 65 	imul   ebp,DWORD PTR [rsi+0x63],0x6564756c
  4f:	2f                   	(bad)  
  50:	78 38                	js     8a <_init-0x696>
  52:	36 5f                	ss pop rdi
  54:	36 34 2d             	ss xor al,0x2d
  57:	6c                   	ins    BYTE PTR es:[rdi],dx
  58:	69 6e 75 78 2d 67 6e 	imul   ebp,DWORD PTR [rsi+0x75],0x6e672d78
  5f:	75 2f                	jne    90 <_init-0x690>
  61:	62                   	(bad)  
  62:	69 74 73 00 2f 75 73 	imul   esi,DWORD PTR [rbx+rsi*2+0x0],0x7273752f
  69:	72 
  6a:	2f                   	(bad)  
  6b:	69 6e 63 6c 75 64 65 	imul   ebp,DWORD PTR [rsi+0x63],0x6564756c
  72:	00 00                	add    BYTE PTR [rax],al
  74:	67 75 65             	addr32 jne dc <_init-0x644>
  77:	73 73                	jae    ec <_init-0x634>
  79:	2e 63 00             	movsxd eax,DWORD PTR cs:[rax]
  7c:	00 00                	add    BYTE PTR [rax],al
  7e:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
  81:	64 64 65 66 2e 68 00 	fs fs gs cs pushw 0x100
  88:	01 
  89:	00 00                	add    BYTE PTR [rax],al
  8b:	74 79                	je     106 <_init-0x61a>
  8d:	70 65                	jo     f4 <_init-0x62c>
  8f:	73 2e                	jae    bf <_init-0x661>
  91:	68 00 02 00 00       	push   0x200
  96:	6c                   	ins    BYTE PTR es:[rdi],dx
  97:	69 62 69 6f 2e 68 00 	imul   esp,DWORD PTR [rdx+0x69],0x682e6f
  9e:	02 00                	add    al,BYTE PTR [rax]
  a0:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
  a3:	64 69 6f 2e 68 00 03 	imul   ebp,DWORD PTR fs:[rdi+0x2e],0x30068
  aa:	00 
  ab:	00 73 79             	add    BYTE PTR [rbx+0x79],dh
  ae:	73 5f                	jae    10f <_init-0x611>
  b0:	65 72 72             	gs jb  125 <_init-0x5fb>
  b3:	6c                   	ins    BYTE PTR es:[rdi],dx
  b4:	69 73 74 2e 68 00 02 	imul   esi,DWORD PTR [rbx+0x74],0x200682e
  bb:	00 00                	add    BYTE PTR [rax],al
  bd:	74 69                	je     128 <_init-0x5f8>
  bf:	6d                   	ins    DWORD PTR es:[rdi],dx
  c0:	65 2e 68 00 03 00 00 	gs cs push 0x300
  c7:	75 6e                	jne    137 <_init-0x5e9>
  c9:	69 73 74 64 2e 68 00 	imul   esi,DWORD PTR [rbx+0x74],0x682e64
  d0:	03 00                	add    eax,DWORD PTR [rax]
  d2:	00 67 65             	add    BYTE PTR [rdi+0x65],ah
  d5:	74 6f                	je     146 <_init-0x5da>
  d7:	70 74                	jo     14d <_init-0x5d3>
  d9:	5f                   	pop    rdi
  da:	63 6f 72             	movsxd ebp,DWORD PTR [rdi+0x72]
  dd:	65 2e 68 00 02 00 00 	gs cs push 0x200
  e4:	00 00                	add    BYTE PTR [rax],al
  e6:	09 02                	or     DWORD PTR [rdx],eax
  e8:	fa                   	cli    
  e9:	08 00                	or     BYTE PTR [rax],al
  eb:	00 00                	add    BYTE PTR [rax],al
  ed:	00 00                	add    BYTE PTR [rax],al
  ef:	00 18                	add    BYTE PTR [rax],bl
  f1:	94                   	xchg   esp,eax
  f2:	08 c9                	or     cl,cl
  f4:	08 91 02 2f 14 08    	or     BYTE PTR [rcx+0x8142f02],dl
  fa:	13 08                	adc    ecx,DWORD PTR [rax]
  fc:	bb 08 83 08 59       	mov    ebx,0x59088308
 101:	83 d8 be             	sbb    eax,0xffffffbe
 104:	59                   	pop    rcx
 105:	02 07                	add    al,BYTE PTR [rdi]
 107:	00 01                	add    BYTE PTR [rcx],al
 109:	01                   	.byte 0x1

Disassembly of section .debug_str:

0000000000000000 <.debug_str>:
   0:	6f                   	outs   dx,DWORD PTR ds:[rsi]
   1:	70 74                	jo     77 <_init-0x6a9>
   3:	69 6e 64 00 6f 70 74 	imul   ebp,DWORD PTR [rsi+0x64],0x74706f00
   a:	61                   	(bad)  
   b:	72 67                	jb     74 <_init-0x6ac>
   d:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  10:	4f 5f                	rex.WRXB pop r15
  12:	46                   	rex.RX
  13:	49                   	rex.WB
  14:	4c                   	rex.WR
  15:	45 00 73 79          	add    BYTE PTR [r11+0x79],r14b
  19:	73 5f                	jae    7a <_init-0x6a6>
  1b:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  1c:	65 72 72             	gs jb  91 <_init-0x68f>
  1f:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  22:	4f 5f                	rex.WRXB pop r15
  24:	73 61                	jae    87 <_init-0x699>
  26:	76 65                	jbe    8d <_init-0x693>
  28:	5f                   	pop    rdi
  29:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
  2b:	64 00 73 68          	add    BYTE PTR fs:[rbx+0x68],dh
  2f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
  30:	72 74                	jb     a6 <_init-0x67a>
  32:	20 69 6e             	and    BYTE PTR [rcx+0x6e],ch
  35:	74 00                	je     37 <_init-0x6e9>
  37:	73 69                	jae    a2 <_init-0x67e>
  39:	7a 65                	jp     a0 <_init-0x680>
  3b:	5f                   	pop    rdi
  3c:	74 00                	je     3e <_init-0x6e2>
  3e:	5f                   	pop    rdi
  3f:	5f                   	pop    rdi
  40:	74 7a                	je     bc <_init-0x664>
  42:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  43:	61                   	(bad)  
  44:	6d                   	ins    DWORD PTR es:[rdi],dx
  45:	65 00 5f 49          	add    BYTE PTR gs:[rdi+0x49],bl
  49:	4f 5f                	rex.WRXB pop r15
  4b:	77 72                	ja     bf <_init-0x661>
  4d:	69 74 65 5f 70 74 72 	imul   esi,DWORD PTR [rbp+riz*2+0x5f],0x727470
  54:	00 
  55:	5f                   	pop    rdi
  56:	66 6c                	data16 ins BYTE PTR es:[rdi],dx
  58:	61                   	(bad)  
  59:	67 73 00             	addr32 jae 5c <_init-0x6c4>
  5c:	5f                   	pop    rdi
  5d:	49                   	rex.WB
  5e:	4f 5f                	rex.WRXB pop r15
  60:	32 5f 31             	xor    bl,BYTE PTR [rdi+0x31]
  63:	5f                   	pop    rdi
  64:	73 74                	jae    da <_init-0x646>
  66:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
  68:	75 74                	jne    de <_init-0x642>
  6a:	5f                   	pop    rdi
  6b:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
  6e:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
  70:	76 69                	jbe    db <_init-0x645>
  72:	72 6f                	jb     e3 <_init-0x63d>
  74:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  75:	00 5f 6d             	add    BYTE PTR [rdi+0x6d],bl
  78:	61                   	(bad)  
  79:	72 6b                	jb     e6 <_init-0x63a>
  7b:	65 72 73             	gs jb  f1 <_init-0x62f>
  7e:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  81:	4f 5f                	rex.WRXB pop r15
  83:	72 65                	jb     ea <_init-0x636>
  85:	61                   	(bad)  
  86:	64 5f                	fs pop rdi
  88:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
  8a:	64 00 73 74          	add    BYTE PTR fs:[rbx+0x74],dh
  8e:	64 65 72 72          	fs gs jb 104 <_init-0x61c>
  92:	00 6c 6f 6e          	add    BYTE PTR [rdi+rbp*2+0x6e],ch
  96:	67 20 6c 6f 6e       	and    BYTE PTR [edi+ebp*2+0x6e],ch
  9b:	67 20 69 6e          	and    BYTE PTR [ecx+0x6e],ch
  9f:	74 00                	je     a1 <_init-0x67f>
  a1:	5f                   	pop    rdi
  a2:	5f                   	pop    rdi
  a3:	74 69                	je     10e <_init-0x612>
  a5:	6d                   	ins    DWORD PTR es:[rdi],dx
  a6:	65 7a 6f             	gs jp  118 <_init-0x608>
  a9:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  aa:	65 00 5f 6c          	add    BYTE PTR gs:[rdi+0x6c],bl
  ae:	6f                   	outs   dx,DWORD PTR ds:[rsi]
  af:	63 6b 00             	movsxd ebp,DWORD PTR [rbx+0x0]
  b2:	5f                   	pop    rdi
  b3:	5f                   	pop    rdi
  b4:	64 61                	fs (bad) 
  b6:	79 6c                	jns    124 <_init-0x5fc>
  b8:	69 67 68 74 00 5f 63 	imul   esp,DWORD PTR [rdi+0x68],0x635f0074
  bf:	75 72                	jne    133 <_init-0x5ed>
  c1:	5f                   	pop    rdi
  c2:	63 6f 6c             	movsxd ebp,DWORD PTR [rdi+0x6c]
  c5:	75 6d                	jne    134 <_init-0x5ec>
  c7:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  c8:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  cb:	4f 5f                	rex.WRXB pop r15
  cd:	32 5f 31             	xor    bl,BYTE PTR [rdi+0x31]
  d0:	5f                   	pop    rdi
  d1:	73 74                	jae    147 <_init-0x5d9>
  d3:	64 65 72 72          	fs gs jb 149 <_init-0x5d7>
  d7:	5f                   	pop    rdi
  d8:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  db:	4f 5f                	rex.WRXB pop r15
  dd:	46                   	rex.RX
  de:	49                   	rex.WB
  df:	4c                   	rex.WR
  e0:	45 5f                	rex.RB pop r15
  e2:	70 6c                	jo     150 <_init-0x5d0>
  e4:	75 73                	jne    159 <_init-0x5c7>
  e6:	00 5f 70             	add    BYTE PTR [rdi+0x70],bl
  e9:	6f                   	outs   dx,DWORD PTR ds:[rsi]
  ea:	73 00                	jae    ec <_init-0x634>
  ec:	5f                   	pop    rdi
  ed:	49                   	rex.WB
  ee:	4f 5f                	rex.WRXB pop r15
  f0:	77 72                	ja     164 <_init-0x5bc>
  f2:	69 74 65 5f 62 61 73 	imul   esi,DWORD PTR [rbp+riz*2+0x5f],0x65736162
  f9:	65 
  fa:	00 5f 73             	add    BYTE PTR [rdi+0x73],bl
  fd:	62                   	(bad)  
  fe:	75 66                	jne    166 <_init-0x5ba>
 100:	00 5f 6f             	add    BYTE PTR [rdi+0x6f],bl
 103:	6c                   	ins    BYTE PTR es:[rdi],dx
 104:	64 5f                	fs pop rdi
 106:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 107:	66 66 73 65          	data16 data16 jae 170 <_init-0x5b0>
 10b:	74 00                	je     10d <_init-0x613>
 10d:	75 6e                	jne    17d <_init-0x5a3>
 10f:	73 69                	jae    17a <_init-0x5a6>
 111:	67 6e                	outs   dx,BYTE PTR ds:[esi]
 113:	65 64 20 63 68       	gs and BYTE PTR fs:[rbx+0x68],ah
 118:	61                   	(bad)  
 119:	72 00                	jb     11b <_init-0x605>
 11b:	6c                   	ins    BYTE PTR es:[rdi],dx
 11c:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 11d:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 11e:	67 20 6c 6f 6e       	and    BYTE PTR [edi+ebp*2+0x6e],ch
 123:	67 20 75 6e          	and    BYTE PTR [ebp+0x6e],dh
 127:	73 69                	jae    192 <_init-0x58e>
 129:	67 6e                	outs   dx,BYTE PTR ds:[esi]
 12b:	65 64 20 69 6e       	gs and BYTE PTR fs:[rcx+0x6e],ch
 130:	74 00                	je     132 <_init-0x5ee>
 132:	5f                   	pop    rdi
 133:	49                   	rex.WB
 134:	4f 5f                	rex.WRXB pop r15
 136:	32 5f 31             	xor    bl,BYTE PTR [rdi+0x31]
 139:	5f                   	pop    rdi
 13a:	73 74                	jae    1b0 <_init-0x570>
 13c:	64 69 6e 5f 00 5f 49 	imul   ebp,DWORD PTR fs:[rsi+0x5f],0x4f495f00
 143:	4f 
 144:	5f                   	pop    rdi
 145:	6d                   	ins    DWORD PTR es:[rdi],dx
 146:	61                   	(bad)  
 147:	72 6b                	jb     1b4 <_init-0x56c>
 149:	65 72 00             	gs jb  14c <_init-0x5d4>
 14c:	5f                   	pop    rdi
 14d:	73 68                	jae    1b7 <_init-0x569>
 14f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 150:	72 74                	jb     1c6 <_init-0x55a>
 152:	62                   	(bad)  
 153:	75 66                	jne    1bb <_init-0x565>
 155:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 158:	70 61                	jo     1bb <_init-0x565>
 15a:	64 31 00             	xor    DWORD PTR fs:[rax],eax
 15d:	5f                   	pop    rdi
 15e:	75 6e                	jne    1ce <_init-0x552>
 160:	75 73                	jne    1d5 <_init-0x54b>
 162:	65 64 32 00          	gs xor al,BYTE PTR fs:[rax]
 166:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 167:	70 74                	jo     1dd <_init-0x543>
 169:	65 72 72             	gs jb  1de <_init-0x542>
 16c:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 16f:	4f 5f                	rex.WRXB pop r15
 171:	62                   	(bad)  
 172:	75 66                	jne    1da <_init-0x546>
 174:	5f                   	pop    rdi
 175:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
 177:	64 00 6d 61          	add    BYTE PTR fs:[rbp+0x61],ch
 17b:	69 6e 00 5f 6e 65 78 	imul   ebp,DWORD PTR [rsi+0x0],0x78656e5f
 182:	74 00                	je     184 <_init-0x59c>
 184:	61                   	(bad)  
 185:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 186:	73 77                	jae    1ff <_init-0x521>
 188:	65 72 00             	gs jb  18b <_init-0x595>
 18b:	5f                   	pop    rdi
 18c:	5f                   	pop    rdi
 18d:	70 61                	jo     1f0 <_init-0x530>
 18f:	64 32 00             	xor    al,BYTE PTR fs:[rax]
 192:	5f                   	pop    rdi
 193:	5f                   	pop    rdi
 194:	70 61                	jo     1f7 <_init-0x529>
 196:	64 33 00             	xor    eax,DWORD PTR fs:[rax]
 199:	5f                   	pop    rdi
 19a:	5f                   	pop    rdi
 19b:	70 61                	jo     1fe <_init-0x522>
 19d:	64 34 00             	fs xor al,0x0
 1a0:	5f                   	pop    rdi
 1a1:	5f                   	pop    rdi
 1a2:	70 61                	jo     205 <_init-0x51b>
 1a4:	64 35 00 73 68 6f    	fs xor eax,0x6f687300
 1aa:	72 74                	jb     220 <_init-0x500>
 1ac:	20 75 6e             	and    BYTE PTR [rbp+0x6e],dh
 1af:	73 69                	jae    21a <_init-0x506>
 1b1:	67 6e                	outs   dx,BYTE PTR ds:[esi]
 1b3:	65 64 20 69 6e       	gs and BYTE PTR fs:[rcx+0x6e],ch
 1b8:	74 00                	je     1ba <_init-0x566>
 1ba:	5f                   	pop    rdi
 1bb:	49                   	rex.WB
 1bc:	4f 5f                	rex.WRXB pop r15
 1be:	77 72                	ja     232 <_init-0x4ee>
 1c0:	69 74 65 5f 65 6e 64 	imul   esi,DWORD PTR [rbp+riz*2+0x5f],0x646e65
 1c7:	00 
 1c8:	5f                   	pop    rdi
 1c9:	5f                   	pop    rdi
 1ca:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 1cb:	66 66 36 34 5f       	data16 data16 ss xor al,0x5f
 1d0:	74 00                	je     1d2 <_init-0x54e>
 1d2:	5f                   	pop    rdi
 1d3:	66 69 6c 65 6e 6f 00 	imul   bp,WORD PTR [rbp+riz*2+0x6e],0x6f
 1da:	5f                   	pop    rdi
 1db:	63 68 61             	movsxd ebp,DWORD PTR [rax+0x61]
 1de:	69 6e 00 2f 68 6f 6d 	imul   ebp,DWORD PTR [rsi+0x0],0x6d6f682f
 1e5:	65 2f                	gs (bad) 
 1e7:	68 75 61 6e 67       	push   0x676e6175
 1ec:	61                   	(bad)  
 1ed:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 1ee:	74 2f                	je     21f <_init-0x501>
 1f0:	6d                   	ins    DWORD PTR es:[rdi],dx
 1f1:	79 70                	jns    263 <_init-0x4bd>
 1f3:	72 6f                	jb     264 <_init-0x4bc>
 1f5:	67 2f                	addr32 (bad) 
 1f7:	75 6e                	jne    267 <_init-0x4b9>
 1f9:	69 78 5f 70 72 6f 67 	imul   edi,DWORD PTR [rax+0x5f],0x676f7270
 200:	2f                   	(bad)  
 201:	70 72                	jo     275 <_init-0x4ab>
 203:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 204:	63 65 6e             	movsxd esp,DWORD PTR [rbp+0x6e]
 207:	76 00                	jbe    209 <_init-0x517>
 209:	5f                   	pop    rdi
 20a:	5f                   	pop    rdi
 20b:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 20c:	66 66 5f             	data16 pop di
 20f:	74 00                	je     211 <_init-0x50f>
 211:	5f                   	pop    rdi
 212:	49                   	rex.WB
 213:	4f 5f                	rex.WRXB pop r15
 215:	62 61                	(bad)  
 217:	63 6b 75             	movsxd ebp,DWORD PTR [rbx+0x75]
 21a:	70 5f                	jo     27b <_init-0x4a5>
 21c:	62 61                	(bad)  
 21e:	73 65                	jae    285 <_init-0x49b>
 220:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
 223:	64 69 6e 00 5f 49 4f 	imul   ebp,DWORD PTR fs:[rsi+0x0],0x5f4f495f
 22a:	5f 
 22b:	62                   	(bad)  
 22c:	75 66                	jne    294 <_init-0x48c>
 22e:	5f                   	pop    rdi
 22f:	62 61                	(bad)  
 231:	73 65                	jae    298 <_init-0x488>
 233:	00 5f 66             	add    BYTE PTR [rdi+0x66],bl
 236:	6c                   	ins    BYTE PTR es:[rdi],dx
 237:	61                   	(bad)  
 238:	67 73 32             	addr32 jae 26d <_init-0x4b3>
 23b:	00 5f 6d             	add    BYTE PTR [rdi+0x6d],bl
 23e:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 23f:	64 65 00 5f 49       	fs add BYTE PTR gs:[rdi+0x49],bl
 244:	4f 5f                	rex.WRXB pop r15
 246:	72 65                	jb     2ad <_init-0x473>
 248:	61                   	(bad)  
 249:	64 5f                	fs pop rdi
 24b:	62 61                	(bad)  
 24d:	73 65                	jae    2b4 <_init-0x46c>
 24f:	00 5f 76             	add    BYTE PTR [rdi+0x76],bl
 252:	74 61                	je     2b5 <_init-0x46b>
 254:	62                   	(bad)  
 255:	6c                   	ins    BYTE PTR es:[rdi],dx
 256:	65 5f                	gs pop rdi
 258:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 259:	66 66 73 65          	data16 data16 jae 2c2 <_init-0x45e>
 25d:	74 00                	je     25f <_init-0x4c1>
 25f:	47                   	rex.RXB
 260:	4e 55                	rex.WRX push rbp
 262:	20 43 31             	and    BYTE PTR [rbx+0x31],al
 265:	31 20                	xor    DWORD PTR [rax],esp
 267:	37                   	(bad)  
 268:	2e 35 2e 30 20 2d    	cs xor eax,0x2d20302e
 26e:	6d                   	ins    DWORD PTR es:[rdi],dx
 26f:	74 75                	je     2e6 <_init-0x43a>
 271:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 272:	65 3d 67 65 6e 65    	gs cmp eax,0x656e6567
 278:	72 69                	jb     2e3 <_init-0x43d>
 27a:	63 20                	movsxd esp,DWORD PTR [rax]
 27c:	2d 6d 61 72 63       	sub    eax,0x6372616d
 281:	68 3d 78 38 36       	push   0x3638783d
 286:	2d 36 34 20 2d       	sub    eax,0x2d203436
 28b:	67 20 2d 66 6e 6f 2d 	and    BYTE PTR [eip+0x2d6f6e66],ch        # 2d6f70f8 <_end+0x2d4f60c8>
 292:	73 74                	jae    308 <_init-0x418>
 294:	61                   	(bad)  
 295:	63 6b 2d             	movsxd ebp,DWORD PTR [rbx+0x2d]
 298:	70 72                	jo     30c <_init-0x414>
 29a:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 29b:	74 65                	je     302 <_init-0x41e>
 29d:	63 74 6f 72          	movsxd esi,DWORD PTR [rdi+rbp*2+0x72]
 2a1:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 2a4:	4f 5f                	rex.WRXB pop r15
 2a6:	73 61                	jae    309 <_init-0x417>
 2a8:	76 65                	jbe    30f <_init-0x411>
 2aa:	5f                   	pop    rdi
 2ab:	62 61                	(bad)  
 2ad:	73 65                	jae    314 <_init-0x40c>
 2af:	00 73 79             	add    BYTE PTR [rbx+0x79],dh
 2b2:	73 5f                	jae    313 <_init-0x40d>
 2b4:	65 72 72             	gs jb  329 <_init-0x3f7>
 2b7:	6c                   	ins    BYTE PTR es:[rdi],dx
 2b8:	69 73 74 00 6f 70 74 	imul   esi,DWORD PTR [rbx+0x74],0x74706f00
 2bf:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 2c0:	70 74                	jo     336 <_init-0x3ea>
 2c2:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 2c5:	4f 5f                	rex.WRXB pop r15
 2c7:	72 65                	jb     32e <_init-0x3f2>
 2c9:	61                   	(bad)  
 2ca:	64 5f                	fs pop rdi
 2cc:	70 74                	jo     342 <_init-0x3de>
 2ce:	72 00                	jb     2d0 <_init-0x450>
 2d0:	67 75 65             	addr32 jne 338 <_init-0x3e8>
 2d3:	73 73                	jae    348 <_init-0x3d8>
 2d5:	2e 63 00             	movsxd eax,DWORD PTR cs:[rax]
 2d8:	73 74                	jae    34e <_init-0x3d2>
 2da:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
 2dc:	75 74                	jne    352 <_init-0x3ce>
 2de:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 2e1:	4f 5f                	rex.WRXB pop r15
 2e3:	6c                   	ins    BYTE PTR es:[rdi],dx
 2e4:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 2e5:	63 6b 5f             	movsxd ebp,DWORD PTR [rbx+0x5f]
 2e8:	74 00                	je     2ea <_init-0x436>
