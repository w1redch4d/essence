// This file is part of the Essence operating system.
// It is released under the terms of the MIT license -- see LICENSE.md.
// Written by: phcoder.

#define ASM_FILE
#include "multiboot2.h"
	.text
	.code32

#define REL32(x) ((x) - _start + 0x180000)

	.globl _start
	.globl stack
_start:
	// Change GDT
	lgdt	REL32(.gdt)
	ljmpl	$0x8, $REL32(.start_32_bit_mode)

	.start_32_bit_mode:

	mov	$0x10, %eax
	mov	%eax, %ds
	mov	%eax, %es
	mov	%eax, %ss

	mov	$REL32(stack + 0x10000 - 8), %esp
	push	%ebx
	call	mb2_main

	mov	%cr4, %eax
	or	$0x30, %eax
	mov	%eax, %cr4
	
	mov	$0x140000, %eax
	mov	%eax, %cr3

	// Enable long mode
	mov	$0xC0000080, %ecx
	rdmsr
	or	$0x100, %eax
	wrmsr
	mov	%cr0, %eax
	or	$0x80000000, %eax
	mov	%eax, %cr0

	lgdt	REL32(.gdt)

	// Go to 64-bit mode
	ljmpl	$0x48, $REL32(.start_64_bit_mode)

	.code64

	.align 16

	.start_64_bit_mode:

	mov	$0x50, %rax
	mov	%rax, %ds
	mov	%rax, %es
	mov	%rax, %ss

	// Get the start address of the kernel
	mov	kernel_start(%rip), %rcx

	// Map the first MB at 0xFFFFFE0000000000 --> 0xFFFFFE0000100000 
	mov	$0xFFFFFF7FBFDFE000, %rdi
	mov	(%rdi), %rax
	mov	$0xFFFFFF7FBFDFEFE0, %rdi
	mov	%rax, (%rdi)
	mov	%cr3, %rax
	mov	%rax, %cr3

	// Use the new linear address of the GDT
	mov	$0xFFFFFE0000000000, %rax
	add	%rax, .gdt2(%rip)
	lgdt	.gdt(%rip)

	call 	.set_cs

	// Execute the kernel's _start function
	mov	$0x100000, %rdi
	mov	$2, %rsi
	jmp	*%rcx

.set_cs:
	pop	%rax
	push	$0x48
	push	%rax
	.byte	0x48, 0xCB

	.align  MULTIBOOT_HEADER_ALIGN

.multiboot2_header:
	.long MULTIBOOT2_HEADER_MAGIC
	.long MULTIBOOT2_ARCHITECTURE_I386
	.long .multiboot2_header_end - .multiboot2_header
	.long -(.multiboot2_header_end - .multiboot2_header + MULTIBOOT2_HEADER_MAGIC + MULTIBOOT2_ARCHITECTURE_I386)

	.word MULTIBOOT_HEADER_TAG_FRAMEBUFFER
	.word 0
	.long 20
	.long 0 // width: any
	.long 0 // height: any
	.long 0 // depth: any

	.long 0 // padding

	.word MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST
	.word 0
	.long 20
	.long MULTIBOOT_TAG_TYPE_ACPI_NEW
	.long MULTIBOOT_TAG_TYPE_FRAMEBUFFER
	.long MULTIBOOT_TAG_TYPE_MODULE

	.long 0 // padding

	.word MULTIBOOT_HEADER_TAG_MODULE_ALIGN
	.word 0
	.long 8

	.word MULTIBOOT_HEADER_TAG_END
	.word 0
	.long 8
.multiboot2_header_end:	
	
	.align 16
.gdt_data:
	.null_entry:	.quad 0
	.code_entry:	.long 0xFFFF	// 0x08
			.byte 0
			.word 0xCF9A
			.byte 0
	.data_entry:	.long 0xFFFF	// 0x10
			.byte 0
			.word 0xCF92
			.byte 0
	.code_entry_16:	.long 0xFFFF	// 0x18
			.byte 0
			.word 0x0F9A
			.byte 0
	.data_entry_16:	.long 0xFFFF	// 0x20
			.byte 0
			.word 0x0F92
			.byte 0
	.user_code:	.long 0xFFFF	// 0x28
			.byte 0
			.word 0xCFFA
			.byte 0
	.user_data:	.long 0xFFFF	// 0x30
			.byte 0
			.word 0xCFF2
			.byte 0
	.tss:		.long 0x68		// 0x38
			.byte 0
			.word 0xE9
			.byte 0
			.quad 0
	.code_entry64:	.long 0xFFFF	// 0x48
			.byte 0
			.word 0xAF9A
			.byte 0
	.data_entry64:	.long 0xFFFF	// 0x50
			.byte 0
			.word 0xAF92
			.byte 0
	.user_code64:	.long 0xFFFF	// 0x58
			.byte 0
			.word 0xAFFA
			.byte 0
	.user_data64:	.long 0xFFFF	// 0x60
			.byte 0
			.word 0xAFF2
			.byte 0
	.user_code64c:	.long 0xFFFF	// 0x68
			.byte 0
			.word 0xAFFA
			.byte 0
	.gdt:		.word (.gdt - .gdt_data - 1)
	.gdt2:		.quad REL32(.gdt_data)
