// This file is part of the Essence operating system.
// It is released under the terms of the MIT license -- see LICENSE.md.
// Written by: phcoder.

#include "multiboot2.h"

#define ENTRIES_PER_PAGE_TABLE (512)
#define ENTRIES_PER_PAGE_TABLE_BITS (9)
#define K_PAGE_SIZE (4096)
#define K_PAGE_BITS (12)

typedef __UINT8_TYPE__       uint8_t;
typedef __UINT16_TYPE__      uint16_t;
typedef __UINT32_TYPE__        uint32_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __UINT64_TYPE__  uint64_t;

typedef struct VideoModeInformation {
	uint8_t valid : 1, edidValid : 1;
	uint8_t bitsPerPixel;
	uint16_t widthPixels, heightPixels;
	uint16_t bytesPerScanlineLinear;
	uint64_t bufferPhysical;
	uint8_t edid[128];
} VideoModeInformation;

typedef struct ElfHeader {
	uint32_t magicNumber; // 0x7F followed by 'ELF'
	uint8_t bits; // 1 = 32 bit, 2 = 64 bit
	uint8_t endianness; // 1 = LE, 2 = BE
	uint8_t version1;
	uint8_t abi; // 0 = System V
	uint8_t _unused0[8];
	uint16_t type; // 1 = relocatable, 2 = executable, 3 = shared
	uint16_t instructionSet; // 0x03 = x86, 0x28 = ARM, 0x3E = x86-64, 0xB7 = AArch64
	uint32_t version2;
	uint64_t entry;
	uint64_t programHeaderTable;
	uint64_t sectionHeaderTable;
	uint32_t flags;
	uint16_t headerSize;
	uint16_t programHeaderEntrySize;
	uint16_t programHeaderEntries;
	uint16_t sectionHeaderEntrySize;
	uint16_t sectionHeaderEntries;
	uint16_t sectionNameIndex;
} ElfHeader;

typedef struct ElfSectionHeader {
	uint32_t name; // Offset into section header->sectionNameIndex.
	uint32_t type; // 4 = rela
	uint64_t flags;
	uint64_t address;
	uint64_t offset;
	uint64_t size;
	uint32_t link;
	uint32_t info;
	uint64_t align;
	uint64_t entrySize;
} ElfSectionHeader;

typedef struct ElfProgramHeader {
	uint32_t type; // 0 = unused, 1 = load, 2 = dynamic, 3 = interp, 4 = note
	uint32_t flags; // 1 = executable, 2 = writable, 4 = readable
	uint64_t fileOffset;
	uint64_t virtualAddress;
	uint64_t _unused0;
	uint64_t dataInFile;
	uint64_t segmentSize;
	uint64_t alignment;
} ElfProgramHeader;

typedef struct __attribute__((packed)) GDTData {
	uint16_t length;
	uint64_t address;
} GDTData;

typedef struct MemoryRegion {
	uint64_t base, pages;
} MemoryRegion;

#define MAX_MEMORY_REGIONS (1024)

struct {
	// 0x106000
	char rsdp_copy[4096];
	// 0x107000          Graphics info
	VideoModeInformation graphics_info;
	char filler[0xFE8 - sizeof(VideoModeInformation)];
	// 0x107FE8	    RSDP address
	uint64_t rsdp_address;
	// 0x107FF0	    Installation ID
	char iid[16];
} kernel_params __attribute__((section(".kernel_params")));

// 0x140000-0x150000 Identity paging tables
uint64_t paging_table[0x2000] __attribute__((section(".paging_table"), aligned(4096)));

// 0x160000-0x170000 Memory regions
MemoryRegion memoryRegions[MAX_MEMORY_REGIONS]  __attribute__((section(".memory_map")));
int memoryRegionCount = 0;

// 0x1c0000-0x1e0000 Identity paging tables
uint64_t kernel_paging_table[0x2000] __attribute__((section(".kernel_paging_table"), aligned(4096)));
// 0x180000-0x1C0000 Loader (this)
// 0x1F0000-0x200000 Stack
uint8_t stack[0x10000] __attribute__((section(".stack"), aligned(4096)));

uint64_t kernel_start;

static void ZeroMemory(void *pointer, uint64_t size) {
	char *d = (char *) pointer;

	for (uintptr_t i = 0; i < size; i++) {
		d[i] = 0;
	}
}

static void CopyMemory(void *dest, void *src, uint64_t size) {
	char *d = (char *) dest;
	char *s = (char *) src;

	for (uintptr_t i = 0; i < size; i++) {
		d[i] = s[i];
	}
}

static uint8_t hex2val (char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return 0;
}

#ifdef __cplusplus
extern "C"
#endif
void mb2_main(void *mb2_info) {
	ElfHeader *header;
	struct multiboot_tag_old_acpi *old_acpi = 0;
	struct multiboot_tag_new_acpi *new_acpi = 0;
	struct multiboot_tag_module *kernel_module = 0, *iid_module = 0;
	const char *iid_string = 0;

	ZeroMemory(&kernel_params, sizeof(kernel_params));

	for (struct multiboot_tag *tag = (struct multiboot_tag *) ((uint8_t *)mb2_info + 8);
	     tag->type != MULTIBOOT_TAG_TYPE_END;
	     tag = (struct multiboot_tag *) ((uint8_t *) tag + ((tag->size + MULTIBOOT_TAG_ALIGN - 1) & ~(MULTIBOOT_TAG_ALIGN - 1))))
		switch(tag->type) {
		case MULTIBOOT_TAG_TYPE_ACPI_OLD:
			old_acpi = (struct multiboot_tag_old_acpi *) tag;
			break;
		case MULTIBOOT_TAG_TYPE_ACPI_NEW:
			new_acpi = (struct multiboot_tag_new_acpi *) tag;
			break;
		case MULTIBOOT_TAG_TYPE_MODULE: {
			struct multiboot_tag_module *module = (struct multiboot_tag_module *) tag;
			if (module->mod_end - module->mod_start == 16)
				iid_module = module;
			else
				kernel_module = module;
			break;
		}
		case MULTIBOOT_TAG_TYPE_MMAP: {
			struct multiboot_tag_mmap *mmap = (struct multiboot_tag_mmap *) tag;
			struct multiboot_mmap_entry *mmap_entry = mmap->entries;
			for (; (uint8_t *)mmap_entry < (uint8_t *)tag + tag->size && memoryRegionCount != MAX_MEMORY_REGIONS - 1;
			     mmap_entry = (struct multiboot_mmap_entry *) ((uint8_t *) mmap_entry + mmap->entry_size)) {
				if (mmap_entry->type != MULTIBOOT_MEMORY_AVAILABLE)
					continue;
				uint64_t st = (mmap_entry->addr + 0xfff) & ~0xfffULL;
				uint64_t end = (mmap_entry->addr + mmap_entry->len) & ~0xfffULL;
				if (st < 0x300000)
					st = 0x300000;
				if (st >= end)
					continue;

				memoryRegions[memoryRegionCount].base = st;
				memoryRegions[memoryRegionCount].pages = (end - st) >> 12;
				memoryRegionCount++;
			}
			memoryRegions[memoryRegionCount].base = 0;
			break;
		}
		case MULTIBOOT_TAG_TYPE_FRAMEBUFFER: {
			struct multiboot_tag_framebuffer *fb = (struct multiboot_tag_framebuffer *) tag;
			kernel_params.graphics_info.heightPixels = fb->common.framebuffer_height;
			kernel_params.graphics_info.widthPixels = fb->common.framebuffer_width;
			kernel_params.graphics_info.bytesPerScanlineLinear = fb->common.framebuffer_pitch;
			kernel_params.graphics_info.bufferPhysical = fb->common.framebuffer_addr;
			kernel_params.graphics_info.bitsPerPixel = fb->common.framebuffer_bpp;
			kernel_params.graphics_info.valid = 1;
			kernel_params.graphics_info.edidValid = 0;
			break;
		}
		case MULTIBOOT_TAG_TYPE_CMDLINE: {
			struct multiboot_tag_string *cmdline = (struct multiboot_tag_string *) tag;
			for (const char *ptr = cmdline->string; *ptr;) {
				if (ptr[0] == 'i' && ptr[1] == 'i' && ptr[2] == 'd' && ptr[3] == '=')
					iid_string = ptr + 4;
				while (*ptr && *ptr != ' ' && *ptr != '\t')
					ptr++;
				while (*ptr && (*ptr == ' ' || *ptr == '\t'))
					ptr++;
			}
			break;
		}
		}

	if (new_acpi) {
		CopyMemory (&kernel_params.rsdp_copy, new_acpi->rsdp, new_acpi->size - sizeof(struct multiboot_tag));
		kernel_params.rsdp_address = (uintptr_t) &kernel_params.rsdp_copy;
	} else if (old_acpi) {
		CopyMemory (&kernel_params.rsdp_copy, old_acpi->rsdp, old_acpi->size - sizeof(struct multiboot_tag));
		kernel_params.rsdp_address = (uintptr_t) &kernel_params.rsdp_copy;
	}

	if (iid_string) {
		int j = 0;
		for (const char *ptr = iid_string; *ptr && *ptr != ' ' && *ptr != '\t' && j < 16; ) {
			while (*ptr == '-')
				ptr++;
			if (ptr[0] == '\0' || ptr[0] == ' ' || ptr[0] == '\t' ||
			    ptr[1] == '\0' || ptr[1] == ' ' || ptr[1] == '\t')
				break;
			kernel_params.iid[j++] = (hex2val(ptr[0]) << 4) | hex2val(ptr[1]);
			ptr += 2;
		}
	} else if (iid_module) {
		CopyMemory (kernel_params.iid, (void *) iid_module->mod_start, sizeof(kernel_params.iid));
	}

	// Identity map the first 3MB for the loader.
	{
		uint64_t *paging = paging_table;
		uint64_t base = (uintptr_t)paging;
		ZeroMemory(paging, 0x5000);

		paging[0x1FE] = base | 3; // Recursive
		paging[0x000] = (base + 0x1000) | 3; // L4
		paging[0x200] = (base + 0x2000) | 3; // L3
		paging[0x400] = (base + 0x3000) | 3; // L2
		paging[0x401] = (base + 0x4000) | 3;

		for (uintptr_t i = 0; i < 0x400; i++) {
			paging[0x600 + i] = (i * 0x1000) | 3; // L1
		}
	}

	// Allocate and map memory for the kernel.
	{
		uint64_t nextPageTable = (uintptr_t) &kernel_paging_table;
		uint32_t kernelBuffer = kernel_module->mod_start;
		uint32_t kernelBufferEnd = kernel_module->mod_end;

		header = (ElfHeader *) kernelBuffer;
		kernel_start = header->entry;
		ElfProgramHeader *programHeaders = (ElfProgramHeader *) (kernelBuffer + header->programHeaderTable);
		uintptr_t programHeaderEntrySize = header->programHeaderEntrySize;

		for (uintptr_t i = 0; i < header->programHeaderEntries; i++) {
			ElfProgramHeader *header = (ElfProgramHeader *) ((uint8_t *) programHeaders + programHeaderEntrySize * i);
			if (header->type != 1) continue;

			uintptr_t pagesToAllocate = (header->segmentSize + 0xfff) >> 12;
			uintptr_t physicalAddress = 0;

			for (uintptr_t j = 0; j < MAX_MEMORY_REGIONS; j++) {
				MemoryRegion *region = memoryRegions + j;
				if (!region->base) break;
				if (region->pages < pagesToAllocate) continue;
				// Prevent intersections with kernel buffer
				if (region->base <= kernelBufferEnd && region->base + (pagesToAllocate << 12) > kernelBuffer) {
					uint64_t new_base = (kernelBufferEnd + 0xfff) & ~0xfffULL;
					uint64_t new_pages = region->pages - (new_base - region->base);
					if (new_pages < pagesToAllocate) continue;
					// Sacrifice at most size of kernel buffer
					region->base = new_base;
					region->pages = new_pages;
				}
				physicalAddress = region->base;
				region->pages -= pagesToAllocate;
				region->base += pagesToAllocate << 12;
				break;
			}

			if (!physicalAddress) {
				// TODO Error handling.
				*((uint32_t *) kernel_params.graphics_info.bufferPhysical + 3) = 0xFFFF00FF;
				while (1);
			}

			ZeroMemory((void *) physicalAddress, header->segmentSize);
			CopyMemory((void *) physicalAddress, (void *) (kernelBuffer + header->fileOffset), header->dataInFile);

			for (uintptr_t j = 0; j < pagesToAllocate; j++, physicalAddress += 0x1000) {
				uint64_t virtualAddress = header->virtualAddress + j * K_PAGE_SIZE;
				physicalAddress &= 0xFFFFFFFFFFFFF000;
				virtualAddress  &= 0x0000FFFFFFFFF000;

				uintptr_t indexL4 = (virtualAddress >> (K_PAGE_BITS + ENTRIES_PER_PAGE_TABLE_BITS * 3)) & (ENTRIES_PER_PAGE_TABLE - 1);
				uintptr_t indexL3 = (virtualAddress >> (K_PAGE_BITS + ENTRIES_PER_PAGE_TABLE_BITS * 2)) & (ENTRIES_PER_PAGE_TABLE - 1);
				uintptr_t indexL2 = (virtualAddress >> (K_PAGE_BITS + ENTRIES_PER_PAGE_TABLE_BITS * 1)) & (ENTRIES_PER_PAGE_TABLE - 1);
				uintptr_t indexL1 = (virtualAddress >> (K_PAGE_BITS + ENTRIES_PER_PAGE_TABLE_BITS * 0)) & (ENTRIES_PER_PAGE_TABLE - 1);

				uint64_t *tableL4 = paging_table;

				if (!(tableL4[indexL4] & 1)) {
					tableL4[indexL4] = nextPageTable | 7;
					ZeroMemory((void *) nextPageTable, K_PAGE_SIZE);
					nextPageTable += K_PAGE_SIZE;
				}

				uint64_t *tableL3 = (uint64_t *) (tableL4[indexL4] & ~(K_PAGE_SIZE - 1));

				if (!(tableL3[indexL3] & 1)) {
					tableL3[indexL3] = nextPageTable | 7;
					ZeroMemory((void *) nextPageTable, K_PAGE_SIZE);
					nextPageTable += K_PAGE_SIZE;
				}

				uint64_t *tableL2 = (uint64_t *) (tableL3[indexL3] & ~(K_PAGE_SIZE - 1));

				if (!(tableL2[indexL2] & 1)) {
					tableL2[indexL2] = nextPageTable | 7;
					ZeroMemory((void *) nextPageTable, K_PAGE_SIZE);
					nextPageTable += K_PAGE_SIZE;
				}

				uint64_t *tableL1 = (uint64_t *) (tableL2[indexL2] & ~(K_PAGE_SIZE - 1));
				uintptr_t value = physicalAddress | 3;
				tableL1[indexL1] = value;
			}
		}
	}


	// Back to asm.
}
