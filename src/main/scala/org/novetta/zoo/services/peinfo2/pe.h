//https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
#pragma once
#include <stdlib.h>
#include <stdint.h>
#include "constants.h"
typedef int16_t DOS_hdr_short;
typedef uint16_t DOS_hdr_ptr;
typedef uint32_t DOS_hdr_long;

struct DOS_hdr
{
	char signature[2];
	DOS_hdr_short lastsize;
	DOS_hdr_short nblocks;
	DOS_hdr_short nrelocs;
	DOS_hdr_short hdrsize;
	DOS_hdr_short minalloc;
	DOS_hdr_short maxalloc;
	DOS_hdr_ptr ss;
	DOS_hdr_ptr sp;
	DOS_hdr_short checksum;
	DOS_hdr_ptr ip;
	DOS_hdr_ptr cs;
	DOS_hdr_short relocpos;
	DOS_hdr_short noverlay;
	DOS_hdr_short reserved[4];
	DOS_hdr_short oem_id;
	DOS_hdr_short oem_info;
	DOS_hdr_short reserved2[10];
	DOS_hdr_long e_lfanew;
};

void print_DOS_hdr(struct DOS_hdr* dh);

typedef int16_t COFF_hdr_short;
typedef uint32_t COFF_hdr_long;
struct COFF_hdr
{
	char pe_signature[4];
	COFF_hdr_short machine;
	COFF_hdr_short number_sections;
	COFF_hdr_long time_date_stamp;
	COFF_hdr_long symbol_table_ptr;
	COFF_hdr_long number_symbols;
	COFF_hdr_short size_optional_hdr;
	COFF_hdr_short characteristics;
};

void print_COFF_hdr(struct COFF_hdr* ch);

typedef int16_t PEOPT_short;
typedef int32_t PEOPT_long;
struct PEOPT_version
{
	PEOPT_short major;
	PEOPT_short minor;
};
typedef struct PEOPT_version PEOPT_version;

struct PEOPT_hdr
{
	PEOPT_short signature;
	char linker_version_major;
	char linker_version_minor;
	PEOPT_long size_code;
	PEOPT_long size_initialized_data;
	PEOPT_long size_uinitialized_data;
	PEOPT_long address_entry_point;
	PEOPT_long base_code;
	PEOPT_long base_data;
	PEOPT_long image_base;
	PEOPT_long section_alignment;
	PEOPT_long file_alignment;
	PEOPT_version os_version;
	PEOPT_version img_version;
	PEOPT_version subsystem_version;
	PEOPT_long reserved;
	PEOPT_long size_image;
	PEOPT_long size_headers;
	PEOPT_long checksum;
	PEOPT_short subsystem;
	PEOPT_short dll_characteristics;
	PEOPT_long size_stack_reserve;
	PEOPT_long size_stack_commit;
	PEOPT_long size_heap_reserve;
	PEOPT_long size_heap_commit;
	PEOPT_long loader_flags;
	PEOPT_long number_rva_and_sizes;
};