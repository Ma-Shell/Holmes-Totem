//https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "constants.h"
#include "list.h"

typedef int16_t DOS_hdr_short;
typedef uint16_t DOS_hdr_ptr;
typedef uint32_t DOS_hdr_long;

struct DOS_hdr
{
	union { char c[2]; uint16_t ui16; } signature;
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
	union {	char c[4]; uint32_t ui32; } pe_signature;
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
	PEOPT_long base_image;
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

void print_PEOPT_hdr(struct PEOPT_hdr* poh);

typedef int16_t PEOPTx64_short;
typedef int32_t PEOPTx64_long;
typedef int64_t PEOPTx64_qlong;
struct PEOPTx64_version
{
	PEOPTx64_short major;
	PEOPTx64_short minor;
};
typedef struct PEOPTx64_version PEOPTx64_version;

struct PEOPTx64_hdr
{
	PEOPTx64_short signature;
	char linker_version_major;
	char linker_version_minor;
	PEOPTx64_long size_code;
	PEOPTx64_long size_initialized_data;
	PEOPTx64_long size_uinitialized_data;
	PEOPTx64_long address_entry_point;
	PEOPTx64_long base_code;
	PEOPTx64_qlong base_image;
	PEOPTx64_long section_alignment;
	PEOPTx64_long file_alignment;
	PEOPTx64_version os_version;
	PEOPTx64_version img_version;
	PEOPTx64_version subsystem_version;
	PEOPTx64_long reserved;
	PEOPTx64_long size_image;
	PEOPTx64_long size_headers;
	PEOPTx64_long checksum;
	PEOPTx64_short subsystem;
	PEOPTx64_short dll_characteristics;
	PEOPTx64_qlong size_stack_reserve;
	PEOPTx64_qlong size_stack_commit;
	PEOPTx64_qlong size_heap_reserve;
	PEOPTx64_qlong size_heap_commit;
	PEOPTx64_long loader_flags;
	PEOPTx64_long number_rva_and_sizes;
};

struct PEOPT_data_directory
{
	PEOPT_long virtual_address;
	PEOPT_long size;
};

struct DEBUG_DIRECTORY
{
	uint32_t characteristics;
	uint32_t time_date_stamp;
	uint16_t major_version;
	uint16_t minor_version;
	uint32_t type;
	uint32_t size_of_data;
	uint32_t address_of_raw_data;
	uint32_t pointer_to_raw_data;
};

struct IMAGE_SECTION_hdr
{
	char name[8];
	union {	int32_t misc; uint32_t physical_address; uint32_t virtual_size; } misc;
	uint32_t virtual_address;
	uint32_t size_raw_data;
	uint32_t pointer_to_raw_data;
	uint32_t pointer_relocations;
	int32_t pointer_linenumbers;
	uint16_t numberRelocations;
	uint16_t number_lines;
	int32_t characteristics;
};

struct RICH_hdr_start
{
	uint32_t DanS;
	uint32_t checksum[3];
};

struct RICH_hdr_entry
{
	union { uint32_t compid; uint32_t rich; };
	uint32_t times_used;
};

struct RICH_hdr
{
	struct RICH_hdr_start* start;
	struct RICH_hdr_entry* entries; // this is an array with length num_entries
	uint16_t num_entries;
};

struct PE_file
{
	void* map;
	size_t file_size;
	uint32_t section_alignment;
	uint32_t file_alignment;
	struct DOS_hdr* dos;
	struct COFF_hdr* coff;
	union{ struct PEOPT_hdr* x32; struct PEOPTx64_hdr* x64; } peopt;
	struct PEOPT_data_directory* data_directories[16];
	struct DEBUG_DIRECTORY* debug_directories;
	uint16_t num_debug_directories;
	struct IMAGE_SECTION_hdr** sects;
	struct RICH_hdr* rich;
	bool is_x64;
	struct list warnings;
};