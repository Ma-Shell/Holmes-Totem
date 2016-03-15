#include <sys/types.h>
#include <stdio.h>
#include "pe.c"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include "list.h"
struct IMAGE_SECTION_hdr** parse_sections(void* offset, struct COFF_hdr* coff, size_t file_size, struct list* warnings);

void parse_DOS_hdr(struct DOS_hdr* dos)
{
	if(dos->signature.ui16 != 0x5a4d) //MZ
	{
		printf("ERROR: DOS-Header signature mismatch! Should be MZ, but is %.2s\n", dos->signature);
		exit(-1);
	}
	print_DOS_hdr(dos);
}

void parse_COFF_hdr(struct COFF_hdr* coff)
{
	if(coff->pe_signature.ui32 != 0x00004550) //PE\x00\x00
	{
		printf("ERROR: PE signature mismatch! Should be PE, but is %.4s\n", coff->pe_signature.c);
		exit(-1);
	}
	print_COFF_hdr(coff);
}

bool parse_PEOPT_hdr(struct PEOPT_hdr* poh)
{

	//TODO: PEOPT might be shorter...

	bool x64 = false;
	if(poh->signature == 267)
	{
		// Windows 8 specific check
		if(poh->address_entry_point < poh->size_headers)
			printf("SizeOfHeaders is smaller than AddressOfEntryPoint: this file cannot run under Windows 8");
		if(poh->number_rva_and_sizes > 0x10)
			printf("Suspicious NumberOfRvaAndSizes in the Optional Header. Normal values are never larger than 0x10, the value is: 0x%x", poh->number_rva_and_sizes);

	}
	else if (poh->signature == 523)
	{
		x64 = true;
		struct PEOPTx64_hdr* pohx64 = (struct PEOPTx64_hdr*) poh;

		// Windows 8 specific check
		if(pohx64->address_entry_point < pohx64->size_headers)
			printf("SizeOfHeaders is smaller than AddressOfEntryPoint: this file cannot run under Windows 8");
		if(pohx64->number_rva_and_sizes > 0x10)
			printf("Suspicious NumberOfRvaAndSizes in the Optional Header. Normal values are never larger than 0x10, the value is: 0x%x", pohx64->number_rva_and_sizes);
	}
	else
	{
		printf("ERROR: PEOPT header signature should be either 267 or 523, but is %d", poh->signature);
		exit(-1);
	}

	print_PEOPT_hdr(poh);
	return x64;
}

void parse(void* map, size_t file_size)
{
	struct list warnings = {NULL, NULL};

	struct DOS_hdr* dos = map;
	parse_DOS_hdr(dos);
	if(dos->e_lfanew > file_size)
	{
		printf("Invalid e_lfanew: 0x%04x\n", dos->e_lfanew);
		exit(-1);
	}

	struct COFF_hdr* coff = map + dos->e_lfanew;
	parse_COFF_hdr(coff);

	struct PEOPT_hdr* poh = ((void*)coff)+sizeof(struct COFF_hdr);
	struct PEOPTx64_hdr* pohx64 = (struct PEOPTx64_hdr*) poh;
	bool x64 = parse_PEOPT_hdr(poh);

	void* offset = ((void*)poh) + sizeof(struct PEOPT_hdr);
	size_t number_rva_and_sizes = poh->number_rva_and_sizes;
	if(x64)
	{
		offset = ((void*)pohx64) + sizeof(struct PEOPTx64_hdr);
		number_rva_and_sizes = pohx64->number_rva_and_sizes;
	}

	struct PEOPT_data_directory* dds[16];
	size_t i = 0;
	for(i = 0; i < number_rva_and_sizes & 0x7fffffff; i++)
	{
		printf("%s: %08x\n", directory_entry_types[i], offset-map);
		dds[i] = offset;
		printf("RVA: %08x, Size: %08x\n", dds[i]->virtual_address, dds[i]->size);
		offset += sizeof(struct PEOPT_data_directory);
	}
	struct IMAGE_SECTION_hdr** sects = parse_sections(offset, coff, file_size, &warnings);
	offset += coff->number_sections*sizeof(struct IMAGE_SECTION_hdr);
	
	free(sects);
	struct list_elem* warning = warnings.head;
	while(warning)
	{
		printf("%s", warning->data);
		warning = warning->next;
	}
	clear(&warnings);
}

//TODO
bool is_driver()
{
	return false;
}

void append_warning(struct list* warnings, char* warning, ...)
{
	va_list ap;
	va_start(ap, warning);
	size_t size = vsnprintf(NULL, 0, warning, ap);
	va_end(ap);
	char* a = malloc(size + 1);
	va_start(ap, warning);
	vsprintf(a, warning, ap);
	va_end(ap);

	append(warnings, a);
}

void print_section_flags(struct IMAGE_SECTION_hdr* sect, size_t i, struct list* warnings)
{
	bool write_perm = false;
	bool execute_perm = false;
	for(size_t j = 0; j < sizeof(SECTION_CHARACTERISTICS_Vals) / sizeof(uint32_t); j++)
	{
		if(sect->characteristics & SECTION_CHARACTERISTICS_Vals[j])
		{
			printf("%s\n", SECTION_CHARACTERISTICS_Strings[j]);
			if(!strcmp(SECTION_CHARACTERISTICS_Strings[j] + 10, "WRITE"))
				write_perm = true;
			else if(!strcmp(SECTION_CHARACTERISTICS_Strings[j] + 10, "EXECUTE"))
				execute_perm = true;
		}
	}
	if(write_perm && execute_perm)
	{
		// Drivers can legitimately have wx-PAGE section
		if(!((!strcmp(sect->name, "PAGE")) && is_driver()))
		{
			append_warning(warnings, "Suspicious flags set for section %d. Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.\n", i);
		}
	}

}

int compare_by_rva(const void* a, const void* b)
{
	const struct IMAGE_SECTION_hdr* a1 = *(void**)a;
	const struct IMAGE_SECTION_hdr* b1 = *(void**)b;
	//printf("%s: %x vs %s: %x\n", a1->name, a1->virtualaddress, b1->name, b1->virtualaddress);
	return (a1->virtualaddress - b1->virtualaddress);
}

struct IMAGE_SECTION_hdr** parse_sections(void* offset, struct COFF_hdr* coff, size_t file_size, struct list* warnings)
{
	struct IMAGE_SECTION_hdr** sect = malloc(coff->number_sections * sizeof(struct IMAGE_SECTION_hdr*));
	for(size_t i = 0; i < coff->number_sections; i++)
	{
		int8_t MAX_SIMULATNEOUS_ERRORS = 3;
		sect[i] = offset;
		offset += sizeof(struct IMAGE_SECTION_hdr);
		//TODO: check whether all null-bytes
		//TODO: check length
		if(sect[i]->size_raw_data + sect[i]->pointer_raw_data > file_size)
		{
			MAX_SIMULATNEOUS_ERRORS--;
			append_warning(warnings, "Error parsing section %d. SizeOfRawData is larger than file.\n", i);
		}
		//TODO: further checks
		if(sect[i]->misc.physical_address > 0x10000000) //??
		{
			MAX_SIMULATNEOUS_ERRORS--;
			append_warning(warnings, "Suspicious value found parsing section %d. VirtualSize is extremely large > 256MiB.", i);
		}
		printf("%s: %p\n", (sect[i]->name), sect[i]->virtualaddress);
		if(MAX_SIMULATNEOUS_ERRORS <= 0)
		{
			printf("Too many warnings parsing section. Aborting.\n");
			break;
		}
		print_section_flags(sect[i], i, warnings);
	}
	//sort the sections by their virtual addresses
	qsort (&sect[0], coff->number_sections, sizeof(struct IMAGE_SECTION_hdr*), compare_by_rva);
	return sect;
}

void main(int argc, char* argv[])
{
	int f = open(argv[1], O_RDONLY);
	if(!f)
	{
		printf("Could not open file %s\n", argv[1]);
		exit(-1);
	}
	size_t file_size;
	file_size = lseek(f, 0, SEEK_END);
	lseek(f, 0, SEEK_SET);
	printf("size is %i\n", file_size);

	void* map = mmap(NULL, file_size, PROT_READ, MAP_SHARED, f, 0);
	close(f);
	parse(map, file_size);
	munmap(map, file_size);
}