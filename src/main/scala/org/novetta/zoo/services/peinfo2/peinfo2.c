#include <sys/types.h>
#include <stdio.h>
#include "pe.c"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

void parse_DOS_hdr(struct DOS_hdr* dh)
{
	if(dh->signature.ui16 != 0x5a4d) //MZ
	{
		printf("ERROR: DOS-Header signature mismatch! Should be MZ, but is %.2s\n", dh->signature);
		exit(-1);
	}
	print_DOS_hdr(dh);
}

void parse_COFF_hdr(struct COFF_hdr* ch)
{
	if(ch->pe_signature.ui32 != 0x00004550) //PE\x00\x00
	{
		printf("ERROR: PE signature mismatch! Should be PE, but is %.4s\n", ch->pe_signature.c);
		exit(-1);
	}
	print_COFF_hdr(ch);
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

void parse(void* m, size_t file_size)
{
	struct DOS_hdr* dh = m;
	parse_DOS_hdr(dh);
	if(dh->e_lfanew > file_size)
	{
		printf("Invalid e_lfanew: 0x%04x\n", dh->e_lfanew);
		exit(-1);
	}

	struct COFF_hdr* ch = m + dh->e_lfanew;
	parse_COFF_hdr(ch);

	struct PEOPT_hdr* poh = ((void*)ch)+sizeof(struct COFF_hdr);
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
		//TODO: parse sections
		printf("%s: %08x\n", directory_entry_types[i], offset-m);
		dds[i] = offset;
		printf("RVA: %08x, Size: %08x\n", dds[i]->virtual_address, dds[i]->size);
		offset += sizeof(struct PEOPT_data_directory);
	}

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

	void* m = mmap(NULL, file_size, PROT_READ, MAP_SHARED, f, 0);
	close(f);
	parse(m, file_size);
	munmap(m, file_size);
}