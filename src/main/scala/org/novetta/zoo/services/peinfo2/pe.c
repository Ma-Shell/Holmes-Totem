#include "pe.h"
#include <time.h>
#include "constants.h"
void print_DOS_hdr(struct DOS_hdr* dh)
{
	size_t i = 0;

	printf("====== DOS ======\n");
	printf("sig: %.2s\n", dh->signature.c);
	printf("lastsize: %hx\n", dh->lastsize);
	printf("nblocks: %hx\n", dh->nblocks);
	printf("nrelocs: %hx\n", dh->nrelocs);
	printf("hdrsize: %hx\n", dh->hdrsize);
	printf("minalloc: %hx\n", dh->minalloc);
	printf("maxalloc: %hx\n", dh->maxalloc);
	printf("ss: %hx\n", dh->ss);
	printf("sp: %hx\n", dh->sp);
	printf("checksum: %hx\n", dh->checksum);
	printf("ip: %hx\n", dh->ip);
	printf("cs: %hx\n", dh->cs);
	printf("relocpos: %hx\n", dh->relocpos);
	printf("noverlay: %hx\n", dh->noverlay);
	printf("reserved:");
	for(i = 0; i < 4; i++)
		printf(" %hx", dh->reserved[i]);
	printf("\n");

	printf("oem_id: %hx\n", dh->oem_id);
	printf("oem_info: %hx\n", dh->oem_info);
	printf("reserved2:");
	for(i = 0; i < 10; i++)
		printf(" %hx", dh->reserved2[i]);
	printf("\n");

	printf("e_lfanew: %hx\n", dh->e_lfanew);
	printf("==================\n");
}

void print_COFF_hdr(struct COFF_hdr* ch)
{
	printf("====== COFF ======\n");
	printf("PE-signature: %.4s\n", ch->pe_signature.c);
	printf("machine: %hx\n", ch->machine);
	printf("number of sections: %hx\n", ch->number_sections);
	time_t t = ch->time_date_stamp;
	printf("time date stamp: %x: %s", ch->time_date_stamp, ctime(&t));
	printf("symbol table pointer: %x\n", ch->symbol_table_ptr);
	printf("number of symbols: %x\n", ch->number_symbols);
	printf("size of optional header: %hx\n", ch->size_optional_hdr);
	printf("characteristics: %hx\n", ch->characteristics);
	if(ch->characteristics & COFF_CHARACTERISTICS_EXECUTABLE)
		printf("Executable\n");
	if(ch->characteristics & COFF_CHARACTERISTICS_NON_RELOCATABLE)
		printf("Non-relocatable\n");
	if(ch->characteristics & COFF_CHARACTERISTICS_IS_DLL)
		printf("Is a DLL\n");
	//TODO: characteristics
	printf("===================\n");
}

void print_PEOPT_hdr(struct PEOPT_hdr* poh)
{
	if(poh->signature == 267)
	{
		printf("32 bit\n");
		printf("Entry Point: %x\n", poh->address_entry_point);
		printf("Number rva: %x\n", poh->number_rva_and_sizes);
	}
	else if (poh->signature == 523)
	{
		struct PEOPTx64_hdr* pohx64 = (struct PEOPTx64_hdr*) poh;
		printf("64 bit\n");
		printf("Entry Point: %x\n", pohx64->address_entry_point);
		printf("Number rva: %x\n", pohx64->number_rva_and_sizes);
	}
	else
	{
		printf("ERROR: PEOPT header signature should be either 267 or 523, but is %d", poh->signature);
		exit(-1);
	}
}