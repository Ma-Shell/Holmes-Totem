#include <stdio.h>
#include "pe.c"

void read(void* ptr, size_t num, FILE* f)
{
	size_t r = 0;
	while(num > 0)
	{
		r = fread(ptr, 1, num, f);
		num -= r;
		ptr += r;
	}
}

void main()
{
	FILE* f = fopen("/home/marcel/work/dangerous/VirusShare_6673b460a6fc491afa9efd6cb0c922a1", "rb");
	if(!f)
	{
		printf("File does not exist!\n");
		exit(-1);
	}

	struct DOS_hdr dh;
	read(&dh, sizeof(struct DOS_hdr), f);
	
	print_DOS_hdr(&dh);

	fseek(f, dh.e_lfanew, 0);

	struct COFF_hdr ch;
	read(&ch, sizeof(struct COFF_hdr), f);
	print_COFF_hdr(&ch);

	struct PEOPT_hdr poh;
	read(&poh, sizeof(struct PEOPT_hdr), f);
	printf("Entry Point: %x\n", poh.address_entry_point);
	fclose(f);
}