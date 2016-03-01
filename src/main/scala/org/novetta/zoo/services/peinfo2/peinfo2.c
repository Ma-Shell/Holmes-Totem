#include <sys/types.h>
#include <stdio.h>
#include "pe.c"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
typedef uint8_t bool;
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

void parse_PEOPT_hdr(struct PEOPT_hdr* poh)
{
	print_PEOPT_hdr(poh);
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
	bool x64 = poh->signature == 523;
	parse_PEOPT_hdr(poh);
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