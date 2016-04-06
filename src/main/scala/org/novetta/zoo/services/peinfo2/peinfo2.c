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
struct IMAGE_SECTION_hdr** parse_sections(void* offset, struct PE_file* pe);

int64_t max(int64_t a, int64_t b)
{
	if(a > b)
		return a;
	else
		return b;
}

void append_warning(struct PE_file* pe, char* warning, ...)
{
	va_list ap;
	va_start(ap, warning);
	size_t size = vsnprintf(NULL, 0, warning, ap);
	va_end(ap);
	char* a = malloc(size + 1);
	va_start(ap, warning);
	vsprintf(a, warning, ap);
	va_end(ap);

	append(&pe->warnings, a);
}

bool power_of_two(size_t val)
{
	return val != 0 && (val & (val-1)) == 0;
}

size_t adjust_file_alignment(struct PE_file* pe, size_t val)
{
	static bool file_alignment_warning = false;
	if (pe->file_alignment > 0x200) 
	{
		//If it's not a power of two, report it:
		if((!power_of_two(pe->file_alignment)) && (!file_alignment_warning))
		{
			append_warning(pe, "If FileAlignment > 0x200 it should be a power of 2. Value: %x", pe->file_alignment);
			file_alignment_warning = true;
		}
	}
	if(pe->file_alignment < 0x200)
		return val;
	return (val / 0x200) * 0x200;
}

size_t adjust_section_alignment(struct PE_file* pe, size_t val)
{
	static bool section_alignment_warning = false;
	//TODO
	if(pe->file_alignment < 0x200)
	{
		if((pe->file_alignment != pe->section_alignment) && (!section_alignment_warning))
		{
			append_warning(pe, "If FileAlignment(%x) < 0x200 it should equal SectionAlignment(%x)", pe->file_alignment, pe->section_alignment);
			section_alignment_warning = true;
		}
	}
	if(pe->section_alignment < 0x1000) //page size
		pe->section_alignment = pe->file_alignment;

	// 0x200 is the minimum valid FileAlignment according to the documentation
	// although ntoskrnl.exe has an alignment of 0x80 in some Windows versions

	if (pe->section_alignment && (val % pe->section_alignment))
		return pe->section_alignment * (val / pe->section_alignment);
	return val;
}

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

/*
Checks whether the section contains the address provided.
*/
bool contains_rva(struct PE_file* pe, struct IMAGE_SECTION_hdr* sect, uint32_t rva, uint32_t next_section_virtual_address)
{
	// Check if the SizeOfRawData is realistic. If it's bigger than the size of the whole
	// PE file minus the start address of the section it could be either truncated or the
	// SizeOfRawData contain a misleading value. In either of those cases we take the VirtualSize
	size_t size;
	if(pe->file_size - adjust_file_alignment(pe, sect->pointer_to_raw_data) < sect->size_raw_data)
		// PECOFF documentation v8 says:
        // VirtualSize: The total size of the section when loaded into memory.
        // If this value is greater than SizeOfRawData, the section is zero-padded.
        // This field is valid only for executable images and should be set to zero
        // for object files.
		size = sect->misc.virtual_size;
	else
		size = max(sect->size_raw_data, sect->misc.virtual_size);

	uint32_t virtual_address_adj = adjust_section_alignment(pe, sect->virtual_address);
	// Check whether there's any section after the current one that starts before the
	// calculated end for the current one, if so, cut the current section's size
	// to fit in the range up to where the next section starts.
	if((next_section_virtual_address != 0) && 
	  (next_section_virtual_address > sect->virtual_address) &&
      (virtual_address_adj + size > next_section_virtual_address))
    {
    	size = next_section_virtual_address - virtual_address_adj;
    }
	return (virtual_address_adj <= rva) && (rva < virtual_address_adj + size);
}

struct IMAGE_SECTION_hdr* get_section_by_rva(struct PE_file* pe, uint32_t rva)
{
	size_t i = 0;
	for(i = 0; i < pe->coff->number_sections; i++)
	{
		if(contains_rva(pe, pe->sects[i], rva, i < pe->coff->number_sections-1?pe->sects[i]->virtual_address:0))
			return pe->sects[i];
	}
	return NULL;
}

uint32_t get_section_offset_from_rva(struct PE_file* pe, struct IMAGE_SECTION_hdr* s, uint32_t rva)
{
	return (rva - 
		adjust_section_alignment(
			pe,
			s->virtual_address)) +
		adjust_file_alignment(
			pe,
			s->pointer_to_raw_data);
}

/*
Get the file offset corresponding to this RVA.

Given a RVA, this method will find the section where
the data lies and return the offset within the file.
*/
uint32_t get_offset_from_rva(struct PE_file* pe, uint32_t rva)
{
	struct IMAGE_SECTION_hdr* s = get_section_by_rva(pe, rva);
	if(s == NULL)
	{
		// If not found within a section assume it might point to overlay
		// data or otherwise data present but not contained in any section.
		// In those cases the RVA should equal the offset
		if(rva < pe->file_size)
			return rva;

		//TODO:
		// raise PEFormatError, 'data at RVA can\'t be fetched. Corrupt header?'
		return 0;
		//exit(-1);
	}
	return get_section_offset_from_rva(pe, s, rva);
}

/*
Get data chunk from a section.

Allows to query data from the section by passing the
addresses where the PE file would be loaded by default.
It is then possible to retrieve code and data by its real
addresses as it would be if loaded.
*/
void* get_section_data(struct PE_file* pe, struct IMAGE_SECTION_hdr* s, uint32_t start)
{
	size_t pointer_to_raw_data_adj = adjust_file_alignment(pe, s->pointer_to_raw_data);
	size_t virtual_address_adj = adjust_section_alignment(pe, s->virtual_address);

	size_t offset;
	if(!start)
		offset = pointer_to_raw_data_adj;
	else
		offset = (start - virtual_address_adj) + pointer_to_raw_data_adj;
	// PointerToRawData is not adjusted here as we might want to read any possible extra bytes
	// that might get cut off by aligning the start (and hence cutting something off the end)
	return pe->map + offset;
}

/*
Get data regardless of the section where it lies on.
*/
void* get_data(struct PE_file* pe, uint32_t rva)
{
	struct IMAGE_SECTION_hdr* s = get_section_by_rva(pe, rva);
	if(!s)
	{
		//TODO!!!
		return NULL;
	}
	return get_section_data(pe, s, rva);
}

uint8_t get_directory_entry_index(const char* name)
{
	printf("%s\n", name);
	for(uint8_t i = 0; i < sizeof(DIRECTORY_ENTRY_Strings)/sizeof(const char*); i++)
	{
		if(!strcmp(DIRECTORY_ENTRY_Strings[i], name))
			return i;
	}
	printf("DIRECTORY INDEX %s NOT FOUND!\n", name);
	exit(-1);
}

struct list* get_import_table(struct PE_file* pe, uint32_t rva, uint32_t max_length)
{
	struct list* table = calloc(sizeof(struct list*), 1);
	// We need the ordinal flag for a simple heuristic
	// we're implementing within the loop
	uint64_t ordinal_flag;
	uint8_t size;
	if(pe->is_x64)
	{
		ordinal_flag = IMAGE_ORDINAL_FLAG64;
		size = 8;
	}
	else
	{
		ordinal_flag = IMAGE_ORDINAL_FLAG;
		size = 4;
	}
	uint32_t MAX_ADDRESS_SPREAD = 0x8000000; // 128*2**20 = 64 MB
	uint8_t MAX_REPEATED_ADDRESS = 15;
	uint8_t repeated_address = 0;
	struct list addresses_of_data_set_64 = {NULL, NULL};
	struct list addresses_of_data_set_32 = {NULL, NULL};
	uint32_t start_rva = rva;
	while(rva)
	{
		if(rva >= start_rva + max_length)
		{
			append_warning(pe, "Error parsing the import table. Entries go beyond bounds.");
			break;
		}
		// if we see too many times the same entry we assume it could be
		// a table containing bogus data (with malicious intent or otherwise)
		if (repeated_address >= MAX_REPEATED_ADDRESS)
		{
			clear(table);
			goto CLEANUP;
		}

		// if the addresses point somewhere but the difference between the highest
		// and lowest address is larger than MAX_ADDRESS_SPREAD we assume a bogus
		// table as the addresses should be contained within a module
		if(list_extremum(&addresses_of_data_set_32, &comp_max) - list_extremum(&addresses_of_data_set_32, &comp_min) > MAX_ADDRESS_SPREAD)
		{
			clear(table);
			goto CLEANUP;
		}
		if(list_extremum(&addresses_of_data_set_64, &comp_max) - list_extremum(&addresses_of_data_set_64, &comp_min) > MAX_ADDRESS_SPREAD)
		{
			clear(table);
			goto CLEANUP;
		}

		uint64_t thunk_data;
		bool failed = false;
		if(pe->is_x64)
		{
			thunk_data = *((uint64_t*)get_data(pe, rva));
		}
		else
		{
			thunk_data = *((uint32_t*)get_data(pe, rva));
		}
		// Check if the AddressOfData lies within the range of RVAs that it's
        // being scanned, abort if that is the case, as it is very unlikely
        // to be legitimate data.
        // Seen in PE with SHA256:
        // 5945bb6f0ac879ddf61b1c284f3b8d20c06b228e75ae4f571fa87f5b9512902c
		if((thunk_data >= start_rva) && (thunk_data <= rva))
		{
			append_warning(pe, "Error parsing the import table. AddressOfData overlaps with THUNK_DATA for THUNK at RVA 0x%x", rva);
			break;
		}
		if(thunk_data != 0)
		{
			// If the entry looks like could be an ordinal...
			if (thunk_data & ordinal_flag)
			{
				// but its value is beyond 2^16, we will assume it's a
				// corrupted and ignore it altogether
				if (thunk_data & 0x7fffffff > 0xffff)
				{
					clear(table);
					goto CLEANUP;
				}
			} // and if it looks like it should be an RVA
			else
			{
				// keep track of the RVAs seen and store them to study their
				// properties. When certain non-standard features are detected
				// the parsing will be aborted
				if(list_contains(&addresses_of_data_set_32, thunk_data) ||
				   list_contains(&addresses_of_data_set_64, thunk_data))
				{
					repeated_address += 1;
				}
				if(thunk_data >= 0x100000000) //(2^32)
					append(&addresses_of_data_set_64, thunk_data);
				else
					append(&addresses_of_data_set_32, thunk_data);
			}
		}
		else
			break;

		rva += size;
		append(table, thunk_data);
	}

	CLEANUP:
		clear(&addresses_of_data_set_32);
		clear(&addresses_of_data_set_64);
		return table;
}

uint16_t* get_word_from_data(void* data, uint32_t offset)
{
	return (uint16_t*) (data + (offset*2)); //TODO?
}

char* get_string_at_rva(struct PE_file* pe, uint32_t rva)
{
	if (!rva)
		return NULL;
	struct IMAGE_SECTION_hdr* s = get_section_by_rva(pe, rva);
	if (!s)
		return pe->map + rva;
	
	return get_section_data(pe, s, rva);
}

/*
Parse the imported symbols.
*/
struct list* parse_imports(struct PE_file* pe, uint32_t original_first_thunk, uint32_t first_thunk, uint32_t forwarder_chain, uint32_t max_length)
{
	struct list* imported_symbols = calloc(sizeof(struct list*), 1);
	// Import Lookup Table. Contains ordinals or pointers to strings.
	struct list* ilt = get_import_table(pe, original_first_thunk, max_length);
	// Import Address Table. May have identical content to ILT if
	// PE file is not bounded, Will contain the address of the
	// imported symbols once the binary is loaded or if it is already
	// bound.
	struct list* iat = get_import_table(pe, first_thunk, max_length);

	// Would crash if IAT or ILT were NULL
	if((!ilt || !(ilt->head)) && (!iat || !(iat->head)))
	{
		clear_and_delete_elements(imported_symbols);
		goto CLEANUP;
	}
	struct list* table = NULL;
	if(ilt)
		table = ilt;
	else if (iat)
		table = iat;
	else
		return NULL; //TODO: cleanup?

	uint8_t imp_offset = 4;
	uint64_t address_mask = 0x7fffffff;
	uint64_t ordinal_flag = IMAGE_ORDINAL_FLAG;
	if(pe->is_x64)
	{
		imp_offset = 8;
		address_mask = 0x7fffffffffffffff;
		ordinal_flag = IMAGE_ORDINAL_FLAG64;
	}
	uint8_t num_invalid = 0;
	uint8_t idx = 0;
	bool import_by_ordinal;
	struct list_elem* current = table->head;
	uint64_t imp_ord;
	uint16_t imp_hint;
	uint64_t hint_name_table_rva;
	uint32_t name_offset;
	char* imp_name;
	while(current)
	{
		imp_ord = NULL;
		imp_hint = NULL;
		imp_name = NULL;
		name_offset = NULL;
		hint_name_table_rva = NULL;
		if(current->data)
		{
			// If imported by ordinal, we will append the ordinal number
			if((uint64_t)current->data & ordinal_flag) //TODO...
			{
				import_by_ordinal = true;
				imp_ord = (uint64_t)current->data & 0xffff; //TODO...
			}
			else
			{
				import_by_ordinal = false;
				hint_name_table_rva = (uint64_t)current->data & address_mask; //TODO...
				void* data = get_data(pe, hint_name_table_rva);
				// Get the Hint
				imp_hint = *get_word_from_data(data, 0);
				imp_name = get_string_at_rva(pe, current->data+2);
				/* TODO!!!
				if(!is_valid_function_name(imp_name))
					imp_name = "*invalid*";
				*/
				printf("%s\n", imp_name);
				name_offset = get_offset_from_rva(pe, current->data+2);
			}
			//TODO!!! CONTINUE HERE!!!
		}

		current = current->next;
	}

	//TODO: clear and free ilt, iat, imported_symbols...
	//TODO...
	CLEANUP:
		return imported_symbols;
}

/*
Walk and parse the imiport directory.
*/
void parse_import_directory(struct PE_file* pe, uint32_t rva, uint32_t size)
{
	while(true)
	{
		// TODO! Check validity...
		uint8_t error_count = 0;
		uint32_t file_offset = get_offset_from_rva(pe, rva);
		pe->import_descriptor = pe->map + file_offset;

		// If the structure is all zeros, we reached the end of the list
		if((pe->import_descriptor->original_first_thunk == 0) &&
           (pe->import_descriptor->time_date_stamp == 0) &&
           (pe->import_descriptor->forwarder_chain == 0) &&
           (pe->import_descriptor->name == 0) &&
           (pe->import_descriptor->first_thunk == 0))
        {
        	break;
        }
        printf("import name: %s\n", pe->map + get_offset_from_rva(pe, pe->import_descriptor->name));

        rva += sizeof(struct IMPORT_DESCRIPTOR);

        // If the array of thunk's is somewhere earlier than the import
        // descriptor we can set a maximum length for the array. Otherwise
        // just set a maximum length of the size of the file
        uint32_t max_len = pe->file_size - file_offset;
        if((rva > pe->import_descriptor->original_first_thunk) || (rva > pe->import_descriptor->first_thunk))
        	max_len = max((int64_t)rva - pe->import_descriptor->original_first_thunk, (int64_t)rva - pe->import_descriptor->first_thunk);
        parse_imports(pe, pe->import_descriptor->original_first_thunk, pe->import_descriptor->first_thunk, pe->import_descriptor->forwarder_chain, max_len);
        //TODO...
	}

}

/*
Parse the export directory.
Given the RVA of the export directory, it will process all its entries.
*/
void parse_export_directory(struct PE_file* pe, uint32_t rva, uint32_t size)
{
	// TODO!

}

void parse_resources_directory()
{
	//TODO!
}

void parse_debug_directory(struct PE_file* pe, uint32_t rva, uint32_t size)
{
	pe->num_debug_directories = size/sizeof(struct DEBUG_DIRECTORY);
	pe->debug_directories = pe->map + get_offset_from_rva(pe, rva);
	printf("DEBUG:::%08x, %08x\n", get_offset_from_rva(pe, rva), rva);
	printf("%i\n", pe->num_debug_directories);
	printf("%08x\n", pe->debug_directories[0].pointer_to_raw_data);
}

void parse_relocations_directory()
{
	//TODO!
}

void parse_directory_tls()
{
	//TODO!
}

void parse_directory_load_config()
{
	//TODO!
}

void parse_delay_import_directory()
{
	//TODO!
}

void parse_directory_bound_imports()
{
	//TODO!
}

/*
Parse and process the PE file's data directories.
*/
void parse_data_directories(struct PE_file* pe)
{
    char* directory_parsing[9] = 
    {
        "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", 
        "IMAGE_DIRECTORY_ENTRY_RESOURCE", "IMAGE_DIRECTORY_ENTRY_DEBUG",
        "IMAGE_DIRECTORY_ENTRY_BASERELOC", "IMAGE_DIRECTORY_ENTRY_TLS",
        "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"
    };
    void (*directory_parsing_functions[])() = 
    {
    	&parse_import_directory, &parse_export_directory,
    	&parse_resources_directory, &parse_debug_directory,
        &parse_relocations_directory, &parse_directory_tls,
        &parse_directory_load_config, &parse_delay_import_directory,
        &parse_directory_bound_imports
    };

    for(uint8_t i = 0; i<sizeof(directory_parsing)/sizeof(char*); i++)
    {
    	uint8_t index = get_directory_entry_index(directory_parsing[i]);
    	printf("%d\n", index);
    	struct PEOPT_data_directory* dir_entry = pe->data_directories[index];
    	if(dir_entry->virtual_address != 0)
    	{
   			directory_parsing_functions[i](pe, dir_entry->virtual_address, dir_entry->size);
   			//TODO: 
   			/*
   			if value:
                       setattr(self, entry[0][6:], value)
            */
    	}	
    }
}

/*
Parses the rich header
see http://www.ntcore.com/files/richsign.htm for more information

Structure:
00 DanS ^ checksum, checksum, checksum, checksum
10 Symbol RVA ^ checksum, Symbol size ^ checksum...
...
XX Rich, checksum, 0, 0,...
*/
void parse_rich_header(struct PE_file* pe)
{
	pe->rich = malloc(sizeof(struct RICH_hdr));
	pe->rich->start = pe->map + 0x80;
	uint32_t cs = pe->rich->start->checksum[0];

	// the checksum should be present 3 times after the DanS signature
	if (!((cs == pe->rich->start->checksum[1]) &&
		  (cs == pe->rich->start->checksum[2]) &&
		  ((cs ^ pe->rich->start->DanS) == 0x536E6144))) // 'DanS'
	{
		//printf("invalid rich %08x -> %08x, %08x, %08x, %08x\n", pe->rich->start->DanS, pe->rich->start->DanS ^ cs, cs, pe->rich->start->checksum[1],pe->rich->start->checksum[2]);
		free(pe->rich);
		pe->rich = NULL;
		return;
	}
	pe->rich->entries = pe->map + 0x80 + 4*4;
	//TODO: FIXME: Pefile only checks a maximum of 28 values, should we do more???
	for(uint8_t i = 0; i < 28; i++)
	{
		// Stop until the Rich footer signature is found
		//printf("%08x\n", pe->rich->entries[i].rich);
		if(pe->rich->entries[i].rich == 0x68636952) // 'Rich'
		{
			// it should be followed by the checksum
			if(*(&pe->rich->entries[i].rich + 1) != cs)
				append_warning(pe, "Rich Header corrupted");
			//printf("found rich-signature at %d\n", i);
			return;
		}
		//header values come by pairs
		pe->rich->num_entries += 1;
	}
}

void parse(struct PE_file* pe)
{
	pe->warnings.head = NULL;
	pe->warnings.tail = NULL;

	pe->dos = pe->map;
	parse_DOS_hdr(pe->dos);
	if(pe->dos->e_lfanew > pe->file_size)
	{
		printf("Invalid e_lfanew: 0x%04x\n", pe->dos->e_lfanew);
		exit(-1);
	}

	pe->coff = pe->map + pe->dos->e_lfanew;
	parse_COFF_hdr(pe->coff);

	pe->peopt.x32 = ((void*)pe->coff)+sizeof(struct COFF_hdr);
	pe->is_x64 = parse_PEOPT_hdr(pe->peopt.x32);
	if(pe->is_x64)
	{
		pe->section_alignment = pe->peopt.x64->section_alignment;
		pe->file_alignment = pe->peopt.x64->file_alignment;
	}
	else
	{
		pe->section_alignment = pe->peopt.x32->section_alignment;
		pe->file_alignment = pe->peopt.x32->file_alignment;	
	}
	
	int32_t entrypoint = pe->peopt.x32->address_entry_point;

	void* offset = ((void*)pe->peopt.x32) + sizeof(struct PEOPT_hdr);
	size_t number_rva_and_sizes = pe->peopt.x32->number_rva_and_sizes;
	if(pe->is_x64)
	{
		offset = ((void*)pe->peopt.x64) + sizeof(struct PEOPTx64_hdr);
		number_rva_and_sizes = pe->peopt.x64->number_rva_and_sizes;
		entrypoint = pe->peopt.x64->address_entry_point;
	}

	size_t i = 0;
	for(i = 0; i < number_rva_and_sizes & 0x7fffffff; i++)
	{
		printf("%s: %08x\n", DIRECTORY_ENTRY_Strings[i], offset-pe->map);
		pe->data_directories[i] = offset;
		printf("RVA: %08x, Size: %08x\n", pe->data_directories[i]->virtual_address, pe->data_directories[i]->size);
		offset += sizeof(struct PEOPT_data_directory);
	}
	pe->sects = parse_sections(offset, pe);
	offset += pe->coff->number_sections*sizeof(struct IMAGE_SECTION_hdr);
	
	uint32_t lowest_section_offset = pe->sects[0]->pointer_to_raw_data;
	for(i = 0; i < pe->coff->number_sections; i++)
	{
		if((pe->sects[i]->pointer_to_raw_data > 0) && (pe->sects[i]->pointer_to_raw_data < lowest_section_offset))
		{
			//TODO: Watch out file alignment
			lowest_section_offset = pe->sects[i]->pointer_to_raw_data;
		}
	}
	size_t header_size;
	if(lowest_section_offset < (offset - pe->map))
		header_size = offset - pe->map;
	else
		header_size = lowest_section_offset;

	//Check whether the entry point within a section
	if(get_section_by_rva(pe, entrypoint) != NULL)
	{
		//Check whether the entry point lies within the file
		int32_t ep_offset = get_offset_from_rva(pe, entrypoint);
		if(ep_offset > pe->file_size)
		{
			append_warning(pe, "Possibly corrupt file. AddressOfEntryPoint lies outside the file. AddressOfEntryPoint: 0x%x\n", entrypoint);
		}
	}
	else
	{
		append_warning(pe, "AddressOfEntryPoint lies outside the sections' boundaries. AddressOfEntryPoint: 0x%x\n", entrypoint);
	}

	parse_data_directories(pe);
	parse_rich_header(pe);
	if(pe->rich)
	{
		/*
		//TODO: self.RICH_HEADER = RichHeader()
                self.RICH_HEADER.checksum = rich_header.get('checksum', None)
                self.RICH_HEADER.values = rich_header.get('values', None)
                */
        printf("%i entries\n", pe->rich->num_entries);
	}

	if(pe->rich)
		free(pe->rich);
	free(pe->sects);
	struct list_elem* warning = pe->warnings.head;
	while(warning)
	{
		printf("%s", warning->data);
		warning = warning->next;
	}
	clear(&pe->warnings);
}

//TODO
bool is_driver()
{
	return false;
}

void print_section_flags(struct IMAGE_SECTION_hdr* sect, size_t i, struct PE_file* pe)
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
			append_warning(pe, "Suspicious flags set for section %d. Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.", i);
		}
	}

}

int compare_by_rva(const void* a, const void* b)
{
	const struct IMAGE_SECTION_hdr* a1 = *(void**)a;
	const struct IMAGE_SECTION_hdr* b1 = *(void**)b;
	//printf("%s: %x vs %s: %x\n", a1->name, a1->virtualaddress, b1->name, b1->virtualaddress);
	return (a1->virtual_address - b1->virtual_address);
}

struct IMAGE_SECTION_hdr** parse_sections(void* offset, struct PE_file* pe)
{
	struct IMAGE_SECTION_hdr** sect = malloc(pe->coff->number_sections * sizeof(struct IMAGE_SECTION_hdr*));
	for(size_t i = 0; i < pe->coff->number_sections; i++)
	{
		int8_t MAX_SIMULATNEOUS_ERRORS = 3;
		sect[i] = offset;
		offset += sizeof(struct IMAGE_SECTION_hdr);
		//TODO: check whether all null-bytes
		//TODO: check length
		if(sect[i]->size_raw_data + sect[i]->pointer_to_raw_data > pe->file_size)
		{
			MAX_SIMULATNEOUS_ERRORS--;
			append_warning(pe, "Error parsing section %d. SizeOfRawData is larger than file.", i);
		}
		//TODO: further checks
		if(sect[i]->misc.physical_address > 0x10000000) //??
		{
			MAX_SIMULATNEOUS_ERRORS--;
			append_warning(pe, "Suspicious value found parsing section %d. VirtualSize is extremely large > 256MiB.", i);
		}
		printf("%s: %p\n", (sect[i]->name), sect[i]->virtual_address);
		if(MAX_SIMULATNEOUS_ERRORS <= 0)
		{
			printf("Too many warnings parsing section. Aborting.\n");
			break;
		}
		print_section_flags(sect[i], i, pe);
	}
	//sort the sections by their virtual addresses
	qsort (&sect[0], pe->coff->number_sections, sizeof(struct IMAGE_SECTION_hdr*), compare_by_rva);
	return sect;
}

void main(int argc, char* argv[])
{
	struct PE_file pe;
	int f = open(argv[1], O_RDONLY);
	if(!f)
	{
		printf("Could not open file %s\n", argv[1]);
		exit(-1);
	}
	
	pe.file_size = lseek(f, 0, SEEK_END);
	lseek(f, 0, SEEK_SET);
	printf("size is %i\n", pe.file_size);

	pe.map = mmap(NULL, pe.file_size, PROT_READ, MAP_SHARED, f, 0);
	close(f);
	parse(&pe);
	munmap(pe.map, pe.file_size);
}