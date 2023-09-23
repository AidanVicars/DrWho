#pragma once

#include <string>
#include <unordered_map>

#include <windows.h>

#include "file.hpp"

enum class section_prot_flags : std::uint32_t
{
	rwx = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
	rx = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
	rw = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
	r = IMAGE_SCN_MEM_READ
};

class image
{
private:
	std::uint64_t image_base;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER sections;
	PIMAGE_EXPORT_DIRECTORY export_dir;
public:
	image(std::uint64_t base, PIMAGE_NT_HEADERS nt_header)
		: image_base(base), nt_header(nt_header)
	{
		sections = IMAGE_FIRST_SECTION(nt_header);
		export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(image_base + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}

	std::uint64_t get_export(const char* export_name)
	{
		return 0;
	}

	std::uint64_t get_entry_point()
	{
		return image_base + nt_header->OptionalHeader.AddressOfEntryPoint;
	}

};

namespace image_manager
{
	std::unordered_map<std::string, image*> mapped_images;

	std::uint32_t get_section_prot(PIMAGE_SECTION_HEADER section_header)
	{
		std::uint32_t section_chars = section_header->Characteristics;

		if(section_chars & (std::uint32_t)section_prot_flags::rwx)
		{
			return PAGE_EXECUTE_READWRITE;
		}
		else if (section_chars & (std::uint32_t)section_prot_flags::rw)
		{
			return PAGE_READWRITE;
		}
		else if (section_chars & (std::uint32_t)section_prot_flags::rx)
		{
			return PAGE_EXECUTE_READ;
		}
		else if (section_chars & (std::uint32_t)section_prot_flags::r)
		{
			return PAGE_READONLY;
		}

		return PAGE_EXECUTE_READWRITE;
	}

	bool copy_sections(PIMAGE_NT_HEADERS nt_headers, std::uint64_t file_base, std::uint64_t mapping_base)
	{
		PIMAGE_SECTION_HEADER section_list = IMAGE_FIRST_SECTION(nt_headers);

		for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER current_section = &section_list[i];
			PVOID section_base = reinterpret_cast<PVOID>(mapping_base + current_section->VirtualAddress);
			PVOID file_sect_addr = reinterpret_cast<PVOID>(file_base + current_section->PointerToRawData);

			std::uint32_t section_size = current_section->SizeOfRawData;

			if (section_size < current_section->Misc.VirtualSize)
			{
				section_size = current_section->Misc.VirtualSize;
			}

			if (VirtualAlloc(section_base, section_size, MEM_COMMIT, PAGE_READWRITE) == 0)
			{
				return false;
			}

			if (current_section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				memset(section_base, 0, current_section->Misc.VirtualSize);
			}

			if (current_section->SizeOfRawData == 0)
				continue;

			memcpy(section_base, file_sect_addr, current_section->SizeOfRawData);
		}

		return true;
	}

	bool resolve_imports(PIMAGE_NT_HEADERS nt_headers, std::uint64_t mapping_base)
	{
		PIMAGE_IMPORT_DESCRIPTOR import_descriptors = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(mapping_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for (int i = 0; import_descriptors[i].OriginalFirstThunk; ++i)
		{
			char* module_name = reinterpret_cast<char*>(mapping_base + import_descriptors[i].Name);


			HMODULE import_module = LoadLibraryA(module_name);
			if (import_module == NULL) {
				return NULL;
			}

			IMAGE_THUNK_DATA* lookup_table = (IMAGE_THUNK_DATA*)(mapping_base + import_descriptors[i].OriginalFirstThunk);

			// the address table is a copy of the lookup table at first
			// but we put the addresses of the loaded function inside => that's the IAT
			IMAGE_THUNK_DATA* address_table = (IMAGE_THUNK_DATA*)(mapping_base + import_descriptors[i].FirstThunk);

			// null terminated array, again
			for (int i = 0; lookup_table[i].u1.AddressOfData != 0; ++i) {
				void* function_handle = NULL;

				// Check the lookup table for the adresse of the function name to import
				DWORD lookup_addr = lookup_table[i].u1.AddressOfData;

				if ((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) { //if first bit is not 1
					// import by name : get the IMAGE_IMPORT_BY_NAME struct
					IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*)(mapping_base + lookup_addr);
					// this struct points to the ASCII function name
					char* funct_name = (char*)&(image_import->Name);
					// get that function address from it's module and name
					function_handle = (void*)GetProcAddress(import_module, funct_name);
				}
				else {
					// import by ordinal, directly
					function_handle = (void*)GetProcAddress(import_module, (LPSTR)lookup_addr);
				}

				if (function_handle == NULL) {
					return NULL;
				}

				// change the IAT, and put the function address inside.
				address_table[i].u1.Function = (ULONGLONG)function_handle;
			}
		}
	}

	bool resolve_relocations(std::uint64_t image_base, PIMAGE_NT_HEADERS nt_header, std::uint64_t delta)
	{
		PIMAGE_BASE_RELOCATION relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + image_base);
		std::uint32_t relocation_size = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		std::uint32_t current_size = 0;

		while (current_size <= relocation_size)
		{
			std::uint16_t* relocation_entries = reinterpret_cast<std::uint16_t*>((std::uint64_t)relocation + sizeof(IMAGE_BASE_RELOCATION));
			std::uint32_t relocation_count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);

			for (std::uint32_t i = relocation_count; i < relocation_count; i++)
			{
				std::uint16_t reloc_type = relocation_entries[i] >> 12;
				std::uint16_t reloc_offset = relocation_entries[i] & 0xFFF;

				void* relocation_base = reinterpret_cast<void*>(image_base + reloc_offset);

				switch (reloc_type)
				{
				case IMAGE_REL_BASED_LOW:
					*(std::uint16_t*)relocation_base += LOWORD(delta);
					break;
				case IMAGE_REL_BASED_HIGH:
					*(std::uint16_t*)relocation_base += HIWORD(delta);
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*(std::uint32_t*)relocation_base += (uint32_t)delta;
					break;
				case IMAGE_REL_BASED_DIR64:
					*(std::uint64_t*)relocation_base += delta;
					break;
				}

			}

			relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((std::uint64_t)relocation + relocation->SizeOfBlock);
			current_size += relocation->SizeOfBlock;
		}

		return true;
	}

	bool resolve_page_protections(PIMAGE_NT_HEADERS nt_headers, std::uint64_t mapping_base)
	{
		PIMAGE_SECTION_HEADER section_list = IMAGE_FIRST_SECTION(nt_headers);

		for (std::uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER current_section = &section_list[i];
			DWORD old_protection = 0;
			
			if (!VirtualProtect(LPVOID(mapping_base + current_section->VirtualAddress), current_section->Misc.VirtualSize, get_section_prot(current_section), &old_protection))
			{
				DWORD error = GetLastError();
				return false;
			}
		}

		return true;
	}

	image* map_image(std::string& image_name)
	{
		file image_buffer{ image_name };
		PIMAGE_DOS_HEADER dos_header = image_buffer.read_ptr<IMAGE_DOS_HEADER>(0);

		if (dos_header->e_magic != 'ZM' || dos_header->e_lfanew == 0)
			return 0;

		PIMAGE_NT_HEADERS nt_header = image_buffer.read_ptr<IMAGE_NT_HEADERS>(dos_header->e_lfanew);

		if (nt_header->Signature != 'EP' || nt_header->OptionalHeader.SizeOfImage == 0)
			return 0;

		std::uint64_t mapping_base = (std::uint64_t)VirtualAlloc((LPVOID)nt_header->OptionalHeader.ImageBase, nt_header->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);

		if(mapping_base == 0)
			mapping_base = (std::uint64_t)VirtualAlloc(nullptr, nt_header->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);

		if (mapping_base == 0)
			return 0;

		VirtualAlloc((LPVOID)mapping_base, nt_header->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
		memcpy((void*)mapping_base, image_buffer.read_ptr(0), nt_header->OptionalHeader.SizeOfHeaders);

		if (copy_sections(nt_header, image_buffer.get_buffer_base(), mapping_base) == false)
			return 0;

		if (std::uint64_t delta = mapping_base - nt_header->OptionalHeader.ImageBase)
		{
			if (resolve_relocations(mapping_base, nt_header, delta) == false)
				return 0;
		}

		if (resolve_imports(nt_header, mapping_base) == false)
			return 0;

		if (resolve_page_protections(nt_header, mapping_base) == false)
			return 0;

		return new image{ mapping_base, reinterpret_cast<PIMAGE_NT_HEADERS>(mapping_base + dos_header->e_lfanew) };
	}

	std::uint64_t load_image(std::string& image_name)
	{
		image* mapped_image = map_image(image_name);
		mapped_images.emplace(image_name, mapped_image);

		return mapped_image->get_entry_point();
	}
}