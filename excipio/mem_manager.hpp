#pragma once
#include <unordered_map>
#include <cstdint>
#include <string>
#include <optional>

#include <Windows.h>

#include <Zydis/Zydis.h>

#define PAGE_ADDRESS(address) address & ~0xFFF


namespace mem_manager
{
	struct page_copy_t
	{
		std::uint64_t page_address;
		std::uint64_t page_copy;
		std::uint32_t page_protection;
		
		page_copy_t(std::uint64_t page_address, std::uint64_t page_copy, std::uint32_t page_protection) : page_address(page_address), page_copy(page_copy), page_protection(page_address) {};
		page_copy_t() = default;
	};

	std::vector<std::uint64_t> tracked_pages;
	std::vector<page_copy_t> page_copies;
	std::unordered_map<std::string, std::uint64_t> tracked_addresses;
	ZydisDecoder zy_decoder;

	bool is_tracked_page(std::uint64_t page_address)
	{
		for (auto& tracked_page : tracked_pages)
		{
			if (tracked_page == page_address)
				return true;
		}

		return false;
	}

	std::optional<std::string> get_tracked_address(std::uint64_t address)
	{
		for (auto& tracked_address : tracked_addresses)
		{
			if (tracked_address.second == address)
				return tracked_address.first;
		}

		return std::nullopt;
	}

	bool track_page(std::uint64_t page_address)
	{
		MEMORY_BASIC_INFORMATION mem_info;
		if (VirtualQuery((void*)page_address, &mem_info, sizeof MEMORY_BASIC_INFORMATION) == false)
		{
			std::uint32_t error_code = GetLastError();
			DebugBreak();
			return false;
		}

		std::uint8_t* page_copy = new std::uint8_t[0x1000];
		memcpy((void*)page_copy, (void*)page_address, 0x1000);

		if (VirtualFree((LPVOID)page_address, 0x1000, MEM_DECOMMIT) == false)
		{
			std::uint32_t error_code = GetLastError();
			DebugBreak();
			return false;
		}

		page_copies.push_back(page_copy_t(page_address, (std::uint64_t)page_copy, (std::uint32_t)mem_info.Protect));
		tracked_pages.push_back(page_address);
	}

	bool track_address(std::uint64_t address, std::string address_label)
	{
		tracked_addresses.emplace(address_label, address);

		if (is_tracked_page(PAGE_ADDRESS(address)) == true)
			return true;

		return track_page(PAGE_ADDRESS(address));
	}


	std::optional<page_copy_t> get_page_copy(std::uint64_t page_address)
	{
		for (auto& copy : page_copies)
		{
			if (copy.page_address == page_address)
				return copy;
		}

		return std::nullopt;
	}

	bool page_in(std::uint64_t page_address)
	{
		auto page_copy_opt = get_page_copy(page_address);

		if (!page_copy_opt)
			return false;

		auto& page_copy = page_copy_opt.value();

		if (VirtualAlloc((void*)page_copy.page_address, 0x1000, MEM_COMMIT, PAGE_READWRITE) == nullptr)
		{
			std::uint32_t error_code = GetLastError();
			DebugBreak();
			return false;
		}

		memcpy((void*)page_copy.page_address, (void*)page_copy.page_copy, 0x1000);
		

		return true;
	}

	bool page_out(std::uint64_t page_address)
	{
		auto page_copy_opt = get_page_copy(page_address);

		if (!page_copy_opt)
			return false;

		auto& page_copy = page_copy_opt.value();

		DWORD old_prot = 0;
		if (VirtualProtect((void*)page_copy.page_address, 0x1000, PAGE_READWRITE, &old_prot) == false)
		{
			std::uint32_t error_code = GetLastError();
			DebugBreak();
			return false;
		}

		memcpy((void*)page_copy.page_copy, (void*)page_copy.page_address, 0x1000);

		if (VirtualFree((LPVOID)page_address, 0x1000, MEM_DECOMMIT) == false)
		{
			std::uint32_t error_code = GetLastError();
			DebugBreak();
			return false;
		}

		return true;
	}

}