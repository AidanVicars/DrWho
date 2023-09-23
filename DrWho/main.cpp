#include <iostream>

#include "ia32.hpp"
#include "image_manager.hpp"
#include "mem_manager.hpp"

static std::uint64_t last_page = 0;

LONG __stdcall exception_handler(EXCEPTION_POINTERS* exception_data)
{
	if (exception_data->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		std::uint64_t errata_address = exception_data->ExceptionRecord->ExceptionInformation[1];
		std::uint64_t page_address = PAGE_ADDRESS(errata_address);
		last_page = page_address;

		if (mem_manager::is_tracked_page(page_address) == false)
			return EXCEPTION_CONTINUE_SEARCH;

		eflags_t current_flags{ exception_data->ContextRecord->EFlags };
		current_flags.fields.tf = 1;
		exception_data->ContextRecord->EFlags = current_flags.dword;

		if (mem_manager::page_in(page_address) == false)
			return EXCEPTION_CONTINUE_SEARCH;

		auto tracked_address = mem_manager::get_tracked_address(errata_address);
		if (tracked_address)
		{
			std::string verb = exception_data->ExceptionRecord->ExceptionInformation[0] == 1 ? " wrote from: " : " read from: ";

			std::cout << tracked_address.value().c_str() << std::hex << " [" << errata_address << "]" << verb << exception_data->ContextRecord->Rip << '\n';
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (exception_data->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		eflags_t current_flags{ exception_data->ContextRecord->EFlags };
		current_flags.fields.tf = 0;
		exception_data->ContextRecord->EFlags = current_flags.dword;

		if (mem_manager::page_out(last_page) == true)
			return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
	std::string image_path = { "F:\\Cxx\\ExampleDll\\x64\\Debug\\ExampleDll.dll" };

	std::uint64_t image_entry = image_manager::load_image(image_path);

	using DllMainT = BOOL(*WINAPI)(HINSTANCE, DWORD, LPVOID);

	AddVectoredExceptionHandler(TRUE, exception_handler);

	mem_manager::track_address(0x180019880, "Caption");

	DWORD old_port;
	VirtualProtect((void*)0x180019880, 1000, PAGE_READWRITE, &old_port);
	*(uintptr_t*)(0x180019880) = (uintptr_t)"dadadada\0";

	((DllMainT)image_entry)(nullptr, DLL_PROCESS_ATTACH, nullptr);
	

	while (true)
	{

	}

	return 0;
}