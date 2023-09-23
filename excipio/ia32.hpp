#pragma once

#include <cstdint>

union eflags_t
{
	std::uint64_t dword;
	struct
	{
		std::uint32_t cf : 1;  
		std::uint32_t : 1;	   
		std::uint32_t pf : 1;  
		std::uint32_t : 1;	   
		std::uint32_t af : 1;  
		std::uint32_t : 1;	   
		std::uint32_t zf : 1;  
		std::uint32_t sf : 1;  
		std::uint32_t tf : 1;  
		std::uint32_t _if : 1; 
		std::uint32_t df : 1;  
		std::uint32_t of : 1;  
		std::uint32_t iopl : 1;
		std::uint32_t nt : 1;  
		std::uint32_t : 1;	   
		std::uint32_t rf : 1;  
		std::uint32_t vm : 1;  
		std::uint32_t ac : 1;  
		std::uint32_t vif : 1; 
		std::uint32_t vip : 1; 
		std::uint32_t id : 1;  
		std::uint32_t : 10;	   
	} fields;
};