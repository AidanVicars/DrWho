#pragma once

#include <fstream>
#include <string>

class file
{
private:
	std::uint8_t* file_buffer;
	std::uint64_t file_size;
public:
	file(std::string& file_path)
	{
		std::ifstream file_stream{ file_path, std::ios_base::binary };

		if (file_stream.fail())
		{
			throw std::exception{ "Failed to open file, excipio may be underprivileged or the path is wrong" };
		}

		file_stream.seekg(0, std::ios_base::end);
		file_size = file_stream.tellg();
		file_stream.seekg(0, std::ios_base::beg);

		file_buffer = new uint8_t[file_size];
		file_stream.read((char*)file_buffer, file_size);
	}

	~file()
	{
		delete[] file_buffer;
	}

	template<typename ptr_t = void>
	ptr_t* read_ptr(std::uint64_t offset)
	{
		if (offset >= file_size)
			return nullptr;

		return reinterpret_cast<ptr_t*>(&file_buffer[offset]);
	}

	template<typename data_t>
	data_t read(std::uint64_t offset)
	{
		return reinterpret_cast<data_t>(file_buffer[offset]);
	}

	std::uint64_t get_buffer_base()
	{
		return reinterpret_cast<std::uint64_t>(file_buffer);
	}

	std::uint64_t get_size()
	{
		return file_size;
	}
};