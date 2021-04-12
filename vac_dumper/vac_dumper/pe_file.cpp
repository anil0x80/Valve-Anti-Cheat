#include "pe_file.h"
#include <filesystem>
#include <fstream>

#include <Windows.h>

using std::vector;
using std::string;

#define DOS_HEADER(data) reinterpret_cast<PIMAGE_DOS_HEADER>(data)
#define NT_HEADER32(data) reinterpret_cast<PIMAGE_NT_HEADERS32>((data) + DOS_HEADER(data)->e_lfanew)
#define NT_HEADER64(data) reinterpret_cast<PIMAGE_NT_HEADERS64>((data) + DOS_HEADER(data)->e_lfanew)
#define SECTION_HEADERS(data) is_amd64 ? reinterpret_cast<PIMAGE_SECTION_HEADER>(NT_HEADER64(data) + 1)\
									   : reinterpret_cast<PIMAGE_SECTION_HEADER>(NT_HEADER32(data) + 1)

pe_file::pe_file(const string path) : path(path)
{
	//if (!std::filesystem::exists(path))
	//	throw(std::runtime_error("File does not exist: " + path));

	const auto file_size = std::filesystem::file_size(path);
	std::ifstream fs(path, std::fstream::binary);
	file_buffer.resize(file_size);
	if (!fs.read((char*)file_buffer.data(), file_size))
		throw(std::runtime_error("Cannot read file data!"));

	fs.close();

	if (DOS_HEADER(file_buffer.data())->e_magic != IMAGE_DOS_SIGNATURE)
		throw(std::runtime_error("Invalid file type, PE signature not matched!"));

	is_amd64 = NT_HEADER32(file_buffer.data())->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}

std::optional<pe_file::pe_section> pe_file::get_section(std::string section_name)
{
	auto* data = file_buffer.data();
	const auto section_count = NT_HEADER32(data)->FileHeader.NumberOfSections;
	auto* section_headers = SECTION_HEADERS(data);

	for (auto i = 0; i < section_count; i++)
	{
		if (!strcmp((char*)section_headers[i].Name, section_name.c_str()))
			return pe_section{ data + section_headers[i].PointerToRawData, section_headers[i].SizeOfRawData };
	}
	IMAGE_EXPORT_DIRECTORY sd;
	return std::nullopt;
}

std::vector<std::byte>* pe_file::get_file_buffer()
{
	return &file_buffer;
}

std::string pe_file::get_file_path()
{
	return path;
}

size_t pe_file::get_size_of_image()
{
	return is_amd64 ? NT_HEADER64(file_buffer.data())->OptionalHeader.SizeOfImage : NT_HEADER32(file_buffer.data())->OptionalHeader.SizeOfImage;
}

void pe_file::overwrite_original()
{
	std::ofstream os(path, std::ofstream::trunc | std::ofstream::binary);
	if (!os.write(reinterpret_cast<char*>(file_buffer.data()), file_buffer.size()))
	{
		throw std::runtime_error("Unable to write to file " + path);
	}
	os.close();
}
