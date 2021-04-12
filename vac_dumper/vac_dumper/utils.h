#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <vector>
#include <sstream>
#include <iomanip> 

namespace utils
{
	void make_x86_jmp(unsigned char* address_to_jump_from, uint32_t address_to_jump_to, uint32_t instruction_length);
	std::uint8_t* find_pattern(std::uint8_t* start, size_t size, std::vector<uint8_t> pattern);
	std::uint8_t* find_pattern(const char* module_name, std::vector<uint8_t> pattern);
	std::uint8_t* find_pattern(const char* module_name, const char* pattern);
	std::uint8_t* find_pattern(std::uint8_t* start, size_t size, const char* pattern);

	void hook_iat(const char* iat_module_name, const char* import_module_name, const char* fn_name, void* new_fn);
	std::string hash_sha256(std::uint8_t* data, size_t size);
	std::string get_curent_directory();
	std::string narrowString(std::wstring& str);

	PIMAGE_SECTION_HEADER get_text_section(uint8_t* module);
	HANDLE create_file(std::string full_path);
	bool write_line_to_file(HANDLE file_handle, std::string line);
	bool write_buffer_to_file(HANDLE file_handle, std::uint8_t* p_buffer, size_t size);
	bool file_exists(std::string full_path);

	uint32_t get_process_id(std::wstring process_name);
	uintptr_t get_process_module(uint32_t process_id, std::wstring module_name);
	std::optional<std::vector<MODULEENTRY32W>>  get_process_modules(uint32_t process_id);
	std::optional<std::vector<PROCESSENTRY32>>  get_all_processes();
	HMODULE get_module_containing_address(uintptr_t address);
	template< typename T >
	std::string int_to_hex(T i)
	{
		std::stringstream stream;
		stream << "0x"
			<< std::setfill('0') << std::setw(sizeof(T) * 2)
			<< std::hex << i;
		return stream.str();
	}
}
