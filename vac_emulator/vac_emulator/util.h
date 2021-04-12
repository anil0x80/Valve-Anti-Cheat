#pragma once
#include <string>
#include <vector>

#include "vac_vector.h"
#include <sstream>
#include <iomanip>

#include "vac_module.h"


namespace util
{
	uint32_t get_syscall_idx(const char* function_name);
	std::vector<std::string> get_args(int argc, char** argv);
	std::uint8_t* find_pattern(const char* module_name, std::vector<uint8_t> pattern, uintptr_t start = 0);
	std::uint8_t* find_pattern(const char* module_name, const char* pattern, uintptr_t start = 0);
	vac_module::primary_keys search_primary_ice_keys(const char* module_name);
	std::vector<uint8_t> search_network_ice_key(const char* module_name);
	std::uint8_t* search_vac_payload_hasher_function(const char* module_name);
	
	bool get_module_encryption_parameters(const char* module_name, uint8_t** params_1, uint32_t* params_1_size,
												  uint8_t** params_2, uint32_t* params_2_size);
	uint8_t* make_x86_jmp(unsigned char* address_to_jump_from, uint32_t address_to_jump_to, uint32_t instruction_length);
	void insert_zeros_at_b_and_end(const char* module_name,vac_vector*, int size);
	void resize_with_0(const char* module_name, vac_vector*, uint32_t el_size);
	template< typename T >
	std::string int_to_hex(T i)
	{
		std::stringstream stream;
		stream << "0x"
			<< std::setfill('0') << std::setw(sizeof(T) * 2)
			<< std::hex << i;
		return stream.str();
	}
	std::string base_64_encode(uint8_t* ptr, size_t length);

	void print_exception_info(_EXCEPTION_POINTERS* record);
}
