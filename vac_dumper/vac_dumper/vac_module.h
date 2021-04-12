#pragma once
#include <cstdint>
#include <string>


struct vac_import
{
	uint32_t module_name_offset;
	uint32_t function_name_offset;
};

struct vac_module_params
{
	vac_module_params* p_;
	uint32_t unk_0;
	uint32_t unk_1;
	uint8_t* payload_entry;
	const unsigned char primary_ice_key[8];
};

/* represents the state of hooked vac module */
class vac_module 
{
public:
	static vac_module* get_module(uintptr_t module_base);
	static vac_module* add_module(uintptr_t module_base, std::string path);

	explicit vac_module(uintptr_t module_base, std::string path);

	uintptr_t module_base{};
	std::string path;
	std::string text_section_hash{};
	bool imports_dumped{};
	
	vac_module_params* module_params{};
	std::uint8_t secondary_ice_key[8]{};
};