#include "util.h"

#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#include "vac_module.h"

/*
 * VAC modules can have more than one supported scan routines
 * each one of them has unique scan_id and primary_ice_keys
 * scan_supported field is always set to 1, indicating operation is supported.
 * you have to pass correct scan_id as input to scan to occur,
 * otherwise you will get SCAN_NOT_SUPPORTED(3) as output.
 */

struct vac_module_scan_params
{
	vac_module_scan_params* p_previous;
	vac_module::scan_id scan_id;
	uint32_t scan_supported;
	uint8_t* scan_payload;
	unsigned char scan_primary_ice_key[8];
};

std::vector<unsigned char> split_bytes(std::string string)
{
	std::vector<unsigned char> bytes;
	size_t delimiter_pos;
	while ((delimiter_pos = string.find(' ')) != std::string::npos)
	{
		std::string token = string.substr(0, delimiter_pos);
		if (token == "?")
			bytes.push_back(0xCC);
		else
			bytes.push_back((unsigned char)stoi(token, nullptr, 16));
		string.erase(0, delimiter_pos + 1);
	}
	if (string == "?")
		bytes.push_back(0xCC);
	else
		bytes.push_back((unsigned char)stoi(string, nullptr, 16));
	return bytes;
}

uint32_t util::get_syscall_idx(const char* function_name)
{
	auto func = GetProcAddress(GetModuleHandleA("ntdll.dll"), function_name);
	if (func)
	{
		return *(uint32_t*)((uint8_t*)func + 1); // B8 CC CC CC CC, mov eax, IDX
	}
	return 0;
}

std::vector<std::string> util::get_args(int argc, char** argv)
{
	argv++; // increment cuz we don't want the path argument
	argc--; // same reason
	
	std::vector<std::string> to_ret;
	if (argv)
	{
		for(auto i = 0; i < argc; i++)
		{
			if(argv)
				to_ret.emplace_back(argv[i]);
		}
		
	}
	return to_ret;
}


std::uint8_t* util::find_pattern(const char* module_name, std::vector<uint8_t> pattern, uintptr_t start)
{
	auto module_start = GetModuleHandleA(module_name);
	MODULEINFO module_info{};
	GetModuleInformation(GetCurrentProcess(), module_start, &module_info, sizeof(MODULEINFO));
	if (!start)
	{
		start = (uintptr_t)module_start;
	}
	auto* end = (unsigned char*)((uintptr_t)module_start + module_info.SizeOfImage);

	for (auto* p = (unsigned char*)start; p < end; p++)
	{
		if (p + pattern.size() > end)
			break;
		
		auto matched_pattern_index = 0u;
		auto* match_current = p;
		while (true)
		{
			if (matched_pattern_index == pattern.size())
				return reinterpret_cast<std::uint8_t*>(p);
			if (*match_current == pattern[matched_pattern_index] || pattern[matched_pattern_index] == 0xCC)
			{
				match_current++;
				matched_pattern_index++;
			}
			else
				break;
		}
	}
	return nullptr;
}

std::uint8_t* util::find_pattern(const char* module_name, const char* pattern, uintptr_t start)
{
	std::vector<unsigned char> converted;
	return find_pattern(module_name, split_bytes(pattern), start);
}

vac_module::primary_keys util::search_primary_ice_keys(const char* module_name)
{
	vac_module::primary_keys to_ret;
	if(module_name)
	{
		uintptr_t last = 0;
		while(auto* found = find_pattern(module_name, "A3 ? ? ? ? C7", last))
		{
			auto* p_vac_scan_params = reinterpret_cast<vac_module_scan_params*>(*(uint32_t*)(found + 1));
			if (p_vac_scan_params)
			{
				std::vector<uint8_t> primary_key(8);
				std::memcpy(primary_key.data(), p_vac_scan_params->scan_primary_ice_key, 8);
				to_ret[p_vac_scan_params->scan_id] = primary_key;
			}
			last = (uintptr_t)found + 16;
		}
	}
	return to_ret;
}

std::vector<uint8_t> util::search_network_ice_key(const char* module_name)
{
	std::vector<uint8_t> to_ret(8);
	if (module_name)
	{
		auto* adr = find_pattern(module_name, "68 ? ? ? ? 50 E8");
		if (adr)
		{
			adr += 1;
			auto* network_ice_key = (uint8_t*)*(uint32_t*)adr;
			std::memcpy(to_ret.data(), network_ice_key, 8);
		}
		else
		{
			std::cout << "Failed to find vac_module_params_adr for " << module_name << std::endl;
		}
	}
	return to_ret;
}

std::uint8_t* util::search_vac_payload_hasher_function(const char* module_name)
{
	std::uint8_t* to_ret = nullptr;
	if (module_name)
	{
		to_ret = find_pattern(module_name, "53 55 8B E9 56");
	}
	return to_ret;
}

bool util::get_module_encryption_parameters(const char* module_name, uint8_t** params_1, uint32_t* params_1_size,
	uint8_t** params_2, uint32_t* params_2_size)
{
	bool result = false;
	auto* vac_encryption_data_retriever_function = find_pattern(module_name, "51 51 53 55 56 57");
	if (vac_encryption_data_retriever_function)
	{
		auto* encryption_data = *(uint8_t**)(find_pattern(module_name, "68 ? ? ? ? 50 E8") + 1);
		auto encryption_data_size = **(uint32_t**)(find_pattern(module_name, "A1 ? ? ? ? 89 44") + 1);
		__asm
		{
			push params_2_size
			push params_2
			push params_1_size
			push params_1
			mov ecx, encryption_data
			mov edx, encryption_data_size
			call vac_encryption_data_retriever_function
			mov result, al
			add esp, 16
		}
	}
	return result;
}

//we need to code a good hooking library..
uint8_t* util::make_x86_jmp(unsigned char* address_to_jump_from, uint32_t address_to_jump_to, uint32_t instruction_length)
{
	DWORD old_protect{};
	VirtualProtect(address_to_jump_from, instruction_length, PAGE_EXECUTE_READWRITE, &old_protect);
	const auto jmp_relative_address = (uint32_t)(address_to_jump_to - (uint32_t)address_to_jump_from) - 5;
	*address_to_jump_from = 0xE9;
	*((DWORD*)(address_to_jump_from + 0x1)) = jmp_relative_address;
	for (DWORD x = 0x5; x < instruction_length; x++) *(address_to_jump_from + x) = 0x90;
	VirtualProtect(address_to_jump_from, instruction_length, old_protect, &old_protect);

	//return original point that we need to route the execution back
	return address_to_jump_from + instruction_length;
}

void util::insert_zeros_at_b_and_end(const char* module_name, vac_vector* vec, int size)
{
	auto* func = find_pattern(module_name, "55 8B EC 83 EC 24");
	if(func)
	{
		typedef int(__thiscall* func_)(vac_vector*, int);
		((func_)func)(vec, size);
	}
}

void util::resize_with_0(const char* module_name, vac_vector* vec, uint32_t el_size)
{
	auto* func = find_pattern(module_name, "56 FF 74 24 08");
	if (func)
	{
		typedef int(__thiscall* func_)(vac_vector*, uint32_t);
		((func_)func)(vec, el_size);
	}
}

std::string util::base_64_encode(uint8_t* ptr, size_t length)
{
	std::ostringstream oss;
	oss << std::setfill('0') << std::hex;

	for (size_t i = 0; i < length; ++i)
		oss << std::setw(2) << static_cast<unsigned int>(ptr[i]);

	return oss.str();
}

void util::print_exception_info(_EXCEPTION_POINTERS* record)
{
	std::cout << "-----exception-----" << std::endl;
#define print_register(reg) std::cout << int_to_hex(ctx->reg) << std::endl;
	auto* ctx = record->ContextRecord;
	print_register(Ebp);
	print_register(Esp);
	print_register(Eax);
	print_register(Edi);
	print_register(Ecx);
	print_register(Edx);
	print_register(Eip);
	std::cout << "Address: " << int_to_hex(record->ExceptionRecord->ExceptionAddress) << std::endl;
	std::cout << "-----exception_end-----" << std::endl;
}
