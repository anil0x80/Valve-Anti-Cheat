#include "vac_module.h"

#include <map>
#include <stdexcept>
#include <string>
#include <vector>



#include "ice_key.h"
#include "util.h"
#include "vac_defs.h"


LONG WINAPI g_exception_filter(_EXCEPTION_POINTERS* _exception_info)
{
	util::print_exception_info(_exception_info);
	printf("UnhandledExceptionFilter!, continuing execution\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}

/* global hook definitions, i am lazy to make it work for more than one module at same time.*/
uint32_t g_packet_encryption_key[2];
uint32_t g_original_packet_encryption;

__declspec(naked) void hooked_payload_encryptor()
{
	__asm
	{
		push edi
		push esi
		push eax

		mov edi, [esp + 20]; edi now points to key
		mov eax, [edi]; low part
		mov edi, [edi + 4]; high part
		mov g_packet_encryption_key, eax; save key
		mov g_packet_encryption_key + 4, edi

		pop eax
		pop esi
		pop edi

		push ebp
		mov ebp, esp
		sub esp, 0xC

		jmp g_original_packet_encryption
	}
}


vac_module::vac_module(const char* module_name, vac_module_index idx) : module_name(module_name), module_idx(idx),
                                                                        current_scan_id()
{
	module_base = (uint32_t)LoadLibraryA(module_name);
	if (!module_base)
		throw std::runtime_error("Failed to load " + std::string(module_name));

	entry_point = (uint8_t*)GetProcAddress((HMODULE)module_base, "_runfunc@20");
	if (!entry_point)
		throw std::runtime_error("Can not locate runfunc for" + std::string(module_name));

	//todo primary ice keys are different for each scan, so we also need to solve that. 
	primary_ice_keys = util::search_primary_ice_keys(module_name);
	if (primary_ice_keys.empty())
		throw std::runtime_error("Failed to find primary ice keys for " + std::string(module_name));

	vac_payload_hasher_function = util::search_vac_payload_hasher_function(module_name);
	if (!vac_payload_hasher_function)
		throw std::runtime_error("Failed to find hasher function for " + std::string(module_name));

	vac_packet_encryptor_function = util::find_pattern(module_name, "55 8B EC 83 EC 0C 53 56 57 8B F9");
	if (!vac_packet_encryptor_function)
		throw std::runtime_error("Failed to find vac packet encryptor function for " + std::string(module_name));

	g_original_packet_encryption = (uint32_t)util::make_x86_jmp(vac_packet_encryptor_function,
	                                                            (uint32_t)hooked_payload_encryptor, 6);
}

vac_module::packet_type vac_module::create_packet(scan_id id)
{
	/*
	 * we need to encrypt the PAYLOAD with primary ice key before sending it. +
	 * output_packet_size must be at least 0x1000  +
	 * packet_output must point to correct memory. +
	 * payload data should be hashed before encryption +
	 */

	current_scan_id = id;
	
	/* fill packet header */
	auto p_packet = std::make_unique<VAC_PACKET>(); // all fields are 0 initialized
	p_packet->scan_id = static_cast<uint32_t>(id);
	p_packet->constant_1 = 1;
	p_packet->payload_hash = 0; //fill this later, we can't calculate it for now.
	p_packet->packet_number = static_cast<uint32_t>(__rdtsc()); // can use anything really, doesn't matter.

	auto* payload_header = (in_payload_header*)p_packet->payload_data;
	std::memcpy(payload_header->secondary_ice_key, secondary_ice_keys[module_idx].data(), 8); // copy secondary key

	return std::move(p_packet);
}

void vac_module::set_payload_hash(packet_type& packet)
{
	/* calculate hash */
	uint32_t payload_hash = -1;
	typedef  void(__fastcall* g_calculate_payload_hash)(uint32_t*, uint8_t*);
	((g_calculate_payload_hash)vac_payload_hasher_function)(&payload_hash, packet->payload_data);
	packet->payload_hash = ~payload_hash;
}

void vac_module::prepare_packet(packet_type& packet)
{
	/* do not forget to call this*/
	set_payload_hash(packet);

	/* encrypt the payload */
	IceKey k{ 1 };
	k.set(primary_ice_keys[current_scan_id].data());
	for (auto i = 0u; i < VAC_PAYLOAD_SIZE; i += 8)
	{
		k.encrypt(&packet->payload_data[i], &packet->payload_data[i]);
	}
}

vac_module::run_result vac_module::run_module(packet_type& packet)
{
	/* do not forget to call this*/
	prepare_packet(packet);
	
	typedef int(__stdcall* g_runfunc)(int32_t, uint8_t*, uint32_t,
		uint8_t*, uint32_t*);

	/* prepare output buffer */
	auto output_size = VAC_OUTPUT_SIZE;
	auto p_output = std::make_unique<uint8_t[]>(output_size);

	SetUnhandledExceptionFilter(g_exception_filter);
	
	const auto result = ((g_runfunc)entry_point)(VAC_FUNCTION_ID, (uint8_t*)packet.get(), VAC_PACKET_SIZE,
		p_output.get(), &output_size);

	/* decrypt output buffer... */
	if (output_size > 1)
	{
		IceKey k{ 1 };
		k.set((uint8_t*)g_packet_encryption_key);
		for (auto i = 0u; i < 0x1000; i += 8)
			k.decrypt(&p_output[i], &p_output[i]);
	}

	return std::make_pair(result, std::move(p_output));
}


