#include "vac_dumper.h"


#include <argnames.h>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <ostream>
#include <vector>

#include "utils.h"
#include <Windows.h>
#include <Psapi.h>

#include "ice_key.h"
#include "target_game.h"
#include "vac_module.h"

vac_dumper g_vac_dumper;
std::unique_ptr<target_game> g_target_game;

void __stdcall hooked_runfunc(unsigned int ret_adr, int a1, int a2, int a3, int a4, int a5)
{
	/* get info related to current vac module */
	auto* current_module = utils::get_module_containing_address((uintptr_t)ret_adr);
	if (!current_module)
		current_module = reinterpret_cast<HMODULE>((uintptr_t)ret_adr & 0xFFFF0000);
	
	MODULEINFO module_info{};
	GetModuleInformation(GetCurrentProcess(), current_module, &module_info, sizeof MODULEINFO);
	auto* module = vac_module::get_module((uintptr_t)current_module);
	if (!module)
	{
		OutputDebugStringA(("Cant find module with base: " + std::to_string((uintptr_t)current_module)).c_str());
		RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, nullptr);
	};

	OutputDebugStringA(("hooked_runfunc called, vac module: " + std::to_string((uintptr_t)current_module)).c_str());
	if (!module->module_params)
	{
		// we don't have the vac_module_params*, find it now and add it to map!
		auto* vac_module_params_adr = utils::find_pattern((uint8_t*)current_module, module_info.SizeOfImage, "A3 ? ? ? ? C7");
		if (vac_module_params_adr)
		{
			OutputDebugStringA(("Found vac_module_params_adr found at: " + std::to_string((uintptr_t)vac_module_params_adr)).c_str());
			vac_module_params_adr += 1;
			vac_module_params_adr = (PBYTE) * (DWORD*)vac_module_params_adr;
			auto* p_vac_module_params = reinterpret_cast<vac_module_params*>(vac_module_params_adr);
			module->module_params = p_vac_module_params;
		}
		else
		{
			OutputDebugStringA(("Failed to find vac_module_params_adr for module " + std::to_string((uintptr_t)current_module)).c_str());
			RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, nullptr);
		}
	}
	
	if(!module->imports_dumped)
	{
		// dump imports
		OutputDebugStringA("Dumping imports..");
		module->imports_dumped = true;
		std::memcpy(module->secondary_ice_key, (unsigned char*)a2 + 16, 8);
		IceKey k{ 1 };

		auto* p_encrypted_size = (DWORD*)utils::find_pattern((uint8_t*)current_module, module_info.SizeOfImage, "68 ? ? ? ? 8B D1");
		if (p_encrypted_size)
		{
			p_encrypted_size = (DWORD*)(((uintptr_t)p_encrypted_size) + 1);
			OutputDebugStringA(("Encrypted imports names size: " + std::to_string(*p_encrypted_size)).c_str());

			auto* encrypted_import_names = utils::find_pattern((uint8_t*)current_module, module_info.SizeOfImage, "B9 ? ? ? ? 68");
			if (encrypted_import_names) 
			{
				//copy encrypted imports into our address space
				OutputDebugStringA(("Encrypted import names found at: " + std::to_string((uintptr_t)encrypted_import_names)).c_str());
				encrypted_import_names += 1;
				encrypted_import_names = (PBYTE) * (DWORD*)encrypted_import_names;
				const auto encrypted_import_names_copy = std::make_unique<unsigned char[]>(*p_encrypted_size);
				std::memcpy(encrypted_import_names_copy.get(), encrypted_import_names, *p_encrypted_size);


				auto* p_vac_module_params = module->module_params;
				k.set(p_vac_module_params->primary_ice_key);
				k.decrypt(&module->secondary_ice_key[0], &module->secondary_ice_key[0]); //decrypt the key from params, the key used to encrypt imports..
				k.set(module->secondary_ice_key);
				for (auto i = 0u; i < *p_encrypted_size; i += 8)
				{
					k.decrypt(&encrypted_import_names[i], &encrypted_import_names_copy[i]); //decrypt imports.
				}

				std::vector<std::string> function_names;
				auto* p_vac_imports = (vac_import*)(encrypted_import_names + *p_encrypted_size); //the array should be right after names.
				for (auto* import = p_vac_imports; import->function_name_offset && import->module_name_offset; import++)
				{
					//probably not needed, better be safe
					if (import->function_name_offset > * p_encrypted_size || import->module_name_offset > * p_encrypted_size)
						break;
					const auto* function_name = (const char*)encrypted_import_names_copy.get() + import->function_name_offset;
					function_names.emplace_back(function_name);
				}
				
				OutputDebugStringA(("Total VAC imports found: " + std::to_string(function_names.size())).c_str());
				if (!function_names.empty())
				{
					auto imports_file_path = utils::get_curent_directory() + module->text_section_hash;
					imports_file_path += "\\imports.txt";
					OutputDebugStringA(imports_file_path.c_str());
					auto* file_handle = utils::create_file(imports_file_path);
					if (file_handle != INVALID_HANDLE_VALUE)
					{
						for (auto& function_name : function_names)
						{
							if (!utils::write_line_to_file(file_handle, function_name))
							{
								OutputDebugStringA(("write_line_to_file failed for function_name: " + function_name).c_str());
								break;
							}
						}
						CloseHandle(file_handle);
						OutputDebugStringA("Write operation complete!");
					}
					else
					{
						OutputDebugStringA("Failed to create import file!");
					}

				}
			}
			else
			{
				OutputDebugStringA("[!] Couldn't get encrypted payload...\n");
			}
		}
		else
		{
			OutputDebugStringA("[!] Couldn't get encrypted payload size...\n");
		}
	}

	//dump the packet here
	OutputDebugStringA("Dumping packet..");
	std::uint8_t packet_data[0xB0];
	std::memcpy(packet_data, (std::uint8_t*)a2, 0xB0);
	IceKey k{ 1 };
	k.set(module->module_params->primary_ice_key);
	auto* encrypted_payload = packet_data + 16; //encrypted payload is at packet + 16
	for(auto i = 0u; i < 0xA0; i+= 8)
	{
		k.decrypt(&encrypted_payload[i], &encrypted_payload[i]);
	}
	/* use timestamp as file name  todo convert timestamp to date before giving it to file*/ 
	const auto timestamp = std::time(nullptr); 
	auto packet_file_path = utils::get_curent_directory() + module->text_section_hash;
	packet_file_path += "\\";
	packet_file_path += std::to_string(g_target_game->get_init_time());
	CreateDirectoryA(packet_file_path.c_str(), nullptr);
	packet_file_path += "\\";
	packet_file_path += std::to_string(timestamp);
	packet_file_path += ".bin";
	OutputDebugStringA(packet_file_path.c_str());
	auto* file_handle = utils::create_file(packet_file_path);
	if (file_handle != INVALID_HANDLE_VALUE)
	{
		if (!utils::write_buffer_to_file(file_handle, packet_data, 0xB0))
			OutputDebugStringA("Failed to write packet data to file!");
		CloseHandle(file_handle);
	}
	else
	{
		OutputDebugStringA("Failed to create file for packet dump!");
	}
}

__declspec(naked) void hooked_proc()
{
	__asm
	{
		push edi
		mov edi, esp
		add edi, 4
		pushad
		pushfd

		push[edi + 24]; p_output_size
		push[edi + 20]; output
		push[edi + 16]; params_size
		push[edi + 12]; params
		push[edi + 8]; function_id
		push[edi + 0]; _ret_to_vac_module_call

		call hooked_runfunc; stdcall, so will clear the stack itself
		popfd
		popad
		pop edi
		
		mov eax, [esp]
		add esp, 4; stack is fully restored
		push ebp
		mov ebp, esp
		push esi
		push edi
		jmp eax
	}
}

auto __stdcall hk_load_library(LPCWSTR module_name, HANDLE file, DWORD flags) -> HMODULE
{
	// load the module into the process
	static auto first_call = true;
	auto* module = LoadLibraryExW(module_name, file, flags);

	// check if target is a VAC module
	auto entry_point = GetProcAddress(module, "_runfunc@20");
	if (!entry_point)
		return module;
	
	//hook the entry point
	OutputDebugStringA("vac module detected!");
	try
	{
		if(first_call)
		{
			first_call = false;
			g_target_game = std::make_unique<target_game>(L"csgo.exe");
			g_target_game->dump_info();
		}
		auto module_path = std::wstring(module_name);
		const auto narrowed_module_path = utils::narrowString(module_path);
		
		auto* added_module = vac_module::add_module((uintptr_t)module, narrowed_module_path); // make sure to hash .text section before hooking!!
		utils::make_x86_jmp((unsigned char*)entry_point, (DWORD)hooked_proc, 0x5);
		OutputDebugStringA("patched _runfunc@20");

		auto directory = utils::get_curent_directory() + added_module->text_section_hash;
		OutputDebugStringA(directory.c_str());
		if (!CreateDirectoryA(directory.c_str(), nullptr))
		{
			//directory already exists, we dumped this guy before.
			directory += "\\";
			added_module->imports_dumped = utils::file_exists(directory + "imports.txt");
			OutputDebugStringA("Directory already exists, or failed!");
			return module;
		}

		/// set the name of the dll
		directory += "\\";
		added_module->imports_dumped = utils::file_exists(directory + "imports.txt");
		directory += "module.dll";

		OutputDebugStringA(directory.c_str());

		/// copy the dll into the directory
		CopyFileA(narrowed_module_path.c_str(), directory.c_str(), TRUE);
	}
	catch(std::exception& e)
	{
		OutputDebugStringA(e.what());
	}
	
	return module;
}

void vac_dumper::initialize(HMODULE module)
{
	OutputDebugStringA("vac_dumper::initialize");
	MODULEINFO module_info{};
	GetModuleInformation(GetCurrentProcess(), GetModuleHandleA("SteamService.dll"), &module_info, sizeof MODULEINFO);
	
	m_address = (uint8_t*)utils::find_pattern(static_cast<uint8_t*>(module_info.lpBaseOfDll), module_info.SizeOfImage, {0x74, 0x47, 0x6A, 0x01, 0x6A, 0x00 });
	if (!m_address)
	{
		OutputDebugStringA("can not find m_address!");
		return;
	}
		
	m_original_byte = *m_address;

	wchar_t path[MAX_PATH];
	GetModuleFileNameW(module, path, MAX_PATH);
	m_module_path = path;
	m_module_path = m_module_path.substr(0, m_module_path.find_last_of(L"\\/") + 1);

	OutputDebugStringA("byte patch success!");
}

void vac_dumper::attach(void) {
	/// force vac to loadlibrary it's modules
	write_byte(jmp_opcode);
	utils::hook_iat("SteamService.dll", "KERNEL32.dll", "LoadLibraryExW", (void*)&hk_load_library);
}

void vac_dumper::detach(void) {
	/// restore the original byte
	write_byte(m_original_byte);
	utils::hook_iat("SteamService.dll", "KERNEL32.dll", "LoadLibraryExW", (void*)&LoadLibraryExW);
}

const std::wstring& vac_dumper::get_directory(void) const
{
	return m_module_path;
}

void vac_dumper::write_byte(uint8_t byte) const
{
	DWORD old;
	VirtualProtect(m_address, 0x1, PAGE_EXECUTE_READWRITE, &old);
	*m_address = byte;
	VirtualProtect(m_address, 0x1, old, &old);
}
