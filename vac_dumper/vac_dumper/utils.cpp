#include "utils.h"

#include <Windows.h>
#include <Psapi.h>
#include <string>

#include <modes.h>
#include <hex.h>
#include <sha.h>
#include <comutil.h>
#include <optional>
#include <TlHelp32.h>
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

void utils::make_x86_jmp(unsigned char* address_to_jump_from, uint32_t address_to_jump_to, uint32_t instruction_length)
{
	DWORD old_protect{};
	VirtualProtect(address_to_jump_from, instruction_length, PAGE_EXECUTE_READWRITE, &old_protect);
	const auto jmp_relative_address = (uint32_t)(address_to_jump_to - (uint32_t)address_to_jump_from) - 5;
	*address_to_jump_from = 0xE8;
	*((DWORD*)(address_to_jump_from + 0x1)) = jmp_relative_address;
	for (DWORD x = 0x5; x < instruction_length; x++) *(address_to_jump_from + x) = 0x90;
	VirtualProtect(address_to_jump_from, instruction_length, old_protect, &old_protect);
}

std::uint8_t* utils::find_pattern(const char* module_name, std::vector<uint8_t> pattern)
{
	auto* start = reinterpret_cast<unsigned char*>(GetModuleHandleA(module_name));
	MODULEINFO module_info{};
	GetModuleInformation(GetCurrentProcess(), (HMODULE)start, &module_info, sizeof(MODULEINFO));
	auto* end = start + module_info.SizeOfImage;

	for (auto* p = start; p < end; p++)
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

std::uint8_t* utils::find_pattern(const char* module_name, const char* pattern)
{
	std::vector<unsigned char> converted;
	return find_pattern(module_name, split_bytes(pattern));
}

std::uint8_t* utils::find_pattern(std::uint8_t* start, size_t size, const char* sz_pattern)
{
	auto pattern = split_bytes(sz_pattern);
	auto* end = start + size;

	for (auto* p = start; p < end; p++)
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

std::uint8_t* utils::find_pattern(std::uint8_t* start, const size_t size, std::vector<std::uint8_t> pattern)
{
	auto* end = start + size;

	for (auto* p = start; p < end; p++)
	{
		if (p + pattern.size() > end)
			break;

		if (std::memcmp(p, pattern.data(), pattern.size()) == 0)
			return p;
	}

	return nullptr;
}

void utils::hook_iat(const char* iat_module_name, const char* import_module_name, const char* fn_name, void* new_fn)
{
	const auto module = (uintptr_t)GetModuleHandleA(iat_module_name);

	auto* dos_header = (PIMAGE_DOS_HEADER)module;
	auto* nt_headers = (PIMAGE_NT_HEADERS)(module + dos_header->e_lfanew);

	auto* imports = (PIMAGE_IMPORT_DESCRIPTOR)(module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (auto* import = imports; import->Name; ++import) {
		auto* module_name = (const char*)(module + import->Name);
		if (std::strcmp(module_name, import_module_name) != 0)
			continue;

		auto* original_first_thunk = (PIMAGE_THUNK_DATA)(module + import->OriginalFirstThunk);
		auto* first_thunk = (PIMAGE_THUNK_DATA)(module + import->FirstThunk);

		for (; original_first_thunk->u1.AddressOfData; ++original_first_thunk, ++first_thunk) {
			const auto* name = (const char*)((PIMAGE_IMPORT_BY_NAME)(module + original_first_thunk->u1.AddressOfData))->Name;
			if (std::strcmp(name, fn_name) != 0)
				continue;

			auto* fn_address = &first_thunk->u1.Function;

			DWORD old;
			VirtualProtect(fn_address, sizeof(new_fn), PAGE_READWRITE, &old);
			*fn_address = (DWORD_PTR)new_fn;
			VirtualProtect(fn_address, sizeof(new_fn), old, &old);
			break;
		}
		break;
	}
}

std::string utils::hash_sha256(std::uint8_t* data, size_t size)
{
	std::string hashed;

	CryptoPP::SHA256 hash;
	unsigned char digest[CryptoPP::SHA256::DIGESTSIZE];

	hash.CalculateDigest(digest, reinterpret_cast<CryptoPP::byte*>(data), size);
	CryptoPP::HexEncoder encoder;
	encoder.Attach(new CryptoPP::StringSink(hashed));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	return hashed;
}

std::string utils::get_curent_directory()
{
	char path[MAX_PATH];
	GetModuleFileNameA(GetModuleHandleA(nullptr), path, MAX_PATH);
	std::string str_path = path;
	str_path = str_path.substr(0, str_path.find_last_of("\\/") + 1);
	return str_path;
}


std::string utils::narrowString(std::wstring& str)
{
	bstr_t b(str.c_str());
	char* ptr = b;
	return ptr;
}

PIMAGE_SECTION_HEADER utils::get_text_section(uint8_t* module)
{
	auto* dos_header = (PIMAGE_DOS_HEADER)module;
	auto* nt_headers = (PIMAGE_NT_HEADERS)((uintptr_t)module + dos_header->e_lfanew);
	auto* section_header = (PIMAGE_SECTION_HEADER)(nt_headers + 1);

	for (auto i = 0Ui16; i < nt_headers->FileHeader.NumberOfSections; ++i)
	{
		auto& section = section_header[i];
		
		if (std::strstr((const char*)section.Name, ".text"))
			return &section;
	}
	
	return nullptr;
}

HANDLE utils::create_file(std::string full_path)
{
	return CreateFileA(full_path.c_str(),              // name of the write
		GENERIC_WRITE,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		CREATE_NEW,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);
}

bool utils::write_line_to_file(HANDLE file_handle, std::string line)
{
	DWORD written;
	line += "\n";
	return WriteFile(file_handle, line.c_str(), line.size()/* + 1*/, &written, nullptr); // no need to write null terminator to text line
																						// as it will be interpreted as space.
}

bool utils::write_buffer_to_file(HANDLE file_handle, std::uint8_t* p_buffer, size_t size)
{
	DWORD written;
	return WriteFile(file_handle, p_buffer, size, &written, nullptr);
}

bool utils::file_exists(std::string full_path)
{
	DWORD dwAttrib = GetFileAttributesA(full_path.c_str());

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

uintptr_t utils::get_process_module(uint32_t process_id, std::wstring module_name)
{
	MODULEENTRY32 me32{};
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);
		return 0;
	}

	do
	{
		if (!_wcsicmp(me32.szModule, module_name.c_str()))
		{
			CloseHandle(hModuleSnap);
			return reinterpret_cast<uintptr_t>(me32.modBaseAddr);
		}

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);

	return 0;
}

std::optional<std::vector<MODULEENTRY32W>> utils::get_process_modules(uint32_t process_id)
{
	std::vector<MODULEENTRY32W> modules;
	MODULEENTRY32 me32{};
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return {};
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);
		return {};
	}

	do
	{
		modules.push_back(me32);
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);

	if (modules.empty())
		return {};
	
	return modules;
}

std::optional<std::vector<PROCESSENTRY32W>> utils::get_all_processes()
{
	std::vector<PROCESSENTRY32W> processes;
	PROCESSENTRY32 pe32{};
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return {};
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return {};
	}

	do
	{
		processes.push_back(pe32);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	if (processes.empty())
		return {};

	return processes;
}

HMODULE utils::get_module_containing_address(uintptr_t address)
{
	auto modules = get_process_modules(GetCurrentProcessId());
	if (modules)
	{
		for (auto& module : *modules)
		{
			auto module_start = (uintptr_t)module.hModule;
			auto module_end = module_start + module.modBaseSize;
			if (address >= module_start && address <= module_end)
			{
				return module.hModule;
			}
		}
	}
	return nullptr;
}

uint32_t utils::get_process_id(std::wstring process_name)
{
	PROCESSENTRY32 pe32{};
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	do
	{
		if (!_wcsicmp(pe32.szExeFile, process_name.c_str()))
		{
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return false;
}

