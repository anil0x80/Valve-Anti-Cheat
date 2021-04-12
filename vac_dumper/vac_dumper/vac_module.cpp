#include "vac_module.h"

#include <Windows.h>
#include <mutex>
#include <utility>
#include <vector>


#include "pe_file.h"
#include "utils.h"

std::mutex g_mutex;
std::vector<vac_module> g_loaded_modules;

vac_module* vac_module::get_module(uintptr_t module_base)
{
	auto result = std::find_if(g_loaded_modules.begin(), g_loaded_modules.end(), [&](vac_module& module) {return module.module_base == module_base; });
	if (result == g_loaded_modules.end())
		return nullptr;
	return &*result;
}

vac_module* vac_module::add_module(uintptr_t module_base, std::string path)
{
	std::lock_guard<std::mutex> guard(g_mutex);
	g_loaded_modules.emplace_back(module_base, path);
	return &g_loaded_modules.back();
}

vac_module::vac_module(uintptr_t module_base, std::string path) : module_base(module_base), path(path)
{
	//auto* text_section = utils::get_text_section((uint8_t*)module_base);
	pe_file file(path); //never use a variable after moving it!
	auto text_section = file.get_section(".text");
	if (!text_section)
		throw std::runtime_error("No text section found for module at base: " + std::to_string(module_base));
	
	text_section_hash = utils::hash_sha256((uint8_t*)text_section->start, text_section->size);
}
