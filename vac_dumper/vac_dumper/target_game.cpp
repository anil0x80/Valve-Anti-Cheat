#include "target_game.h"
#include <ctime>

#include "utils.h"



target_game::target_game(std::wstring process_name) : init_time(std::time(nullptr)),
process_id(utils::get_process_id(process_name)),
process_name(process_name)
{
	if (!process_id)
		OutputDebugStringA("Process id is nul!");
}

time_t target_game::get_init_time()
{
	return init_time;
}

void target_game::dump_info()
{
	if(process_id)
	{
		auto path = utils::get_curent_directory() + "sessions";
		CreateDirectoryA(path.c_str(), nullptr);
		path += "\\";
		path += std::to_string(init_time);
		path += ".txt";
		OutputDebugStringA(path.c_str());
		auto* file_handle = utils::create_file(path);
		if (file_handle != INVALID_HANDLE_VALUE)
		{
			auto process_modules = utils::get_process_modules(process_id);
			if(process_modules)
			{
				utils::write_line_to_file(file_handle, "TARGET_INFORMATION");
				for(auto& module: *process_modules)
				{
					std::wstring w_module_name = module.szModule;
					auto module_name = utils::narrowString(w_module_name);
					utils::write_line_to_file(file_handle, module_name + " : " + utils::int_to_hex((uintptr_t)module.modBaseAddr));
				}
			}
			auto all_processes = utils::get_all_processes();
			if (all_processes)
			{
				utils::write_line_to_file(file_handle, "PROCESS_INFORMATION");
				for(auto& process: *all_processes)
				{
					std::wstring w_process_name = process.szExeFile;
					auto process_name = utils::narrowString(w_process_name);
					utils::write_line_to_file(file_handle, process_name + " : " + utils::int_to_hex(process.th32ProcessID));
				}
			}
			
			CloseHandle(file_handle);
		}
	}
}
