#include <iostream>
#include <string>


#include "run_vac.h"
#include "util.h"
#include "vac_vector.h"

using namespace std;


//calling vac functions with your vac_vector will cause heap corruption(if your vector needs to be freed)
//because an object that is allocated by C++'s new can not be deleted by C's free.
int main(int argc, char* argv[])
{
	Sleep(10000);
	auto print_idxs = [] { cout << "Module indexes: " << endl;  for (auto i = 0; i < (int)vac_module::vac_module_index::MODULE_END; i++) cout << i << endl; };
	auto args = util::get_args(argc, argv);
	
	if (args.empty())
	{
		cout << "Not enough arguments, please specify a module index!" << endl;
		print_idxs();
		return -1;
	}

	const auto module_idx = static_cast<vac_module::vac_module_index>(stoi(args[0]));
	
	switch (module_idx)
	{
	case vac_module::vac_module_index::MODULE_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067:
	{
		auto print_usage = []()
		{
			cout <<
				R"(Usage: <idx> <"memory" or "file" or "threads"> <process_id or file_id> <memory_address or volume serial number> or 0)"
				<< endl;
		};

		auto handler = run_vac::handler_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067;
		if(args.size() != 4)
		{
			print_usage();
			return -1;
		}

		if (args[1] == "memory")
		{
			auto process_id = stoul(args[2]);
			auto memory_address = stoul(args[3]);
			handler(module_idx, vac_module::scan_id::memory_file_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067,
			                                                                                  false, process_id, memory_address);
		}
		else if (args[1] == "file")
		{
			auto file_id = stoull(args[2]);
			auto volume_serial = stoul(args[3]);
			handler(module_idx, vac_module::scan_id::memory_file_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067,
									true, file_id, volume_serial);
			//call run_vac
		}
		else if (args[1] == "threads")
		{
			auto process_id = stoul(args[2]);
			handler(module_idx, vac_module::scan_id::thread_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067,
									false, process_id, 0);
		}
		else
		{
			print_usage();
			return -1;
		}
		break;
	}
	
	case vac_module::vac_module_index::MODULE_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A:
	{
		auto print_usage = []()
		{
			cout <<
				R"(Usage: <idx> <"handles"> <to_process_id>)"
				<< endl;
		};

		auto handler = run_vac::handler_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A;
		if (args.size() != 3)
		{
			print_usage();
			return -1;
		}
		if (args[1] == "handles")
		{
			auto process_id = stoul(args[2]);
			handler(module_idx, vac_module::scan_id::handles_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A,
				process_id);
		}
		else
		{
			print_usage();
			return -1;
		}
		break;
	}
	default:
	{
		cout << "Unknown module index!" << endl;
		print_idxs();
		return -1;
	}
		
	}
	
}