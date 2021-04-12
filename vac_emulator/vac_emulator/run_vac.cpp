#include "run_vac.h"


#include <memory>
#include <stdexcept>
#include <ctime>
#include <iostream>


#include "ice_key.h"
#include "util.h"
#include "vac_module.h"
#include "vac_vector.h"



void prepare_module_and_packet(const char* module_name, vac_module::vac_module_index idx,
				vac_module::scan_id scan_id, vac_module::packet_type* p_packet, vac_module::module_type* p_module)
{
	*p_module = std::make_unique<vac_module>(module_name, idx);
	*p_packet = (*p_module)->create_packet(scan_id);
}


void run_vac::handler_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067(vac_module::vac_module_index idx, vac_module::scan_id scan_id, bool file_scan, uint64_t arg_1, uint64_t arg_2)
{
	using namespace module_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067;
	
	const auto* module_name = "7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067.dll";
	
	vac_module::packet_type packet = nullptr;
	vac_module::module_type module = nullptr;
	try
	{
		prepare_module_and_packet(module_name, idx, scan_id, &packet, &module);
	}
	catch(std::exception& e)
	{
		std::cout << "Exception! :" << e.what() << std::endl;
		return;
	}

	/* prepare payload */
	auto* payload = reinterpret_cast<in*>(packet->payload_data);

	/* prepare payload args*/
	const auto is_thread_scan = scan_id == vac_module::scan_id::thread_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067;
	if (is_thread_scan)
	{
		/* thread mode */
		const auto process_id = static_cast<uint32_t>(arg_1);
		payload->params.thread.target_process_id = process_id;
	}
	else
	{
		if (file_scan)
		{
			/* file mode */
			const auto file_id = arg_1;
			const auto volume_id = static_cast<uint32_t>(arg_2);
			/* fill params */
			payload->params.file.c_0 = 0;
			payload->params.file.file_id = file_id;
			payload->params.file.volume_serial_number = volume_id;
		}
		else
		{
			/* process mode */
			const auto process_id = static_cast<uint32_t>(arg_1);
			const auto target_address = static_cast<uint32_t>(arg_2);
			/* fill params */
			payload->params.memory.target_process_id = process_id;
			payload->params.memory.target_address = target_address;
		}
	}

	auto result = module->run_module(packet);
	if (is_thread_scan)
		print((out_thread*)result.second.get());
	else
		print((out_file_memory*)result.second.get());
}

//this guy crashes shamefully (at ntqsi manual syscall), i have no idea if its because of a bug in VAC code, or my fuck-up.
void run_vac::handler_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A(vac_module::vac_module_index idx,
	vac_module::scan_id scan_id, uint32_t process_id)
{
	using namespace module_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A;

	const auto* module_name = "2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A.dll";

	vac_module::packet_type packet = nullptr;
	vac_module::module_type module = nullptr;
	try
	{
		prepare_module_and_packet(module_name, idx, scan_id, &packet, &module);
	}
	catch (std::exception& e)
	{
		std::cout << "Exception! :" << e.what() << std::endl;
		return;
	}

	/* prepare payload */
	auto* payload = reinterpret_cast<in*>(packet->payload_data);
	payload->params.game_process_id = process_id;
	payload->params.is_system_x64 = 1; // constant, i don't think i will run this on x86 machine
	payload->params.ntopenprocess_syscall_idx = util::get_syscall_idx("NtOpenProcess");
	payload->params.ntquerysysteminformation_syscall_idx = util::get_syscall_idx("NtQuerySystemInformation");

	auto result = module->run_module(packet);
	print((out*)result.second.get());
}

void run_vac::handler_C3F1CCCE88542C99234744D00280EB5EBA8EC6F054D7C8272D969D739F8DDCA5(vac_module::vac_module_index idx,
	vac_module::scan_id scan_id, uint32_t hashed_service_name)
{
	
}
