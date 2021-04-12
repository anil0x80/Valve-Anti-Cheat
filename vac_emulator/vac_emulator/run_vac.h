#pragma once
#include <map>
#include <string>
#include <vector>

#include <stdexcept>
#include "vac_defs.h"
#include "vac_module.h"
#include <iostream>

namespace run_vac
{
	void handler_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067(vac_module::vac_module_index idx, vac_module::scan_id scan_id, bool file_scan, uint64_t arg_1, uint64_t arg_2);
	void handler_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A(vac_module::vac_module_index idx, vac_module::scan_id scan_id, uint32_t process_id);
	void handler_C3F1CCCE88542C99234744D00280EB5EBA8EC6F054D7C8272D969D739F8DDCA5(vac_module::vac_module_index idx, vac_module::scan_id scan_id, uint32_t hashed_service_name);
	//template<typename... Args>
	//void run_vac_handler(vac_module::vac_module_index idx, vac_module::scan_id scan_id,  Args&& ... args)
	//{
	//	
	//	switch(idx)
	//	{
	//	case vac_module::vac_module_index::MODULE_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067:
	//		handler_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067(idx, scan_id, std::forward<Args>(args)...);
	//		break;
	//	case vac_module::vac_module_index::MODULE_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A:
	//		handler_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A(idx, scan_id, std::forward<Args>(args)...);
	//		break;
	//	default:
	//		std::cout << "Unknown index has passed to run_vac_handler!" << std::endl;
	//		break;
	//	}
	//}
}


