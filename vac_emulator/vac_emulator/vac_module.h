#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "vac_defs.h"

/* global definitions */
constexpr auto VAC_OUTPUT_SIZE = 0x10000u;
constexpr auto VAC_PAYLOAD_SIZE = 0xA0u;
constexpr auto VAC_PACKET_SIZE = 0xB0u;
constexpr auto VAC_FUNCTION_ID = 4;

class vac_module
{
public:
	/* needed definitions */
	enum class vac_module_index
	{
		/* idx, memory, proc_id, address OR idx file file_id volume_serial*/
		MODULE_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067,
		MODULE_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A,
		MODULE_C3F1CCCE88542C99234744D00280EB5EBA8EC6F054D7C8272D969D739F8DDCA5,
		MODULE_END
	};

	std::map <vac_module_index, std::vector<uint8_t>> secondary_ice_keys =
	{
		{
			vac_module_index::MODULE_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067,
			{0xD8,0x82,0x31,0x89,0x85,0x6F,0xB4,0x9B}
			//there is only 1 secondary ice key per module, regardless of scans supported.
		},
		{
			vac_module_index::MODULE_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A,
			{0xCC,0xD5,0x2D,0x5A,0xA1,0xAE,0x77,0x79}
		},
		{
			vac_module_index::MODULE_C3F1CCCE88542C99234744D00280EB5EBA8EC6F054D7C8272D969D739F8DDCA5,
			{0x88,0x4A,0xB4,0xE2,0xCA,0xD9,0xB5,0xB8}
		}
	};

	enum class scan_id : uint32_t
	{
		memory_file_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067 = 0xFC6C338,
		thread_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067 = 0x23A999F,
		handles_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A = 0xBA1E0B2,
		driver_C3F1CCCE88542C99234744D00280EB5EBA8EC6F054D7C8272D969D739F8DDCA5 = 0x86C0108
	};

	
	/* needed definitions */
	using primary_keys = std::map<scan_id, std::vector<uint8_t>>;
	using packet_type = std::unique_ptr<VAC_PACKET>;
	using module_type = std::unique_ptr<vac_module>;
	using run_result = std::pair<int, std::unique_ptr<uint8_t[]>>;
	

	vac_module(const char* module_name, vac_module_index idx);
	packet_type create_packet(scan_id id);
	
	// prepares input packet, decrypts output packet, this is thicc
	run_result run_module(packet_type& packet);
	
private:
	void prepare_packet(packet_type& packet);
	void set_payload_hash(packet_type& packet);
	
	std::string module_name;
	vac_module_index module_idx;
	scan_id current_scan_id;
	uint32_t module_base;
	uint8_t* entry_point;
	primary_keys primary_ice_keys;
	uint8_t* vac_payload_hasher_function;
	uint8_t* vac_packet_encryptor_function;
};
