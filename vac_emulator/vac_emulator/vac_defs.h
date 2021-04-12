#pragma once
#include <cstdint>
#include <Windows.h>
#include <TlHelp32.h>

#pragma pack(push, 1)

enum VAC_STATUS : uint32_t
{
	import_init_fail = 78, // could fill this up, but i am lazy.
};

struct VAC_PACKET
{
	uint32_t scan_id; // a module can support more than one scan routines.
	uint32_t constant_1;
	uint32_t payload_hash; // hash of the decrypted payload
	uint32_t packet_number; // this field is generally random
	uint8_t payload_data[0xA0]; // encrypted with primary ice key
};

struct VAC_NT_HEADER_ENTRY
{
	uint32_t signature;
	uint16_t machine;
	uint16_t number_of_sections;
	uint32_t time_data_stamp;
	uint32_t pointer_to_symbol_table;
};

struct VAC_MD5_RESULT
{
	uint64_t low_part;
	uint64_t high_part;
};

struct VAC_SECTION_INFO
{
	uint32_t size_of_raw_data;
	uint32_t rva;
	uint32_t characteristics;
	uint32_t unk_0;
	uint8_t name[8];
};

struct VAC_PACKET_OUT_PE_CERTIFICATE_INFO
{
	IMAGE_FILE_HEADER file_header;
	IMAGE_OPTIONAL_HEADER32 opt_header;
	uint32_t pad[5];
	char overlay_first_8[8];
	VAC_NT_HEADER_ENTRY nt_header_entry;
	uint32_t win_verify_trust_return_value;
	uint32_t win_verify_trust_last_error;
	char issuer_certificate_hash[20];
	char issuer_certificate_name[40];
	char file_certificate_hash[20];
	char file_certificate_name[40];
};

struct VAC_PACKET_OUT_PE_GENERIC_INFO
{
	uint32_t last_error;
	uint32_t first_region_protection;
	uint32_t total_contigious_memory_size;
	uint32_t total_region_protect;
	uint32_t size_of_image_pe;
	uint32_t time_data_stamp_pe;
	uint32_t checksum_pe;
	uint32_t entry_point_rva_pe;
	uint8_t number_of_sections_pe;
	uint8_t non_free_region_count;
	uint8_t is_linked_address;
	uint8_t sections_plus_4;
	uint32_t raw_buffer_xor;
	uint32_t pe_xor_1;
	uint32_t pe_xor_2;
	uint32_t pe_rsrc_xor;
	uint32_t pe_sec_xors[12];
	VAC_MD5_RESULT raw_buffer_md5;
	VAC_MD5_RESULT pe_md5_1;
	VAC_MD5_RESULT pe_md5_2;
	VAC_MD5_RESULT pe_rsrc_md5;
	VAC_MD5_RESULT pe_sec_md5s[12];
	VAC_SECTION_INFO sections[12];
	char pdb_path[260];
	uint32_t unk_pad[31];
};

enum VAC_THREAD_ENTRY_STATUS : uint32_t
{
	ENTRY_MEMORY_LINKED = 0x1000, // uses ntqueryvirtualmemory with memorysectionname
	ENTRY_PEB_LINKED = 0x2000 // set if address is inside any module found on peb
};

struct VAC_PACKET_OUT_THREAD_DATA
{
	uint32_t thread_id;
	VAC_THREAD_ENTRY_STATUS start_address_flags; // 0x1000: module_name_found_with_ntqvm
								  // 0x2000: start_address_linked_to_module
	uint64_t start_address; // high dword is not queried for the module that i found for now.
};

struct VAC_PACKET_OUT_PE_ANALYSIS
{
	DWORD unk_0[8];
};

struct VAC_HANDLE_HOLDER_DATA_2
{
	uint32_t process_id;
	uint32_t total_process_handles; // number of total process handles hold by target
	// this might be used to determine if target is a system process, as they do have a lot of handles to all kind of processes.
	// but your external cheat will stand out like a dick, just having a process handle to game...
};
struct VAC_HANDLE_HOLDER_DATA_1
{
	uint32_t process_id;
	uint32_t file_volume_serial_number;
	uint64_t file_id;
	uint32_t handle_access_mask;
	uint32_t last_error;
	char process_name[40];
};

struct out_header
{
	uint32_t packet_number;
	uint32_t payload_result;
	uint32_t unk_1;
	uint32_t unk_2;
	uint32_t general_status;
};

struct in_payload_header
{
	uint8_t secondary_ice_key[8];
	uint8_t junk_0[24];
	uint8_t flag_0;
	uint8_t junk_1[63];
};
/*
 * in_header
 * 128 bit arguments
 * in_footer
 */
struct in_payload_footer
{
	uint8_t junk_2[48];
};

namespace module_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067
{
	/*
	 * tests
	 * 1) manually mapped module
	 * 2) peb unlinked module
	 * 3) manually mapped with erased pe header
	 */
	struct out_file_memory
	{
		out_header header;
		uint32_t in_process_id;
		uint64_t process_creation_time;
		VAC_PACKET_OUT_PE_GENERIC_INFO pe_info_disk;
		VAC_PACKET_OUT_PE_GENERIC_INFO pe_info_memory;
		char module_name[256];
		uint32_t pe_volume_serial_number;
		uint64_t pe_file_id;
		uint32_t unk_3;
		uint32_t c_5;
		uint32_t last_error_file_id;
		VAC_PACKET_OUT_PE_ANALYSIS pe_analysis;
		uint32_t unk_4[302];
		VAC_PACKET_OUT_PE_CERTIFICATE_INFO pe_cert_info_disk;
	};

	struct out_thread
	{
		out_header header;
		uint32_t thread_enum_status; //0=success, 61=cant get handle, 62=no threads, 63=unk error
		uint32_t c_0;
		uint32_t win32_last_error;
		uint32_t process_id;
		uint32_t module_count; // modules are not queried for this scan.
		uint32_t proc_ctx_status;
		uint32_t number_of_threads;
		VAC_PACKET_OUT_THREAD_DATA thread_info[253];
	};
	
	//size == 0xA0
	struct in
	{
		in_payload_header header;
		
		union 
		{
			struct
			{
				uint32_t target_process_id; // 24
				uint32_t target_address;
				uint32_t junk[2];
			} memory;
			struct
			{
				uint32_t c_0;
				uint64_t file_id;
				uint32_t volume_serial_number;
			} file;
			struct
			{
				uint32_t target_process_id;
				uint32_t junk[3];
			} thread;
		} params;
		
		in_payload_footer footer;
	};

	void print(out_file_memory* out);
	void print(out_thread* out);
}


namespace module_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A
{
	struct out
	{
		out_header header;
		uint32_t last_error;
		uint32_t handles_to_game;
		uint32_t scan_loop_count;
		uint32_t total_handles_in_system;
		uint32_t unk_0;
		VAC_HANDLE_HOLDER_DATA_2 info_2[11];
		VAC_HANDLE_HOLDER_DATA_1 info_1[62];
	};

	struct in
	{
		in_payload_header header;

		struct
		{
			uint32_t game_process_id;
			uint32_t is_system_x64;
			uint32_t ntquerysysteminformation_syscall_idx;
			uint32_t ntopenprocess_syscall_idx;
		} params;
		
		in_payload_footer footer;
	};

	
	void print(out* out);
}

namespace module_C3F1CCCE88542C99234744D00280EB5EBA8EC6F054D7C8272D969D739F8DDCA5
{
	struct out
	{
		out_header header;
		uint32_t c_0;
		char service_name[256];
		char display_name[256];
		uint32_t service_type;
		uint32_t service_start_type;
		uint32_t service_error_control;
		char service_binary_path_name[256];
		char service_load_order_group[32];
		char service_dependencies[256];
		char service_service_start_name[32];
		uint64_t service_file_id;
		uint32_t service_volume_id;
	};

	struct in
	{
		in_payload_header header;
		struct
		{
			uint32_t junk_0; // 24
			uint32_t hashed_service_name; // 25
			uint32_t junk_1[2]; // 26,27
		} params;
		in_payload_footer footer;
	};

	void print(out* out);
};

#pragma pack(pop)