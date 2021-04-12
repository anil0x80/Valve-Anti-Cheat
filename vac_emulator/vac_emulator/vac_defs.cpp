#include "vac_defs.h"


#include "util.h"
#include <iostream>
#include <string>

using util::int_to_hex;
using std::cout;
using std::endl;

#define print_field(info,field) cout << (info) << out->field << endl;

void print_handle_info_1(VAC_HANDLE_HOLDER_DATA_1* info)
{
	cout << "----------handle_holder_info_1------------" << endl;

	cout << "Last Error: " << int_to_hex(info->last_error) << endl;

	cout << "Process ID: " << int_to_hex(info->process_id) << endl;
	cout << "Handle Access: " << int_to_hex(info->handle_access_mask) << endl;
	
	if (info->process_name[0])
	{
		cout << "Process Path: " << info->process_name << endl;
		cout << "File Volume Serial: " << info->file_volume_serial_number << endl;
		cout << "File ID: " << info->file_id << endl;
	}
		
	else
		cout << "Process name and file information was not retrieved!" << endl;
	
	cout << "---------handle_holder_info_1_end------------" << endl;
}

void print_handle_info_2(VAC_HANDLE_HOLDER_DATA_2* info)
{
	cout << "---------handle_holder_info_2------------" << endl;

	cout << "Process ID " << int_to_hex(info->process_id) << " has " << info->total_process_handles << " handles!" << endl;

	cout << "---------handle_holder_info_2_end------------" << endl;
}

void print_header_info(out_header* header)
{
	cout << "[HEADER] Packet Number: " << int_to_hex(header->packet_number) << endl;
	cout << "[HEADER] Payload Result: " << int_to_hex(header->general_status) << endl;
	if (header->general_status == import_init_fail)
	{
		cout << "Module has failed to initialize IAT properly.." << endl;
		return;
	}
	cout << "[HEADER] General Status: " << header->general_status << endl;
}

std::string get_trust_result_string(HRESULT trust, HRESULT last_error)
{
	switch(trust)
	{
	case 0:
		return "File is signed and signature was verified!";
	case TRUST_E_NOSIGNATURE:
		if (TRUST_E_NOSIGNATURE == last_error || TRUST_E_SUBJECT_FORM_UNKNOWN == last_error
			|| TRUST_E_PROVIDER_UNKNOWN == last_error)
			return "File was not signed!";
		else
			return "Unknown error occured";
	case TRUST_E_EXPLICIT_DISTRUST:
		return "File signature is present, but specifically disallowed!";
	case TRUST_E_SUBJECT_NOT_TRUSTED:
		return "File signature is present, but disallowed!";
	case CRYPT_E_SECURITY_SETTINGS:
		return "Admin policy has disabled user trust, no errors.";
	default:
		return "Unknown error, trust: " + int_to_hex(trust) + "last_error: " + int_to_hex(last_error);
	}
}

auto get_sha1_as_string(char* p_sha1)
{
	return util::base_64_encode((uint8_t*)p_sha1, 20);
}

void print_buffer_analysis()
{
	//todo
	return;
}

auto get_md5_as_string(VAC_MD5_RESULT* md5)
{
	return util::base_64_encode((uint8_t*)md5, sizeof VAC_MD5_RESULT);
}

void print_thread_info(VAC_PACKET_OUT_THREAD_DATA* thread)
{
	cout << "-------------thread------------" << endl;

	cout << "Thread ID: " << int_to_hex(thread->thread_id) << endl;
	cout << "Start Address: " << int_to_hex(thread->start_address) << endl;
	
	if (thread->start_address_flags & ENTRY_MEMORY_LINKED)
		cout << "Start Address is LINKED to MEMORY (NTQVM)!" << endl;
	else
		cout << "Start Address is NOT LINKED to MEMORY (NTQVM)!" << endl;

	// below check does not mean anything for 712 module, as it does not query process peb modules.
	//if(thread->start_address_flags & ENTRY_PEB_LINKED)
	//	cout << "Start Address is LINKED to PEB (LDR)!" << endl;
	//else
	//	cout << "Start Address is NOT LINKED to PEB (LDR)!" << endl;

	cout << "------------thread_end------------" << endl;
}

void print_cert_info(VAC_PACKET_OUT_PE_CERTIFICATE_INFO* pe_cert)
{
	cout << "--------------cert_info--------------" << endl;
	
	const auto trust_result = (HRESULT)pe_cert->win_verify_trust_return_value;
	const auto trust_last_error = (HRESULT)pe_cert->win_verify_trust_last_error;
	cout << "Trust Result: " << get_trust_result_string(trust_result, trust_last_error) << endl;;
	
	if (pe_cert->file_certificate_hash[0])
		cout << "File Certificate Hash: " << get_sha1_as_string(pe_cert->file_certificate_hash) << endl;
	if (pe_cert->file_certificate_name[0])
		cout << "File Certificate Name: " << pe_cert->file_certificate_name << endl;
	if (pe_cert->issuer_certificate_hash[0])
		cout << "Issuer Certificate Hash: " << get_sha1_as_string(pe_cert->issuer_certificate_hash) << endl;
	if (pe_cert->issuer_certificate_name[0])
		cout << "Issuer Certificate Name: " << pe_cert->issuer_certificate_name << endl;

	cout << "First 8 bytes of PE overlay: " << util::base_64_encode((uint8_t*)pe_cert->overlay_first_8, 8) << endl;
	
	cout << "------------cert_info_end-------------\n" << endl;
}

void print_pe_information(VAC_PACKET_OUT_PE_GENERIC_INFO* pe, bool from_memory)
{
	if (from_memory)
		cout << "-------------pe_info_memory-----------------" << endl;
	else
		cout << "-------------pe_info_disk-----------------" << endl;

	cout << "Last Error: " << int_to_hex(pe->last_error) << endl;

	cout << "Queried address is " << (pe->is_linked_address ? "linked to PEB" : "NOT linked to PEB") << endl;
	if (from_memory)
	{
		cout << "Memory Size: " << int_to_hex(pe->total_contigious_memory_size) << endl;
		cout << "First Region Protection: " << int_to_hex(pe->first_region_protection) << endl;
		cout << "Total Region Protection: " << int_to_hex(pe->total_region_protect) << endl;
		cout << "Memory Region Count: " << int_to_hex((uint32_t)pe->non_free_region_count) << endl;
	}
	cout << "PE Image Size: " << int_to_hex(pe->size_of_image_pe) << endl;
	cout << "Checksum: " << int_to_hex(pe->checksum_pe) << endl;
	cout << "TimeDateStamp: " << int_to_hex(pe->time_data_stamp_pe) << endl;
	cout << "Entry Point RVA: " << int_to_hex(pe->entry_point_rva_pe) << endl;
	cout << "Section Count: " << int_to_hex((uint32_t)pe->number_of_sections_pe) << endl;
	cout << "PDB Path: " << pe->pdb_path << endl;
	cout << "Raw MD5: " << get_md5_as_string(&pe->raw_buffer_md5) << endl;
	cout << "MD5_1: " << get_md5_as_string(&pe->pe_md5_1) << endl;
	cout << "MD5_2: " << get_md5_as_string(&pe->pe_md5_2) << endl;
	if (pe->pe_rsrc_xor != 0x80000000)
		cout << "Resource Directory MD5: " << get_md5_as_string(&pe->pe_rsrc_md5) << endl;
	else
		cout << "Resource Directory NOT present!" << endl;

	if (pe->number_of_sections_pe)
	{
		cout << "Section Information:" << endl;
		for (auto i = 0; i < pe->number_of_sections_pe; i++)
		{ //hash differences between memory and file ???
			cout << "---------------section start--------------------" << endl;
			auto* p_section = &pe->sections[i];
			cout << "Name: " << (const char*)p_section->name << endl;
			cout << "RVA: " << int_to_hex(p_section->rva) << endl;
			cout << "Raw Size: " << int_to_hex(p_section->size_of_raw_data) << endl;
			cout << "Characteristics: " << int_to_hex(p_section->characteristics) << endl;
			cout << "Hash: " << get_md5_as_string(&pe->pe_sec_md5s[i]) << endl;
		}
	}
	else
		cout << "No section information!" << endl;
	
	cout << "---------------pe_info_end-----------------\n" << endl;
}


void module_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067::print(out_file_memory* out)
{
	if(out)
	{
		auto file_found = true;
		print_header_info(&out->header);
		
		if (out->in_process_id == 0)
		{
			cout << "Mode: File Analyzer" << endl;
			cout << "Target Volume Serial ID: " << int_to_hex(out->pe_volume_serial_number) << endl;
			cout << "Target File ID: " << int_to_hex(out->pe_file_id) << endl;
			cout << "PEFile result: " << int_to_hex(out->header.general_status) << endl;
			cout << "File ID last error: " << int_to_hex(out->last_error_file_id) << endl;
		}	
		else
		{
			cout << "Mode: Process Analyzer" << endl;
			cout << "Target Process ID: " << int_to_hex(out->in_process_id) << endl;
			cout << "Process Enum Result: " << int_to_hex(out->header.general_status) << endl;
			cout << "Process Creation Time: " << int_to_hex(out->process_creation_time) << endl;

			if (out->module_name[0]) // this guy is not queried for file-id mode.
			{
				cout << "File found on disk with path: " << out->module_name << endl;
				cout << "File ID: " << int_to_hex(out->pe_file_id) << endl;
				cout << "Volume Serial: " << int_to_hex(out->pe_volume_serial_number) << endl;
			}
			else
			{
				file_found = false;
				cout << "Could not retrieve any path for target address!" << endl;
			}
			
			print_pe_information(&out->pe_info_memory, true);
		}

		if (file_found)
		{
			print_pe_information(&out->pe_info_disk, false);
			print_cert_info(&out->pe_cert_info_disk);
			if (std::memcmp(&out->pe_info_disk.pe_md5_2, &out->pe_info_memory.pe_md5_2, 16) != 0)
				cout << "Mismatch between file and disk hash, there might be modifications to memory module!" << endl;
		}
	}
}

void module_7126767666FB5AF9C50171ADB6E093A0979172D16D0EE098E3687606DB0DE067::print(out_thread* out)
{
	if (out)
	{
		/* general status */
		print_header_info(&out->header);
		cout << "Process Context Status: " << int_to_hex(out->proc_ctx_status) << endl;
		cout << "Thread Enum Status: " << int_to_hex(out->thread_enum_status) << endl;
		cout << "Win32 Last Error: " << int_to_hex(out->win32_last_error) << endl;

		/* process info */
		cout << "Process ID: " << int_to_hex(out->process_id) << endl;
		cout << "Process Module Count: " << int_to_hex(out->module_count) << endl; 
		cout << "Process Thread Count: " << int_to_hex(out->number_of_threads) << endl;

		/* thread info */
		for(auto i = 0u; i < out->number_of_threads; i++)
		{
			print_thread_info(&out->thread_info[i]);
		}
	}
}

void module_2CF75D45547A47758E4A167CF5029500AC07BF8AE5314EAAB569C6958A25668A::print(out* out)
{
	if (out)
	{
		print_header_info(&out->header);
		print_field("Last Error: ", last_error); // 0x7A max_handle_count_reached 
		print_field("Total Handles In System: ", total_handles_in_system);
		print_field("Total Handles To Game: ", handles_to_game);
		print_field("Handle Scan Loop Count: ", scan_loop_count);

		bool printed = false;
		for(auto i = 0u; i < out->handles_to_game; i++)
		{
			print_handle_info_1(&out->info_1[i]);
			if (i < 12)
				print_handle_info_2(&out->info_2[i]);
			else if (!printed)
			{
				cout << "WARNING, MAX COUNT REACHED FOR INFO_2, NO MORE DATA!" << endl;
				printed = true;
			}
		}
	}
}

void module_C3F1CCCE88542C99234744D00280EB5EBA8EC6F054D7C8272D969D739F8DDCA5::print(out* out)
{
	//todo...
}
