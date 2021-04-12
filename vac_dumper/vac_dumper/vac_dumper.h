#pragma once
#include <map>
#include <memory>
#include <Windows.h>
#include <string>
#include <vector>
#include <time.h>

class vac_dumper
{
	static constexpr auto jmp_opcode = 0xEB;
public:
	void initialize(HMODULE module);

	void attach(void);

	void detach(void);

	const std::wstring& get_directory(void) const;

private:
	void write_byte(uint8_t byte) const;
	uint8_t* m_address{};
	uint8_t			m_original_byte{};
	std::wstring	m_module_path{};
}; extern vac_dumper g_vac_dumper;
