#pragma once
#include <string>

class target_game
{
public:
	explicit target_game(std::wstring process_name);

	time_t get_init_time();
	void dump_info();
	
private:
	time_t init_time;
	uint32_t process_id;
	std::wstring process_name;
};
