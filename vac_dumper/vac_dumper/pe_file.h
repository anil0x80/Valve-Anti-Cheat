#pragma once
#include <optional>
#include <string>
#include <vector>

class pe_file
{
public:
	struct pe_section
	{
		std::byte* start;
		size_t size;
	};

	explicit pe_file(std::string path);

	std::optional<pe_section> get_section(std::string section_name);
	std::vector<std::byte>* get_file_buffer();
	std::string get_file_path();
	size_t get_size_of_image();
	void overwrite_original();


private:
	/* file related things */
	std::string path;
	std::vector<std::byte> file_buffer;
	bool is_amd64;
};

