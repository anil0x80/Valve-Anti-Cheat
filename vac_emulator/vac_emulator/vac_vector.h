#pragma once

#include <cstdint>

//fuck this class..
class vac_vector
{ // i hope there are no bugs.
public:
	vac_vector() = default;
	vac_vector(uint8_t* memory, int memory_size);
	vac_vector(uint32_t item);
	vac_vector(vac_vector& other);
	vac_vector(vac_vector&& other) noexcept;
	vac_vector& operator=(const vac_vector& other);
	vac_vector& operator=(vac_vector&& other) noexcept;
	~vac_vector();
	void swap(vac_vector& another) noexcept;

	
	void add_from_index(vac_vector& other, int start_idx);
	void multiply(vac_vector& other);
	bool subtract_from_index(vac_vector& other, int start_idx);
	
	void append_zero_bits_to_beginning(uint32_t bit_size);
	void print();
	void resize(int new_size, bool zero_initialize = false);
	void calculate_size();
	uint32_t shift_bits_from_bit_pos_index_to_index(uint32_t bit_pos, int32_t index);
	void subtract_ex(vac_vector v1, vac_vector& v2);
	

	static void encryption_phase_1(vac_vector& enc_params_1, vac_vector& enc_params_2);

	uint32_t* p_memory{};
	/* these sizes are represented by element size*/
	int max_size{};
	int size{};
	int size_in_bits{};
private:

};