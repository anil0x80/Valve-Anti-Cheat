#include "vac_vector.h"


#include <algorithm>
#include <Windows.h>
#include <iostream>
#include "ida_defs.h"


#include "util.h"

vac_vector::vac_vector(uint8_t* memory, int memory_size)
{
	resize((memory_size + 3) >> 2, true);
	std::memcpy(p_memory, memory, memory_size);
	calculate_size();
}

vac_vector::vac_vector(uint32_t item)
{
	resize(1);
	*p_memory = item;
	size = 1;
	size_in_bits = 32;
	calculate_size();
}

vac_vector::vac_vector(vac_vector& other)
{
	resize(other.size);
	size = other.size;
	size_in_bits = other.size_in_bits;

	std::memcpy(p_memory, other.p_memory, other.size * 4);
}

vac_vector::vac_vector(vac_vector&& other) noexcept
{
	std::swap(p_memory, other.p_memory);
	std::swap(size, other.size);
	std::swap(max_size, other.max_size);
	std::swap(size_in_bits, other.size_in_bits);
}

vac_vector& vac_vector::operator=(const vac_vector& other)
{
	if (this != &other)
	{
		size = 0;
		resize(other.size);
		std::memcpy(p_memory, other.p_memory, other.size * 4);
	}
	return *this;
}

vac_vector& vac_vector::operator=(vac_vector&& other) noexcept
{
	HeapFree(GetProcessHeap(), 0, p_memory);
	//free(p_memory);
	p_memory = nullptr;

	std::swap(p_memory, other.p_memory);
	std::swap(size, other.size);
	std::swap(max_size, other.max_size);
	std::swap(size_in_bits, other.size_in_bits);

	return *this;
}

vac_vector::~vac_vector()
{
	if (p_memory)
	{
		HeapFree(GetProcessHeap(), 0, p_memory);
		//free(p_memory);
		p_memory = nullptr;
	}

}

void vac_vector::swap(vac_vector& another) noexcept
{
	std::swap(p_memory, another.p_memory);
	std::swap(size, another.size);
	std::swap(max_size, another.max_size);
	std::swap(size_in_bits, another.size_in_bits);
}

void vac_vector::add_from_index(vac_vector& other, int start_idx)
{
	const auto size_required = std::max(other.size + start_idx, size);
	resize(size_required + 1, true); // 1 for carry
	auto* p_start = &p_memory[start_idx];
	uint32_t last_high = 0;
	for (int i = 0; i < other.size; i++)
	{
		auto other_element = other.p_memory[i];
		uint32_t sum_high = (*p_start + (unsigned __int64)other_element) >> 32;
		uint32_t sum_low = *p_start + other_element;
		*p_start = sum_low + last_high;
		p_start++;
		last_high = (__PAIR__(sum_high, last_high) + (unsigned int)sum_low) >> 32;
	}
	while (last_high)
	{
		*p_start += last_high; //add carry to result.
		p_start++;
		last_high = (uint8_t)__CFADD__(last_high, *p_start);
	}

	if (!p_memory[size - 1]) //if there is no carry
	{
		size_in_bits -= 32;
		size -= 1;
	}
}

void vac_vector::multiply(vac_vector& other)
{
	vac_vector total{0}; //total represents total multiply
	vac_vector temp{0}; // temp represents current multiply
	total.resize(size + other.size + 2, true);
	temp.resize(other.size + 1, true);

	for (auto i = 0; i < size; i++)
	{
		uint32_t val = p_memory[i];
		int32_t unk_val = 0;
		for (int j = 0; j < other.size; j++)
		{
			uint64_t result = other.p_memory[j] * (uint64_t)val;
			temp.p_memory[j] = (uint32_t)(unk_val + result);
			unk_val = __CFADD__(unk_val, (uint32_t)result) + HIDWORD(result);
		}
		temp.p_memory[other.size] = unk_val;
		
		total.add_from_index(temp, i);
	}
	total.calculate_size();
	swap(total);
}

bool vac_vector::subtract_from_index(vac_vector& other, int start_idx)
{
	/* substract a2 from this, starting at index element size */
//element size is the index that we will start substracting.
	if (other.size > start_idx && size_in_bits >= other.size_in_bits)
	{
		//idk why is this checked here.
		if (this->size_in_bits == other.size_in_bits)
		{
			// do operations starting from a2's element size.
			// it is probably the last elemnt our vector, too, as our size_in_bits were same.
			auto temp = other.size;
			for (auto i = other.size - 1; temp > start_idx; --i)
			{ // we are looping the "extra" elements of a2 vector
				// if our vector's element is smaller than a2, return 0.
				if (p_memory[i] < other.p_memory[i])
					return false; //could this be for preventing unsigned overflow?
				if (p_memory[i] != other.p_memory[i])
					break;
				
				temp--;
			}
		}
		//if element_size is 5, it means first a2.size - 5 element will be substracted 
		auto* p_subtract_from = &p_memory[start_idx];
		auto* p_subtract_value = &other.p_memory[start_idx];

		uint32_t unk = 0;
		for (int i = other.size - start_idx; i; i--)
		{//start substraction from idx element_size, count a2.size - element_size (till end.)
			const auto will_overflow = *p_subtract_from < *p_subtract_value;
			const auto result = *p_subtract_from - *p_subtract_value;
			*p_subtract_from = result - unk;
			unk = (-(int8_t)will_overflow - (result < unk)) & 1;

			p_subtract_from++;
			p_subtract_value++;
		}
		if (unk)
		{
			bool will_overflow;
			do
			{
				will_overflow = *p_subtract_from < unk;
				*p_subtract_from -= unk;
				p_subtract_from++;
				unk = will_overflow;
			} while (will_overflow);
		}
	}
	else
		return false;

	calculate_size();
	return true;
}

void vac_vector::append_zero_bits_to_beginning(uint32_t bit_size)
{
	vac_vector const_1(1 << (bit_size & 0x1F)); //bit_size % 32
	vac_vector temp;
	temp.add_from_index(const_1, bit_size >> 5);
	multiply(temp);
}

void vac_vector::print()
{
	for(int i = 0; i < size; i++)
	{
		std::cout << p_memory[i] << std::endl;
	}
}

void vac_vector::resize(int new_size, bool zero_initialize)
{
	if (size < new_size)
	{ // we gotta do some copying 
		auto* p_old = p_memory;
		//BRUH, MALLOC HERE ALLOCATES FROM C++ HEAP, NOT PROGRAM HEAP THATS WHY FREEING IT CRASHES ON VAC MODULE!
		//p_memory = (uint32_t*)malloc();// new uint32_t[new_size];
		typedef PVOID(__stdcall* func_)(PVOID  HeapHandle, ULONG  Flags, SIZE_T Size);
		auto* proc = (func_)GetProcAddress(GetModuleHandleA("ntdll"), "RtlAllocateHeap");
		
		p_memory = (uint32_t*)proc(GetProcessHeap(), 0, new_size * 4);
		
		
		max_size = new_size;

		if (p_old)
		{
			std::memcpy(p_memory, p_old, size * 4);
			HeapFree(GetProcessHeap(), 0, p_old);
			//free(p_old);
		}
	}
	if (zero_initialize)
	{
		while (size < new_size)
			p_memory[size++] = 0;
		size_in_bits = 32 * size;
	}
}

void vac_vector::calculate_size()
{
	auto bit_size = 0;
	if (size)
	{
		auto* p_last = &p_memory[size - 1];
		for (auto i = 0; i < size; i++)
		{
			if (*p_last--)
				break;
			size--;
		}
		if (size)
		{
			auto idx = 0;
			_BitScanReverse((unsigned long*)&idx, p_memory[size - 1]);
			bit_size = 32 * size + idx - 31;
		}
	}
	
	size_in_bits = bit_size;
 }

uint32_t vac_vector::shift_bits_from_bit_pos_index_to_index(uint32_t bit_pos, int index)
{
/*
 *
    0,1,2,3,4,5,6 -> (64, 2) == 0,1,4,5,6  (the values at index to pos + index - 1(included) is discarded)
	copy source: bits at pos / 32 + index,
	copy destination: index
	copy size: pos to end

	changes in size and size in pos
	represents that the data at position pos to end
	is discarded after copy operation.

	basically this is a "shift".
*/
	uint32_t result = 0;

	if (!bit_pos || !size_in_bits)
		return result;

	if (bit_pos >= (uint32_t)size_in_bits)
	{
		// invalidate
		size_in_bits = 0;
		size = 0;
		return result;
	}

	auto remainder_from_bits = bit_pos % 32;
	auto elements_from_bits = bit_pos / 32;
	//could this function be named as shift_to_idx, from position pos?
	if (elements_from_bits)
	{
		//SIZE OF COPIED DATA IS elements_from_bits 
		/* copy elements TO index FROM (size_of_elements, end)*/
		auto temp = index;
		for (auto i = elements_from_bits + index; i < (uint32_t)size; i++)
		{
			p_memory[temp++] = p_memory[i];
		}
		result = 32 * elements_from_bits; // new pos
		size -= elements_from_bits;
		size_in_bits -= 32 * (int32_t)elements_from_bits; // BRUH
	}
	
	if (remainder_from_bits)
	{
		auto* p_index = p_memory + index;
		auto offset = size - index - 1;
		if (offset != 1) // if index is the not second last element
		{
			if (remainder_from_bits == 1)
			{ 
				for (auto i = offset; i; i--)
				{
					*p_index = (*p_index >> 1) | (p_index[1] << 31);
					p_index++;
				}
			}
			else
			{
				for (auto i = offset; i; i--)
				{
					*p_index = (*p_index >> remainder_from_bits) | (p_index[1] << (32 - remainder_from_bits));
					p_index++;
				}
			}
		}
		*p_index = *p_index >> remainder_from_bits;
		size_in_bits -= remainder_from_bits;
		result = (size_in_bits + 31) >> 5;
		size = result;
	}
	
	return result;
}

//OH, v2 is OLD this. so its kind of like a backup, since subtraction will impact this,
//we instead swap with v2 and keep our old state there.
void vac_vector::subtract_ex(vac_vector v1, vac_vector& v2)
{
	// there is a bug in this code!
	/*
	 * description:
	 * subtract v1 from this 
	 * save the results at v2
	 * this can hold sign bit or smt, idk
	 * 
	 */
	if(v1.size_in_bits)
	{
		/* calculate difference in bit sizes between this and v1*/
		auto size_difference_in_bits = std::max(size_in_bits - v1.size_in_bits, 0);  // difference between this and a2
		/* make enough space in v1 to add elements */
		v1.append_zero_bits_to_beginning(size_difference_in_bits);

		/* swap this with v2, invalidate this, v2 is the backup of old this. */
		swap(v2);
		size_in_bits = 0;
		size = 0;

		/* resize this to hold some data that idk */
		auto idx = size_difference_in_bits >> 5;
		resize(idx + 1, true);
		
		while(true)
		{
			// the same as using this here, but instead we did a backup and now this is v2 and v2 is old this.
			// so we keep our internal state, but v2 is the result
			if(v2.subtract_from_index(v1, idx))
				p_memory[idx] |= 1 << (size_difference_in_bits & 0x1F);// if its multiple of 8, set this idx as 1
			
			if (!size_difference_in_bits--)
				break;

			idx = size_difference_in_bits >> 5;
			v1.shift_bits_from_bit_pos_index_to_index(1, idx); 
		}
		calculate_size();
	}
}

void vac_vector::encryption_phase_1(vac_vector& enc_params_1, vac_vector& enc_params_2)
{
	auto bit_size = enc_params_2.size << 6; //get enough bits that can hold  enc_params_2.size*2 32 bit values.
	vac_vector const_1(1);
	const_1.append_zero_bits_to_beginning(bit_size); //this is done before subtraction and probably for padding

	auto size_2 = enc_params_2.size << 6;
	vac_vector subtract_result;
	const_1.subtract_ex(enc_params_2, subtract_result); // subtract_result = const_1 - enc_params_2

	int i = 0;
}

