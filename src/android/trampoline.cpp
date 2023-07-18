/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "arm_disassembler.h"
#include "arm_instructions.h"
#include "addresser.h"
#include "buffer.h"
#include "api.h"

namespace alterhook
{
	void trampoline::deleter::operator()(std::byte* ptrampoline) const noexcept
	{
		trampoline_buffer::deallocate(ptrampoline);
	}

	void trampoline::init(std::byte* target)
	{
		if (ptarget == target)
			return;
		if (!is_executable_address(target))
			throw(exceptions::invalid_address(target));
		if (!ptrampoline)
			ptrampoline = trampoline_ptr(trampoline_buffer::allocate());

		positions.clear();
		patch_above = false;
		ptarget = target;

		bool uses_thumb = reinterpret_cast<uintptr_t>(target) & 1;
		bool should_setup_pc_handling = false;
		bool finished = false;
		uintptr_t pc_val = 0;
		size_t unused_dword_pos = 0;
		size_t unused_word_pos = 0;
		size_t unused_halfword_pos = 0;
		size_t unused_byte_pos = 0;
		//const uint8_t size_needed = uses_thumb && (reinterpret_cast<uintptr_t>(target) % 4) ? 
		uint8_t pc_offset = 0;
		std::bitset<16> encountered_reglist{};
		std::bitset<64> tramp_bits{};

		reinterpret_cast<uintptr_t&>(target) &= ~1;
	}
}
