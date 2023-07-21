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

	inline namespace init_impl
	{
		enum instruction_set
		{
			IS_ARM, IS_THUMB, IS_UNKNOWN
		};

		enum tbm_flags
		{
			M_BRANCH, M_LINK
		};

		static ALTERHOOK_HIDDEN cs_arm_op* find_pc_reg(const cs_insn& instr) noexcept
		{
			cs_arm_op* operands = instr.detail->arm.operands;
			
			for (uint8_t i = 0, count = instr.detail->arm.op_count; i != count; ++i)
			{
				if (operands[i].type == ARM_OP_REG && operands[i].reg == ARM_REG_PC)
					return &operands[i];
			}
			return nullptr;
		}

		static ALTERHOOK_HIDDEN int64_t find_imm(const cs_insn& instr) noexcept
		{
			cs_arm_op* operands = instr.detail->arm.operands;

			for (uint8_t i = 0, count = instr.detail->arm.op_count; i != count; ++i)
			{
				if (operands[i].type == ARM_OP_IMM)
					return operands[i].imm;
			}
			return INT64_MAX;
		}

		static ALTERHOOK_HIDDEN arm_op_mem* find_mem(const cs_insn& instr) noexcept
		{
			cs_arm_op* operands = instr.detail->arm.operands;

			for (uint8_t i = 0, count = instr.detail->arm.op_count; i != count; ++i)
			{
				if (operands[i].type == ARM_OP_MEM)
					return &operands[i].mem;
			}
			return nullptr;
		}

		struct ALTERHOOK_HIDDEN trampoline_instruction_entry
		{
			const cs_insn& instr;
			instruction_set next_instr_set;
			uint64_t branch_dest = 0;
			std::bitset<16> flags{};

			/*
			* According to the armv7 documentation the only thumb/thumb2 instructions that are allowed to modify the pc (causing a branch)
			* are the following:
			* > ADD Rdn, Rm -> only encoding T2
			* > MOV Rd, Rm -> only encoding T1
			* > All simple branch instructions (obviously): B, BL, CBNZ, CBZ, CHKA, HB, HBL, HBLP, HBP, TBB, TBH
			* > All interworking branch instructions (those change instruction set as well): BLX, BX, BXJ
			* > LDR -> any encoding (Rt has to be PC), causes interworking branch
			* > POP { registers..., PC } -> causes interworking branch
			* > LDM Rn, { registers..., PC } -> causes interworking branch
			* Source: https://shorturl.at/gloG5
			*/
			void thumb_calculate_branch_dest(uintptr_t current_address)
			{
				flags.set(M_BRANCH);

				if (memchr(instr.detail->groups, ARM_GRP_CALL, instr.detail->groups_count))
				{
					flags.set(M_LINK);
					goto HANDLE_BRANCHES;
				}
				else if (memchr(instr.detail->groups, ARM_GRP_JUMP, instr.detail->groups_count))
				{
				HANDLE_BRANCHES:
					if (memchr(instr.detail->groups, ARM_GRP_BRANCH_RELATIVE, instr.detail->groups_count))
					{
						if (instr.id == ARM_INS_BX || instr.id == ARM_INS_BLX)
							next_instr_set = IS_ARM;
						branch_dest = find_imm(instr);
					}
				}
				else if (cs_arm_op* operand = find_pc_reg(instr))
				{
					switch (instr.id)
					{
					case ARM_INS_ADD:
						// only encoding 2 of thumb add has a register operand broken into two pieces
						// so if the piece count isn't 2 then this isn't encoding 2 so we reset branch flag
						if (operand->encoding.operand_pieces_count != 2)
							flags.reset(M_BRANCH);
						break;
					case ARM_INS_MOV:
						// same case as above, only encoding 1 of thumb mov has pc reg broken in two pieces
						if (operand->encoding.operand_pieces_count != 2)
							flags.reset(M_BRANCH);
						break;

					}
				}
			}
		};
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
		const size_t size_needed = uses_thumb && (reinterpret_cast<uintptr_t>(target) % 4) 
			? sizeof(FULL_JMP_ABS) + 2 : sizeof(FULL_JMP_ABS);
		uint8_t pc_offset = 0;
		std::bitset<16> encountered_reglist{};
		std::bitset<64> tramp_bits{};
		std::array<std::byte, 16> tmpbuffer{};
		uint8_t tmpbuff_pos = 0;
		reinterpret_cast<uintptr_t&>(target) &= ~1;
		disassembler arm{ target, uses_thumb };

		for (const cs_insn& instr : arm.disasm(size_needed))
		{
			size_t copy_size = instr.size;
			
		}
	}
}
