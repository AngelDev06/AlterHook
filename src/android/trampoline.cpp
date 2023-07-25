/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "arm_instructions.h"
#include "addresser.h"
#include "buffer.h"
#include "tools.h"
#include "api.h"

namespace alterhook
{
	ALTERHOOK_HIDDEN std::shared_mutex hook_lock{};

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
			M_BRANCH, // whether the instruction causes a branch i.e. modifies the PC register
			M_LINK, // whether the instruction performs a call i.e. modifies the PC & LR register
			M_TBM, // whether the instruction needs to be modified to function i.e. reads from PC
			M_REGLIST, // whether the instructions has a reglist
			M_FINAL_POP, // whether the current instruction is the final pop that finishes pc handling
			M_PUSH, // whether the current instruction is the push that starts pc handling
			M_LDR, // whether the current instruction is the ldr that loads a given register with the value of PC
			M_POP, // whether the current instruction is the pop that finishes the PC handling setup
			M_ADD, // whether the current instruction is the add instruction that increments the value of the register representing the PC
			M_ADR, // whether the current instruction is an adr instruction
			M_ORIGINAL_PUSH // whether the current instruction is a push with reglist operand that was already part of the target
		};

		#define __alterhook_reg_bitnum(reg) ((reg) == ARM_REG_R13 ? 13 : \
											 (reg) >= ARM_REG_R0  ? (reg) - ARM_REG_R0 : \
																    (reg) + 1)

		static ALTERHOOK_HIDDEN bool is_pad(const std::byte* src, size_t size, bool thumb) noexcept
		{
			if (thumb)
			{
				constexpr uint16_t tnop = 0xBF00;
				constexpr uint32_t t2nop = 0xAFF30080;
				if (size % 2)
					++size;
				if (*reinterpret_cast<const uint16_t*>(src) == tnop || !(*reinterpret_cast<const uint16_t*>(src)))
				{
					size /= 2;
					for (size_t i = 1; i < size; ++i)
					{
						if (reinterpret_cast<const uint16_t*>(src)[i] != *reinterpret_cast<const uint16_t*>(src))
							return false;
					}
					return true;
				}
				if (size % 4)
					size += 2;
				if (*reinterpret_cast<const uint32_t*>(src) == t2nop)
				{
					size /= 4;
					for (size_t i = 1; i < size; ++i)
					{
						if (reinterpret_cast<const uint32_t*>(src)[i] != t2nop)
							return false;
					}
					return true;
				}
				return false;
			}
			constexpr uint32_t nop = 0xE320F000;
			if (size % 4)
				size = utils_align(size + 3, 4);
			if (*reinterpret_cast<const uint32_t*>(src) == nop)
			{
				size /= 4;
				for (size_t i = 1; i < size; ++i)
				{
					if (reinterpret_cast<const uint32_t*>(src)[i] != nop)
						return false;
				}
				return true;
			}
			return false;
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

		static ALTERHOOK_HIDDEN std::bitset<16> build_reglist(const cs_insn& instr) noexcept
		{
			std::bitset<16> reglist{};

			for (size_t i = 0, end = instr.detail->arm.op_count; i != end; ++i)
			{
				cs_arm_op& operand = instr.detail->arm.operands[i];
				if (operand.type == ARM_OP_REG && operand.encoding.operand_pieces_count == 1 && operand.encoding.sizes[0] == 1)
					reglist.set(__alterhook_reg_bitnum(operand.reg));
			}
			return reglist;
		}

		struct ALTERHOOK_HIDDEN to_be_modified
		{
			uintptr_t instr;
			size_t size;
			bool thumb;
			cs_operand_encoding encoding;
			std::bitset<16> flags;
			std::bitset<16> reglist;
			std::variant<PUSH_REGLIST*, THUMB2_PUSH_REGLIST*, THUMB_PUSH_REGLIST*>* orig_push;

			void patch_reg(reg_t reg)
			{
				utils_assert(encoding.operand_pieces_count <= 2, "(unreachable) register encoding with more than 2 pieces");
				utils_assert(encoding.operand_pieces_count, "(unreachable) empty register encoding");
				utils_assert(
					(encoding.operand_pieces_count == 1 && encoding.sizes[0] == 4) ||
					(encoding.operand_pieces_count == 2 && (encoding.sizes[0] + encoding.sizes[1]) == 4),
					"(unreachable) register field has more or less than 4 bits"
				);
				// note that for thumb2 if index is greater than 16 we want its distance from end and add 16 to it so we hardcoded 48
				uint8_t i = thumb ? encoding.indexes[0] >= 16 ? 48 : 16 : 32;
				const std::array bitseq = { 0b1, 0b11, 0b111, 0b1111 };
				unsigned reg_part1 = reg >> (4 - encoding.sizes[0]);

				*reinterpret_cast<uint32_t*>(instr) &= ~(bitseq[encoding.sizes[0] - 1] << (i - (encoding.indexes[0] + encoding.sizes[0])));
				*reinterpret_cast<uint32_t*>(instr) |= reg_part1 << (i - (encoding.indexes[0] + encoding.sizes[0]));

				if (encoding.operand_pieces_count == 2)
				{
					uint8_t j = thumb ? encoding.indexes[1] >= 16 ? 48 : 16 : 32;
					unsigned reg_part2 = reg & bitseq[encoding.sizes[1] - 1];
					
					*reinterpret_cast<uint32_t*>(instr) &= ~(bitseq[encoding.sizes[1] - 1] << (j - (encoding.indexes[1] + encoding.sizes[1])));
					*reinterpret_cast<uint32_t*>(instr) |= reg_part2 << (j - (encoding.indexes[1] + encoding.sizes[1]));
				}
			}

			void modify(reg_t reg)
			{
				/*
				* - When handling the PC register we may encounter an instruction that
				*	has a reglist operand.
				* - Since that reglist operand may include the PC we temporarily handle
				*	it by disabling current PC handling setup (by placing a pop) and
				*	re-enable it later if needed.
				* - However since we now know which register we are using to hold the
				*	value of PC we proceed to check if that reglist contains it.
				* - If it does contain it we handle the instructions we have placed
				*	as expected, but if it doesn't then these instructions have no meaning
				*	so we replace them with nop (since we can't change instruction order).
				* - BUT if this is the final pop (the one which disables PC handling setup
				*	for good) then we can't replace it with nop as that would break the setup
				*	entirely.
				* - So in that case we handle it as expected.
				*/
				if (flags[M_REGLIST] && !reglist[reg] && !flags[M_FINAL_POP])
				{
					// on thumb we replace both push & ldr with single 4 byte nop
					if (thumb)
					{
						if (!flags[M_LDR])
						{
							if (flags[M_PUSH])
								new (reinterpret_cast<void*>(instr)) THUMB2_NOP;
							else
								new (reinterpret_cast<void*>(instr)) THUMB_NOP;
						}
					}
					else
						new (reinterpret_cast<void*>(instr)) NOP;
				}
				else if (flags[M_PUSH])
				{
					// if we have encountered a push with reglist operand included in the target
					// then we check if we can make use of it. that can happen if the register
					// we have chosen is going to be pushed last on stack and for that we check if
					// it's the register with the largest corresponding number included in the list.
					// if that isn't the case then we proceed to use our own push as expected
					if (flags[M_ORIGINAL_PUSH])
					{
						if (auto push = std::get_if<PUSH_REGLIST*>(orig_push))
						{
							if ((*push)->greatest(reg))
								(*push)->append(reg);
							else
								goto UPDATE_PUSH;
						}
						else if (auto t2push = std::get_if<THUMB2_PUSH_REGLIST*>(orig_push))
						{
							if ((*t2push)->greatest(reg))
								(*t2push)->append(reg);
							else
								goto UPDATE_PUSH;
						}
						else
						{
							auto tpush = std::get<THUMB_PUSH_REGLIST*>(*orig_push);
							if (tpush->greatest(reg))
								tpush->append(reg);
							else
								goto UPDATE_PUSH;
						}

						if (thumb)
							new (reinterpret_cast<void*>(instr)) THUMB_NOP;
						else
							new (reinterpret_cast<void*>(instr)) NOP;
					}
					else
					{
					UPDATE_PUSH:
						if (thumb)
							reinterpret_cast<THUMB_PUSH*>(instr)->set_register(reg);
						else
							reinterpret_cast<PUSH*>(instr)->set_register(reg);
					}
				}
				else if (thumb)
				{
					if (flags[M_POP])
						reinterpret_cast<THUMB_POP*>(instr)->set_register(reg);
					else if (flags[M_LDR])
						reinterpret_cast<THUMB_LDR_LITERAL*>(instr)->set_register(reg);
					else if (flags[M_ADD])
						reinterpret_cast<THUMB_ADD*>(instr)->set_register(reg);
					// note that adr is replaced by a full thumb2 add since adr doesn't have the PC
					// encoded anywhere
					else if (flags[M_ADR])
						reinterpret_cast<THUMB2_ADD*>(instr)->set_operand_register(reg);
					else
						patch_reg(reg);
				}
				else
				{
					if (flags[M_POP])
						reinterpret_cast<POP*>(instr)->set_register(reg);
					else if (flags[M_LDR])
						reinterpret_cast<LDR_LITERAL*>(instr)->set_register(reg);
					else if (flags[M_ADD])
					{
						reinterpret_cast<ADD*>(instr)->set_operand_register(reg);
						reinterpret_cast<ADD*>(instr)->set_destination_register(reg);
					}
					else
						patch_reg(reg);
				}
			}
		};

		struct ALTERHOOK_HIDDEN trampoline_instruction_entry
		{
			disassembler& arm;
			const cs_insn& instr;
			instruction_set next_instr_set;
			uint64_t branch_dest = 0;
			std::bitset<16> flags{};
			std::bitset<16>& encountered_reglist;
			cs_operand_encoding encoding{};

			void check_branch_instructions()
			{
				if (arm.has_group(instr, ARM_GRP_CALL) || arm.has_group(instr, ARM_GRP_JUMP))
				{
					flags.set(M_BRANCH);
					if (arm.has_group(instr, ARM_GRP_CALL))
						flags.set(M_LINK);
					if (arm.has_group(instr, ARM_GRP_BRANCH_RELATIVE))
					{
						if (instr.id == ARM_INS_BX || instr.id == ARM_INS_BLX)
							next_instr_set = static_cast<instruction_set>(!next_instr_set);
						branch_dest = find_imm(instr);
					}
				}
			}

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
			* source: https://shorturl.at/gloG5
			*/
			void thumb_calculate_branch_dest()
			{
				if (arm.modifies_reg(instr, ARM_REG_PC))
				{
					flags.set(M_BRANCH);
					if (arm.modifies_reg(instr, ARM_REG_LR))
						flags.set(M_LINK);
				}
				else
					check_branch_instructions();
			}

			/*
			* According to the armv7 documentation the only arm instructions that are allowed to modify the PC (causing a branch)
			* are all of the ones mentioned for thumb except for ADD, MOV (thumb specific) and also the following:
			* > ADC -> any encoding
			* > ADD -> any encoding
			* > ADR -> any encoding
			* > AND -> any encoding
			* > ASR -> immediate only
			* > BIC -> any encoding
			* > EOR -> any encoding
			* > LSL -> immediate only
			* > MOV and MVN -> any encoding
			* > ORR -> any encoding
			* > ROR -> immediate only
			* > RRX -> any encoding
			* > RSB -> any encoding
			* > RSC -> any encoding
			* > SBC -> any encoding
			* > SUB -> any encoding
			* Note: all the instructions mentioned above need to have the PC as the Rd (destination operand) and in that case the type of branch caused
			* is interworking (so if the least significant bit is set it switches or remains in thumb state etc.)
			* source: https://shorturl.at/gloG5
			*/
			void arm_calculate_branch_dest()
			{
				if (arm.modifies_reg(instr, ARM_REG_PC))
				{
					flags.set(M_BRANCH);
					if (!arm.reads_reg(instr, ARM_REG_PC))
						return;
					typedef std::bitset<64> opcode_t;
					opcode_t opcode = instr.detail->opcode_encoding.bits;

					// check if it belongs to Data-Processing immediate category
					// since it modifies the PC it can't belong to the other 3
					// with same bit pattern
					// source: https://shorturl.at/gluM6
					if ((opcode & opcode_t(0b111)) == 0b100)
					{
						uint64_t imm = find_imm(instr);
						// when loading the PC on arm instruction set it always points 8 bytes
						// after the current instruction. Also no alignment is needed since
						// the PC is always aligned to 4 bytes
						uint64_t addr = instr.address + 8;

						switch (instr.id)
						{
						case ARM_INS_MOV:
							branch_dest = imm;
							break;
						case ARM_INS_ADC: [[fallthrough]];
						case ARM_INS_ADD:
							branch_dest = addr + imm;
							break;
						case ARM_INS_AND:
							branch_dest = addr & imm;
							break;
						case ARM_INS_BIC:
							branch_dest = addr & ~imm;
							break;
						case ARM_INS_EOR:
							branch_dest = addr ^ imm;
							break;
						case ARM_INS_MVN:
							branch_dest = ~imm;
							break;
						case ARM_INS_ORR:
							branch_dest = addr | imm;
							break;
						case ARM_INS_RSB: [[fallthrough]];
						case ARM_INS_RSC:
							branch_dest = imm - addr;
							break;
						case ARM_INS_SBC: [[fallthrough]];
						case ARM_INS_SUB:
							branch_dest = addr - imm;
							break;
						default:
							utils_assert(false, "(unreachable) arm_calculate_branch_dest: unhandled data processing instruction");
						}
					}
					// a few exceptions that should have been part of the above category but instead belong
					// to its register version (even though they clearly have an immediate operand)
					else if ((opcode & opcode_t(0b1111111)) == 0b1011000 && instr.id != ARM_INS_MOV)
					{
						uint64_t imm = find_imm(instr);
						uint64_t addr = instr.address + 8;

						switch (instr.id)
						{
						case ARM_INS_LSL:
							branch_dest = addr << imm;
							break;
							// the address is always positive so it doesn't matter whether an arithmetic or logical shift occurs
						case ARM_INS_ASR:
						case ARM_INS_LSR:
							branch_dest = addr >> imm;
							break;
						case ARM_INS_ROR:
							branch_dest = utils_ror(addr, imm);
							break;
						case ARM_INS_RRX:
							branch_dest = utils_ror(addr, 1);
							break;
						default:
							utils_assert(false, "(unreachable) arm_calculate_branch_dest: unhandled data processing instruction");
						}
					}
					else if (arm.modifies_reg(instr, ARM_REG_LR))
						flags.set(M_LINK);
				}
				else
					check_branch_instructions();
			}

			void add_mem_pc_encoding(cs_arm_op& operand)
			{
				switch (operand.mem.format)
				{
				case ARM_MEM_U_REG_REG: [[fallthrough]];
				case ARM_MEM_IMM_REG: [[fallthrough]];
				case ARM_MEM_U_REG_IMM: [[fallthrough]];
				case ARM_MEM_U_REG_IMM2: [[fallthrough]];
				case ARM_MEM_U_REG_SHIFT_REG: [[fallthrough]];
				case ARM_MEM_IREG_BREG:
					encoding.indexes[encoding.operand_pieces_count] = operand.encoding.indexes[1];
					encoding.sizes[encoding.operand_pieces_count++] = operand.encoding.sizes[1];
					break;
				case ARM_MEM_REG_ALIGN_REG: [[fallthrough]];
				case ARM_MEM_REG_IMM: [[fallthrough]];
				case ARM_MEM_REG_U_IMM: [[fallthrough]];
				case ARM_MEM_REG_SHIFT_REG: [[fallthrough]];
				case ARM_MEM_REG_REG: [[fallthrough]];
				case ARM_MEM_REG:
					encoding.indexes[encoding.operand_pieces_count] = operand.encoding.indexes[0];
					encoding.sizes[encoding.operand_pieces_count++] = operand.encoding.sizes[0];
					break;
				}
			}

			void handle_pc_rel_instructions()
			{
				for (size_t begin = 0, end = instr.detail->arm.op_count; begin != end; ++begin)
				{
					cs_arm_op& operand = instr.detail->arm.operands[begin];
					if (operand.type == ARM_OP_REG)
					{
						unsigned reg_bitnum = __alterhook_reg_bitnum(operand.reg);

						if (operand.reg == ARM_REG_PC && operand.access == CS_AC_READ && !flags[M_BRANCH])
						{
							// no support for reglist instructions that include the PC in the reglist and read from it
							// that is, push and stm
							if (operand.encoding.operand_pieces_count == 1 && operand.encoding.sizes[0] == 1)
								throw(exceptions::unsupported_instruction_handling(
									reinterpret_cast<const std::byte*>(instr.bytes), 
									next_instr_set, 
									reinterpret_cast<std::byte*>(instr.address)
								));
							encoding = operand.encoding;
							flags.set(M_TBM);
						}
						else
						{
							if (operand.encoding.operand_pieces_count == 1 && operand.encoding.sizes[0] == 1)
								flags.set(M_REGLIST);
							if (!encountered_reglist[reg_bitnum])
								encountered_reglist.set(reg_bitnum);
						}
					}
					else if (operand.type == ARM_OP_MEM)
					{
						utils_assert(operand.mem.index != ARM_REG_PC, "(unreachable) PC is index operand");
						if (operand.mem.base == ARM_REG_PC)
							add_mem_pc_encoding(operand);
					}
				}
			}

			trampoline_instruction_entry(
				disassembler& arm,
				const cs_insn& instr,
				std::bitset<16>& encountered_reglist,
				bool thumb
			) : arm(arm), instr(instr), encountered_reglist(encountered_reglist), next_instr_set(static_cast<instruction_set>(thumb))
			{
				if (thumb)
					thumb_calculate_branch_dest();
				else
					arm_calculate_branch_dest();
				handle_pc_rel_instructions();
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
		bool push_found = false;
		const uintptr_t tramp_begin = reinterpret_cast<uintptr_t>(ptrampoline.get());
		const uintptr_t tramp_end = tramp_begin + memory_slot_size;
		uintptr_t pc_val = 0;
		uintptr_t pc_loc = 0;
		const size_t size_needed = uses_thumb && (reinterpret_cast<uintptr_t>(target) % 4) 
			? sizeof(FULL_JMP_ABS) + 2 : sizeof(FULL_JMP_ABS);
		uint8_t pc_offset = 0;
		std::bitset<16> encountered_reglist{};
		std::bitset<memory_slot_size> used_locations{};
		size_t last_unused_pos = 0;
		uint8_t available_size = memory_slot_size;
		std::variant<PUSH_REGLIST*, THUMB2_PUSH_REGLIST*, THUMB_PUSH_REGLIST*> orig_push{};
		std::array<std::byte, 16> tmpbuff{};
		uint8_t tmpbuffpos = 0;
		uint64_t addr = 0;
		reinterpret_cast<uintptr_t&>(target) &= ~1;
		uint8_t tramp_pos = 0;
		uint8_t it_remaining = 0;
		uint64_t it_original_address = 0;
		THUMB_IT* it_block = nullptr;
		to_be_modified tbm{};
		utils::static_vector<to_be_modified, 16> tbm_list{};
		decltype(tbm_list)::iterator final_pop{ tbm_list.begin() };
		utils::static_vector<std::pair<uintptr_t, bool>, 3> branch_addresses{};
		disassembler arm{ target, uses_thumb };
		std::shared_lock lock{ hook_lock };

		for (const cs_insn& instr : arm.disasm(memory_slot_size))
		{
			arm.set_reg_accesses(instr);
			size_t copy_size = instr.size;
			const std::byte* copy_source = reinterpret_cast<const std::byte*>(instr.bytes);
			const uintptr_t tramp_addr = reinterpret_cast<uintptr_t>(ptrampoline.get()) + tramp_pos;
			tbm.instr = tramp_addr;
			tbm.thumb = uses_thumb;
			tbm.size = instr.size;
			addr = instr.address;
			tmpbuffpos = 0;
			trampoline_instruction_entry entry{ arm, instr, encountered_reglist, uses_thumb };

			// a utility that generates a brand new IT block that can hold the remaining instructions
			// and also removes them from the previous one. this is useful when we place a few unconditional
			// instructions in the middle such as those who are part of the PC handling setup.
			const auto update_it_block = [&]
			{
				const uint8_t old_it_inst_count = it_block->instruction_count();
				const uint8_t old_it_cond_pos = old_it_inst_count - it_remaining + 1;

				if (it_block->get_condition(old_it_cond_pos) == THUMB_IT::E)
				{
					THUMB_IT it{ ARMCC_getOppositeCondition(it_block->get_condition()) };

					for (uint8_t i = old_it_cond_pos + 1, j = 2; i <= old_it_inst_count; ++i, ++j)
						it.set_condition(j, static_cast<THUMB_IT::it_cond>(!it_block->get_condition(i)));

					new (&tmpbuff[tmpbuffpos]) auto(it);
				}
				else
				{
					THUMB_IT it{ it_block->get_condition() };

					for (uint8_t i = old_it_cond_pos + 1, j = 2; i <= old_it_inst_count; ++i, ++j)
						it.set_condition(j, it_block->get_condition(i));

					new (&tmpbuff[tmpbuffpos]) auto(it);
				}
				it_block->pop(it_remaining);
				it_block = reinterpret_cast<THUMB_IT*>(tramp_addr + tmpbuffpos);
				tmpbuffpos += sizeof(THUMB_IT); copy_size += sizeof(THUMB_IT);
				tbm.instr += sizeof(THUMB_IT);
			};
			// writes an instruction to the temporary buffer and updates tbm status
			const auto write_and_advance = [&](auto instr, tbm_flags flag)
			{
				tbm.flags.set(flag);
				new (&tmpbuff[tmpbuffpos]) auto(instr);
				tmpbuffpos += sizeof(instr); copy_size += sizeof(instr);
				tbm.size = sizeof(instr);
				tbm_list.push_back(tbm);
				tbm.instr += sizeof(instr);
				tbm.flags.reset(flag);
			};
			// allocates 4 bytes starting from the end of the trampoline to be used
			// for storing constant data
			const auto find_loc = [&]
			{
				const uintptr_t available_space = tramp_begin + available_size;
				uintptr_t dataloc = 0;
				used_locations |= 0b1111 << last_unused_pos;
				dataloc = tramp_end - (last_unused_pos += 4);
				available_size -= available_space - dataloc;
				return dataloc;
			};

			auto iter = std::find_if(
				branch_addresses.begin(), branch_addresses.end(),
				[&](std::pair<uintptr_t, bool>& element) { return element.first == instr.address; }
			);
			if (iter != branch_addresses.end())
			{
				// can't branch inside an IT block
				if (it_remaining)
				{
					memcpy(reinterpret_cast<void*>(tramp_addr), instr.bytes, instr.size);
					throw(exceptions::invalid_it_block(
						reinterpret_cast<std::byte*>(it_block),
						it_original_address,
						(tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
						it_remaining,
						target
					));
				}
				if (uses_thumb != iter->second)
					arm.switch_instruction_set();
				uses_thumb = iter->second;
				branch_addresses.erase(iter);
			}

			// handles the situation where an instruction that has a reglist operand is spotted
			// and PC handling setup is currently active. we got to disable PC handling setup
			// for safety reasons. if that's unecessary then all the instructions placed will
			// be replaced with nop when modifying
			if (entry.flags[M_REGLIST] && !should_setup_pc_handling)
			{
				tbm.flags.set(M_REGLIST);
				tbm.reglist = build_reglist(instr);
				final_pop = tbm_list.end();

				if (uses_thumb)
				{
					if (it_remaining)
					{
						if (entry.flags[M_BRANCH] && it_remaining > 1)
						{
							memcpy(reinterpret_cast<void*>(tramp_addr), copy_source, copy_size);
							throw(exceptions::invalid_it_block(
								reinterpret_cast<std::byte*>(it_block),
								it_original_address,
								(tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
								it_remaining,
								target
							));
						}

						if (it_remaining == it_block->instruction_count())
						{
							new (tmpbuff.data()) auto(*it_block);
							tmpbuffpos += sizeof(*it_block); copy_size += sizeof(*it_block);

							tbm.flags.set(M_POP);
							new (it_block) THUMB_POP(r7);
							tbm.instr = reinterpret_cast<uintptr_t>(it_block);
							tbm.size = sizeof(THUMB_POP);
							tbm_list.push_back(tbm);
							tbm.instr = tramp_addr + sizeof(*it_block);
							tbm.flags.reset(M_POP);

							it_block = reinterpret_cast<THUMB_IT*>(tramp_addr);
						}
						else
						{
							write_and_advance(THUMB_POP(r7), M_POP);
							update_it_block();
						}
					}
					else
						write_and_advance(THUMB_POP(r7), M_POP);
				}
				else
					write_and_advance(POP(r7), M_POP);

				memcpy(&tmpbuff[tmpbuffpos], instr.bytes, instr.size);
				
				tbm.flags.reset(); tbm.flags.set(M_REGLIST);
				copy_source = tmpbuff.data();
				should_setup_pc_handling = true;

				if (entry.flags[M_BRANCH])
					finished = true;
			}
			// handles all kinds of branch instructions. (including calls and those who just modify the PC)
			else if (entry.flags[M_BRANCH])
			{
				if (it_remaining > 1)
				{
					memcpy(reinterpret_cast<void*>(tramp_addr), copy_source, copy_size);
					throw(exceptions::invalid_it_block(
						reinterpret_cast<std::byte*>(it_block),
						it_original_address,
						(tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
						it_remaining,
						target
					));
				}

				if (entry.flags[M_LINK])
				{
					if (entry.branch_dest)
					{
						if (
							reinterpret_cast<uintptr_t>(target) <= entry.branch_dest &&
							entry.branch_dest < (reinterpret_cast<uintptr_t>(target) + size_needed)
						)
						{
							if (entry.branch_dest > instr.address)
								branch_addresses.emplace_back(entry.branch_dest, entry.next_instr_set);
						}
						else
						{
							const uintptr_t dataloc = find_loc();
							*reinterpret_cast<uint32_t*>(dataloc) = entry.branch_dest | entry.next_instr_set;

							if (uses_thumb)
							{
								copy_size = sizeof(THUMB2_CALL_ABS);

								if (it_remaining)
								{
									switch (it_block->instruction_count())
									{
									case 1:
										it_block->set_second_condition(THUMB_IT::T);
										goto PLACE_CALL;
									case 2:
										it_block->set_third_condition(it_block->get_second_condition());
										goto PLACE_CALL;
									case 3:
										it_block->set_fourth_condition(it_block->get_third_condition());
										goto PLACE_CALL;
									case 4:
										const ARMCC_CondCodes condition = it_block->get_fourth_condition() == THUMB_IT::T ?
											it_block->get_condition() : ARMCC_getOppositeCondition(it_block->get_condition());
										new (tmpbuff.data()) THUMB_IT(condition, THUMB_IT::T);
										tmpbuffpos += sizeof(THUMB_IT); copy_size += sizeof(THUMB_IT);
										copy_source = tmpbuff.data();
										tbm.instr += sizeof(THUMB_IT);
										THUMB2_CALL_ABS tcall{};
										tcall.set_offset(dataloc - utils_align(tbm.instr + 4, 4));
										if (tbm.instr % 4)
											tcall.align();
										new (&tmpbuff[tmpbuffpos]) auto(tcall);
										it_block->pop_instruction();
										break;
									}
								}
								else
								{
								PLACE_CALL:
									THUMB2_CALL_ABS tcall{};
									tcall.set_offset(dataloc - utils_align(tramp_addr + 4, 4));
									if (tramp_addr % 4)
										tcall.align();
									new (tmpbuff.data()) auto(tcall);
									copy_source = tmpbuff.data();
								}
							}
							else
							{
								CALL_ABS call{};
								if (instr.detail->arm.cc != ARMCC_AL && instr.detail->arm.cc != ARMCC_UNDEF)
									call.set_condition(instr.detail->arm.cc);
								call.set_offset(dataloc - (tramp_addr + 8));
								new (tmpbuff.data()) auto(call);
								copy_source = tmpbuff.data();
								copy_size = sizeof(call);
							}
						}
					}
				}
				else
				{
					if (entry.branch_dest)
					{
						if (
							reinterpret_cast<uintptr_t>(target) <= entry.branch_dest &&
							entry.branch_dest < (reinterpret_cast<uintptr_t>(target) + size_needed)
						)
						{
							if (entry.branch_dest > instr.address)
								branch_addresses.emplace_back(entry.branch_dest, entry.next_instr_set);
						}
						else
						{
							finished = (instr.detail->arm.cc == ARMCC_AL || instr.detail->arm.cc == ARMCC_UNDEF) &&
								std::find_if(
									branch_addresses.begin(), branch_addresses.end(),
									[&](std::pair<uintptr_t, bool>& element) { return instr.address < element.first; }
								) == branch_addresses.end();

							const uintptr_t dataloc = find_loc();
							*reinterpret_cast<uint32_t*>(dataloc) = entry.branch_dest | entry.next_instr_set;
							copy_size = sizeof(JMP_ABS);
							copy_source = tmpbuff.data();

							if (uses_thumb)
							{
								if (finished && !should_setup_pc_handling) 
								{
									final_pop = tbm_list.end();
									write_and_advance(THUMB_POP(r7), M_POP);
								}
								if (instr.detail->arm.cc != ARMCC_AL && instr.detail->arm.cc != ARMCC_UNDEF)
								{
									new (&tmpbuff[tmpbuffpos]) THUMB_IT(instr.detail->arm.cc);
									tmpbuffpos += sizeof(THUMB_IT); copy_size += sizeof(THUMB_IT);
									tbm.instr += sizeof(THUMB_IT);
								}
								THUMB2_JMP_ABS tjmp{};
								tjmp.set_offset(dataloc - utils_align(tbm.instr + 4, 4));
								new (&tmpbuff[tmpbuffpos]) auto(tjmp);
							}
							else
							{
								JMP_ABS jmp{};
								if (instr.detail->arm.cc != ARMCC_AL && instr.detail->arm.cc != ARMCC_UNDEF)
									jmp.set_condition(instr.detail->arm.cc);
								if (finished && !should_setup_pc_handling)
									write_and_advance(POP(r7), M_POP);
								jmp.set_offset(dataloc - (tbm.instr + 8));
								new (&tmpbuff[tmpbuffpos]) auto(jmp);
							}
						}
					}
					else
					{
						if (entry.flags[M_TBM])
							throw(exceptions::pc_relative_handling_fail(reinterpret_cast<std::byte*>(instr.address), target));
						if (!should_setup_pc_handling)
						{
							final_pop = tbm_list.end();
							if (uses_thumb)
								write_and_advance(THUMB_POP(r7), M_POP);
							else
								write_and_advance(POP(r7), M_POP);
						}

						finished = (instr.detail->arm.cc == ARMCC_AL || instr.detail->arm.cc == ARMCC_UNDEF) &&
							std::find_if(
								branch_addresses.begin(), branch_addresses.end(),
								[&](std::pair<uintptr_t, bool>& element) { return instr.address < element.first; }
							) == branch_addresses.end();
					}
				}
			}
			// collects some info about an IT block when an IT instruction is encountered
			else if (instr.id == ARM_INS_IT)
			{
				if (it_remaining)
				{
					memcpy(reinterpret_cast<void*>(tramp_addr), instr.bytes, instr.size);
					throw(exceptions::invalid_it_block(
						reinterpret_cast<std::byte*>(it_block),
						it_original_address,
						(tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
						it_remaining,
						target
					));
				}
				it_original_address = instr.address;
				it_block = reinterpret_cast<THUMB_IT*>(tramp_addr);
				it_remaining = reinterpret_cast<THUMB_IT*>(instr.address)->instruction_count() + 1;
			}
			// if a push with reglist operand is encountered we cache for later use if needed
			else if (instr.id == ARM_INS_PUSH && entry.flags[M_REGLIST] && !it_remaining)
			{
				if (uses_thumb)
				{
					if (instr.size == 4)
						orig_push = reinterpret_cast<THUMB2_PUSH_REGLIST*>(tramp_addr);
					else
						orig_push = reinterpret_cast<THUMB_PUSH_REGLIST*>(tramp_addr);
				}
				else
					orig_push = reinterpret_cast<PUSH_REGLIST*>(tramp_addr);
				push_found = true;
			}
			else if (entry.flags[M_TBM])
			{
				copy_source = tmpbuff.data();

				if (should_setup_pc_handling)
				{
					if (push_found)
					{
						tbm.orig_push = &orig_push;
						tbm.flags.set(M_ORIGINAL_PUSH);
						push_found = false;
					}

					if (uses_thumb)
					{
						const auto prepare_pc_emulation = [&]
						{
							if (!pc_loc)
								pc_loc = find_loc();
							write_and_advance(THUMB_LDR_LITERAL(r7, (pc_loc - utils_align(tbm.instr + 4, 4)) / 4), M_LDR);
							const uintptr_t new_pc_val = instr.id == ARM_INS_ADR ? utils_align(instr.address + 4, 4) : instr.address + 4;
							uint32_t& old_pc_val = *reinterpret_cast<uint32_t*>(pc_loc);

							if (!pc_val)
								old_pc_val = pc_val = new_pc_val;
							else
							{
								const uint8_t offset = new_pc_val - old_pc_val;
								pc_val = old_pc_val + offset;
								write_and_advance(THUMB_ADD(r7, offset), M_ADD);
							}
						};

						if (it_remaining)
						{
							if (it_remaining == it_block->instruction_count())
							{
								prepare_pc_emulation();
								new (&tmpbuff[tmpbuffpos]) auto(*it_block);
								tmpbuffpos += sizeof(*it_block); copy_size += sizeof(*it_block);
								tbm.instr += sizeof(*it_block);
								const uintptr_t current_instr = tbm.instr;
								tbm.flags.set(M_PUSH);
								new (it_block) THUMB_PUSH(r7);
								tbm.instr = reinterpret_cast<uintptr_t>(it_block);
								tbm.size = sizeof(THUMB_PUSH);
								tbm_list.push_back(tbm);
								tbm.instr = current_instr;
								tbm.flags.reset(M_PUSH);
								it_block = reinterpret_cast<THUMB_IT*>(tbm.instr - sizeof(*it_block));
							}
							else
							{
								write_and_advance(THUMB_PUSH(r7), M_PUSH);
								prepare_pc_emulation();
								update_it_block();
							}
						}
						else
						{
							write_and_advance(THUMB_PUSH(r7), M_PUSH);
							prepare_pc_emulation();
						}
					}
					else
					{
						if (!pc_loc)
							pc_loc = find_loc();
						write_and_advance(PUSH(r7), M_PUSH);
						write_and_advance(LDR_LITERAL(r7, pc_loc - (tbm.instr + 8)), M_LDR);
						uint32_t& old_pc_val = *reinterpret_cast<uint32_t*>(pc_loc);

						if (!pc_val)
							old_pc_val = pc_val = instr.address + 8;
						else
						{
							const uint16_t offset = (instr.address + 8) - old_pc_val;
							pc_val = old_pc_val + offset;
							write_and_advance(ADD(r7, r7, offset), M_ADD);
						}
					}

					tbm.flags.reset(M_REGLIST);
					tbm.flags.reset(M_ORIGINAL_PUSH);
					should_setup_pc_handling = false;
				}
				else
				{
					if (uses_thumb)
					{
						const auto update_custom_pc = [&]
						{
							uintptr_t offset = instr.id == ARM_INS_ADR ? utils_align(instr.address + 4, 4) : instr.address + 4;
							offset -= pc_val;

							if (offset)
							{
								pc_val += offset;
								write_and_advance(THUMB_ADD(r7, offset), M_ADD);
								return true;
							}
							return false;
						};

						if (it_remaining)
						{
							if (it_remaining == it_block->instruction_count())
							{
								uintptr_t offset = instr.id == ARM_INS_ADR ? utils_align(instr.address + 4, 4) : instr.address + 4;
								offset -= pc_val;

								if (offset)
								{
									new (tmpbuff.data()) auto(*it_block);
									tmpbuffpos += sizeof(*it_block); copy_size += sizeof(*it_block);
									pc_val += offset;
									tbm.flags.set(M_ADD);
									new (it_block) THUMB_ADD(r7, offset);
									tbm.instr = reinterpret_cast<uintptr_t>(it_block);
									tbm.size = sizeof(THUMB_ADD);
									tbm_list.push_back(tbm);
									tbm.instr = tramp_addr + sizeof(*it_block);
									tbm.flags.reset(M_ADD);
									it_block = reinterpret_cast<THUMB_IT*>(tramp_addr);
								}
							}
							else if (update_custom_pc())
								update_it_block();
						}
						else
							update_custom_pc();
					}
					else
					{
						const uint16_t offset = (instr.address + 8) - pc_val;
						pc_val += offset;
						write_and_advance(ADD(r7, r7, offset), M_ADD);
					}
				}

				// thumb adr is an exception
				if (instr.id == ARM_INS_ADR && instr.size == sizeof(uint16_t))
				{
					copy_size -= 2;
					reg_t reg = static_cast<reg_t>(__alterhook_reg_bitnum(instr.detail->regs_write[0]));
					uint64_t imm = instr.detail->arm.operands[1].imm;
					write_and_advance(THUMB2_ADD(reg, r7, imm), M_ADR);
				}
				else
				{
					tbm.flags.set(M_TBM);
					tbm.size = instr.size;
					tbm.encoding = entry.encoding;
					memcpy(&tmpbuff[tmpbuffpos], instr.bytes, instr.size);
					tbm_list.push_back(tbm);
				}
				tbm.flags.reset();
			}

			if (
				std::find_if(
					branch_addresses.begin(), branch_addresses.end(),
					[&](const std::pair<uintptr_t, bool>& element) { return element.first > instr.address; }
				) != branch_addresses.end() && copy_size != instr.size
			)
				throw(exceptions::instructions_in_branch_handling_fail(target));

			if ((tramp_pos + copy_size) > available_size)
				throw(exceptions::trampoline_max_size_exceeded(target, tramp_pos + copy_size, available_size));

			if (it_remaining)
				--it_remaining;

			instruction_sets.set(positions.size(), uses_thumb);
			positions.push_back({ instr.address - reinterpret_cast<uintptr_t>(target), tramp_pos });
			memcpy(reinterpret_cast<void*>(tramp_addr), copy_source, copy_size);
			tramp_pos += copy_size;

			if (finished)
				break;
			if (((instr.address - reinterpret_cast<uintptr_t>(target)) + instr.size) >= size_needed)
			{
				if (it_remaining)
					throw(exceptions::incomplete_it_block(
						reinterpret_cast<std::byte*>(it_block),
						it_original_address,
						(tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
						it_remaining,
						target
					));
				tbm.instr = tramp_addr + copy_size;
				void* copy_dest = reinterpret_cast<void*>(tramp_begin + tramp_pos);
				copy_size = 0;
				copy_source = tmpbuff.data();

				if (!should_setup_pc_handling)
				{
					final_pop = tbm_list.end();
					if (uses_thumb)
					{
						write_and_advance(THUMB_POP(r7), M_POP);

						if (tbm.instr % 4)
						{
							const uintptr_t dataloc = find_loc();
							*reinterpret_cast<uint32_t*>(dataloc) = (instr.address + instr.size) | 1;
							THUMB2_JMP_ABS tjmp{};
							tjmp.set_offset(dataloc - utils_align(tbm.instr + 4, 4));
							new (&tmpbuff[tmpbuffpos]) auto(tjmp);
							copy_size += sizeof(tjmp);
						}
						else
						{
							new (&tmpbuff[tmpbuffpos]) THUMB2_FULL_JMP_ABS((instr.address + instr.size) | 1);
							copy_size += sizeof(THUMB2_FULL_JMP_ABS);
						}
					}
					else
					{
						write_and_advance(POP(r7), M_POP);
						new (&tmpbuff[tmpbuffpos]) FULL_JMP_ABS(instr.address + instr.size);
						copy_size += sizeof(FULL_JMP_ABS);
					}
				}
				else if (uses_thumb)
				{
					if (tbm.instr % 4)
					{
						const uintptr_t dataloc = find_loc();
						*reinterpret_cast<uint32_t*>(dataloc) = (instr.address + instr.size) | 1;
						THUMB2_JMP_ABS tjmp{};
						tjmp.set_offset(dataloc - utils_align(tbm.instr + 4, 4));
						new (&tmpbuff[tmpbuffpos]) auto(tjmp);
						copy_size += sizeof(tjmp);
					}
					else
					{
						new (&tmpbuff[tmpbuffpos]) THUMB2_FULL_JMP_ABS((instr.address + instr.size) | 1);
						copy_size += sizeof(THUMB2_FULL_JMP_ABS);
					}
				}
				else
				{
					new (&tmpbuff[tmpbuffpos]) FULL_JMP_ABS(instr.address + instr.size);
					copy_size += sizeof(FULL_JMP_ABS);
				}

				if ((tramp_pos + copy_size) > available_size)
					throw(exceptions::trampoline_max_size_exceeded(target, tramp_pos + copy_size, available_size));

				memcpy(copy_dest, copy_source, copy_size);
				positions.push_back({ (instr.address - reinterpret_cast<uintptr_t>(target)) + instr.size, tramp_pos });
				tramp_pos += copy_size;
				break;
			}
		}

		tramp_size = tramp_pos;

		if (tbm_list)
		{
			std::array regs = { r0, r1, r2, r3, r4, r5, r6, r7 };
			const auto search_result = std::find_if_not(
				regs.begin(), regs.end(),
				[=](reg_t reg) { return encountered_reglist[reg]; }
			);
			if (search_result == regs.end())
				throw(exceptions::unused_register_not_found(target));
			if (final_pop != tbm_list.begin())
				final_pop->flags.set(M_FINAL_POP);
			for (to_be_modified& tbm : tbm_list)
				tbm.modify(*search_result);
		}

		const size_t origpos = addr - reinterpret_cast<uintptr_t>(target);
		if (origpos < size_needed && !is_pad(target + origpos, size_needed - origpos, uses_thumb))
		{
			if (
				(origpos < sizeof(LDR_LITERAL) && !is_pad(target + origpos, sizeof(LDR_LITERAL) - origpos, uses_thumb)) ||
				!is_pad(target - sizeof(uint32_t), sizeof(uint32_t), uses_thumb)
			)
				throw(exceptions::insufficient_function_size(target, origpos, size_needed));

			patch_above = true;
		}
	}

	trampoline::trampoline(const trampoline& other)
		: ptarget(other.ptarget), ptrampoline(trampoline_buffer::allocate()), instruction_sets(other.instruction_sets),
		patch_above(other.patch_above), tramp_size(other.tramp_size), positions(other.positions)
	{
		memcpy(ptrampoline.get(), other.ptrampoline.get(), memory_slot_size);
	}

	trampoline::trampoline(trampoline&& other) noexcept
		: ptarget(std::exchange(other.ptarget, nullptr)), ptrampoline(std::move(other.ptrampoline)), instruction_sets(other.instruction_sets),
		patch_above(other.patch_above), tramp_size(other.tramp_size), positions(other.positions) {}

	trampoline& trampoline::operator=(const trampoline& other)
	{
		if (this != &other)
		{
			ptarget = other.ptarget;
			instruction_sets = other.instruction_sets;
			patch_above = other.patch_above;
			tramp_size = other.tramp_size;
			positions = other.positions;
			if (!ptrampoline)
				ptrampoline = trampoline_ptr(trampoline_buffer::allocate());
			memcpy(ptrampoline.get(), other.ptrampoline.get(), memory_slot_size);
		}
		return *this;
	}

	trampoline& trampoline::operator=(trampoline&& other) noexcept
	{
		if (this != &other)
		{
			ptarget = std::exchange(other.ptarget, nullptr);
			ptrampoline = std::move(other.ptrampoline);
			instruction_sets = other.instruction_sets;
			patch_above = other.patch_above;
			tramp_size = other.tramp_size;
			positions = other.positions;
		}
		return *this;
	}

	std::string trampoline::str() const
	{
		utils_assert(ptarget, "Attempt to disassemble an uninitialized trampoline");
		std::stringstream stream;
		bool uses_thumb = instruction_sets[0];
		size_t i = 0;
		disassembler arm{ ptrampoline.get(), instruction_sets[0], false };

		for (const cs_insn& instr : arm.disasm(tramp_size))
		{
			if (instr.address != reinterpret_cast<uintptr_t>(ptrampoline.get()))
				stream << '\n';
			stream << "0x" << std::hex << std::setfill('0') << std::setw(8) << instr.address
				<< ": " << instr.mnemonic << '\t' << instr.op_str;

			if ((i + 1) != positions.size())
			{
				auto [oldpos, newpos] = positions[i + 1];
				if (newpos == (instr.address + instr.size))
				{
					if (instruction_sets[i + 1] != instruction_sets[i])
						arm.switch_instruction_set();
					++i;
				}
			}
		}
		return stream.str();
	}

	void ALTERHOOK_HIDDEN process_frozen_threads(trampoline& tramp, bool enable_hook, unsigned long& pc)
	{

	}
}
