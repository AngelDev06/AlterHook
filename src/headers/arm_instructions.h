/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

// all of the following are used to make asm generation look nicer than a mess of hardcoded constants
namespace alterhook
{
	enum reg_t
	{
		r0 = 0, r1 = 1, r2 = 2,
		r3 = 3, r4 = 4, r5 = 5,
		r6 = 6, r7 = 7, r8 = 8,
		r9 = 9, r10 = 10, r11 = 11,
		r12 = 12, r13 = 13, r14 = 14,
		r15 = 15, sp = r13, lr = r14,
		pc = r15
	};

	struct ARM_INSTRUCTION
	{
		uint32_t instr;

		constexpr void set_condition(CondCodes cond)
		{
			instr &= ~(0b1111 << 28);
			instr |= cond << 28;
		}

		constexpr void set_register(reg_t reg)
		{
			instr &= ~(0b1111 << 12);
			instr |= reg << 12;
		}

		void write_to(void* dst)
		{
			*static_cast<uint32_t*>(dst) = instr;
		}
	};

	struct PUSH : ARM_INSTRUCTION
	{
		constexpr PUSH(reg_t reg) : ARM_INSTRUCTION({ 0xE52D0004 | (reg << 12) }) {}
	};

	struct PUSH_REGLIST : ARM_INSTRUCTION
	{
		constexpr PUSH_REGLIST() : ARM_INSTRUCTION({ 0xE92D0000 }) {}
		void set_register(reg_t) = delete;

		constexpr void append(reg_t reg) { instr |= 1 << reg; }
		constexpr void remove(reg_t reg) { instr &= ~(1 << reg); }
		constexpr bool greatest(reg_t reg) { return (1 << reg) > (instr & 0xFFFF); }
	};

	struct POP : ARM_INSTRUCTION
	{
		constexpr POP(reg_t reg) : ARM_INSTRUCTION({ 0xE49D0004 | (reg << 12) }) {}
	};

	struct MOV : ARM_INSTRUCTION
	{
		constexpr MOV(reg_t dest, reg_t src) : ARM_INSTRUCTION({ 0xE1A00000 | (dest << 12) | src }) {}
		void set_register(reg_t) = delete;

		constexpr void set_destination_register(reg_t reg)
		{
			instr &= ~(0b1111 << 12);
			instr |= reg << 12;
		}
		constexpr void set_source_register(reg_t reg)
		{
			instr &= ~0b1111;
			instr |= reg;
		}
	};

	struct ADD : ARM_INSTRUCTION
	{
		constexpr ADD(reg_t dstreg, reg_t operandreg, uint16_t offset)
			: ARM_INSTRUCTION({ 0xE2800000 | (operandreg << 16) | (dstreg << 12) | offset }) {}

		constexpr void set_offset(uint16_t offset)
		{
			instr &= ~0xFFF;
			instr |= offset;
		}

		constexpr void set_destination_register(reg_t reg) { ARM_INSTRUCTION::set_register(reg); }
		constexpr void set_operand_register(reg_t reg)
		{
			instr &= ~(0b1111 << 16);
			instr |= reg << 16;
		}
		constexpr void set_register(reg_t reg)
		{
			set_destination_register(reg);
			set_operand_register(reg);
		}
	};

	struct LDR_LITERAL_LIKE : ARM_INSTRUCTION
	{
		constexpr void set_offset(int32_t offset)
		{
			instr &= ~0xFFF;

			if (offset >= 0)
			{
				instr |= 1 << 23;
				instr |= offset;
			}
			else
			{
				instr &= ~(1 << 23);
				instr |= -offset;
			}
		}

		constexpr void set_offset(int16_t offset)
		{
			instr &= ~0xF0F;

			if (offset >= 0)
			{
				instr |= 1 << 23;
				instr |= (offset & (0b1111 << 4)) << 4;
				instr |= offset & 0b1111;
			}
			else
			{
				instr &= ~(1 << 23);
				instr |= (-offset & (0b1111 << 4)) << 4;
				instr |= -offset & 0b1111;
			}
		}
	};

	struct LDRD_LITERAL : LDR_LITERAL_LIKE
	{
		constexpr LDRD_LITERAL(reg_t reg, int16_t offset) : LDR_LITERAL_LIKE({ 0xE14F00D0 | (reg << 12) }) { set_offset(offset); }
		constexpr void set_offset(int16_t offset) { LDR_LITERAL_LIKE::set_offset(offset); }
	};

	struct LDR_LITERAL : LDR_LITERAL_LIKE
	{
		constexpr LDR_LITERAL(reg_t reg, int32_t offset) : LDR_LITERAL_LIKE({ 0xE51F0000 | (reg << 12) }) { set_offset(offset); }
		constexpr void set_offset(int32_t offset) { LDR_LITERAL_LIKE::set_offset(offset); }
	};

	struct LDRH_LITERAL : LDR_LITERAL_LIKE
	{
		constexpr LDRH_LITERAL(reg_t reg, int16_t offset) : LDR_LITERAL_LIKE({ 0xE15F00B0 | (reg << 12) }) { set_offset(offset); }
		constexpr void set_offset(int16_t offset) { LDR_LITERAL_LIKE::set_offset(offset); }
	};

	struct LDRB_LITERAL : LDR_LITERAL_LIKE
	{
		constexpr LDRB_LITERAL(reg_t reg, int32_t offset) : LDR_LITERAL_LIKE({ 0xE55F0000 | (reg << 12) }) { set_offset(offset); }
		constexpr void set_offset(int32_t offset) { LDR_LITERAL_LIKE::set_offset(offset); }
	};

	struct JMP_ABS
	{
		LDR_LITERAL ldr;

		constexpr JMP_ABS() : ldr(pc, -4) {}

		constexpr void set_offset(int32_t offset) { ldr.set_offset(offset); }

		constexpr void set_condition(CondCodes cond) { ldr.set_condition(cond); }

		void write_to(void* dst) { memcpy(dst, this, sizeof(JMP_ABS)); }
	};

	struct FULL_JMP_ABS
	{
		LDR_LITERAL ldr;
		uint32_t address;

		constexpr FULL_JMP_ABS(uint32_t address) : ldr(pc, -4), address(address) {}

		void write_to(void* dst) { memcpy(dst, this, sizeof(FULL_JMP_ABS)); }
	};

	struct CALL_ABS
	{
		MOV mov;
		LDR_LITERAL ldr;

		constexpr CALL_ABS() : mov(lr, pc), ldr(pc, -4) {}

		constexpr void set_offset(int32_t offset) { ldr.set_offset(offset - 4); }

		constexpr void set_condition(CondCodes cond)
		{
			mov.set_condition(cond);
			ldr.set_condition(cond);
		}

		void write_to(void* dst) { memcpy(dst, this, sizeof(CALL_ABS)); }
	};

	struct THUMB2_INSTRUCTION
	{
		uint16_t opcode;
		uint16_t operands;

		constexpr void set_register(reg_t reg)
		{
			operands &= ~(0b1111 << 12);
			operands |= reg << 12;
		}

		void write_to(void* dst)
		{
			*static_cast<THUMB2_INSTRUCTION*>(dst) = *this;
		}
	};

	struct THUMB2_PUSH_REGLIST : THUMB2_INSTRUCTION
	{
		constexpr THUMB2_PUSH_REGLIST() : THUMB2_INSTRUCTION({ 0xE92D, 0x0000 }) {}
		void set_register(reg_t) = delete;

		constexpr void append(reg_t reg) { operands |= 1 << reg; }
		constexpr void remove(reg_t reg) { operands &= ~(1 << reg); }
		constexpr bool greatest(reg_t reg) { return (1 << reg) > operands; }
	};

	struct THUMB2_LDR_LITERAL_LIKE : THUMB2_INSTRUCTION
	{
		constexpr void set_offset(int32_t offset)
		{
			operands &= ~0xFFF;
			if (offset >= 0)
			{
				opcode |= 1 << 7;
				operands |= offset;
			}
			else
			{
				opcode &= ~(1 << 7);
				operands |= -offset;
			}
		}
	};

	struct THUMB2_LDRD_LITERAL : THUMB2_LDR_LITERAL_LIKE
	{
		constexpr THUMB2_LDRD_LITERAL(reg_t reg1, reg_t reg2, int16_t offset)
			: THUMB2_LDR_LITERAL_LIKE({ 0xE95F, static_cast<uint16_t>((reg1 << 12) | (reg2 << 8)) }) {
			set_offset(offset);
		}

		constexpr void set_register_2(reg_t reg)
		{
			operands &= ~(0b1111 << 8);
			operands |= reg << 8;
		}

		constexpr void set_offset(int16_t offset)
		{
			operands &= ~0xFF;

			if (offset >= 0)
			{
				opcode |= 1 << 7;
				operands |= offset;
			}
			else
			{
				opcode &= ~(1 << 7);
				operands |= -offset;
			}
		}
	};

	struct THUMB2_LDR_LITERAL : THUMB2_LDR_LITERAL_LIKE
	{
		constexpr THUMB2_LDR_LITERAL(reg_t reg, int32_t offset) : THUMB2_LDR_LITERAL_LIKE({ 0xF85F, static_cast<uint16_t>(reg << 12) })
		{
			set_offset(offset);
		}
	};

	struct THUMB2_LDRH_LITERAL : THUMB2_LDR_LITERAL_LIKE
	{
		constexpr THUMB2_LDRH_LITERAL(reg_t reg, int32_t offset) : THUMB2_LDR_LITERAL_LIKE({ 0xF83F, static_cast<uint16_t>(reg << 12) })
		{
			set_offset(offset);
		}
	};

	struct THUMB2_LDRB_LITERAL : THUMB2_LDR_LITERAL_LIKE
	{
		constexpr THUMB2_LDRB_LITERAL(reg_t reg, int32_t offset) : THUMB2_LDR_LITERAL_LIKE({ 0xF81F, static_cast<uint16_t>(reg << 12) })
		{
			set_offset(offset);
		}
	};

	struct THUMB2_ADD : THUMB2_INSTRUCTION
	{
		constexpr THUMB2_ADD(reg_t destreg, reg_t operandreg, uint16_t offset)
			: THUMB2_INSTRUCTION({ static_cast<uint16_t>(0xF200 | operandreg), static_cast<uint16_t>(destreg << 8) })
		{
			set_offset(offset);
		}

		void set_register(reg_t reg) = delete;
		constexpr void set_destination_register(reg_t reg)
		{
			operands &= ~(0b1111 << 8);
			operands |= reg << 8;
		}
		constexpr void set_operand_register(reg_t reg)
		{
			opcode &= ~0b1111;
			opcode |= reg;
		}
		constexpr void set_offset(uint16_t offset)
		{
			opcode &= ~(1 << 10);
			opcode |= (offset >> 1) & (1 << 10);
			operands &= ~0x70FF;
			operands |= (offset & (0b111 << 8)) << 4;
			operands |= offset & 0xFF;
		}
	};

	struct THUMB2_JMP_ABS
	{
		THUMB2_LDR_LITERAL ldr;

		constexpr THUMB2_JMP_ABS() : ldr(pc, 0) {}

		constexpr void set_offset(int32_t offset) { ldr.set_offset(offset); }

		void write_to(void* dst)
		{
			memcpy(dst, this, sizeof(THUMB2_JMP_ABS));
		}
	};

	struct THUMB2_FULL_JMP_ABS
	{
		THUMB2_LDR_LITERAL ldr;
		uint32_t address;

		constexpr THUMB2_FULL_JMP_ABS(uint32_t address) : ldr(pc, 0), address(address) {}

		void write_to(void* dst) { memcpy(dst, this, sizeof(THUMB2_FULL_JMP_ABS)); }
	};

	struct THUMB2_CALL_ABS
	{
		THUMB2_ADD add;
		THUMB2_LDR_LITERAL ldr;

		constexpr THUMB2_CALL_ABS() : add(lr, pc, 5), ldr(pc, 0) {}

		constexpr void set_offset(int32_t offset) { ldr.set_offset(offset - 4); }

		constexpr void align() { add.set_offset(7); }

		void write_to(void* dst) { memcpy(dst, this, sizeof(THUMB2_CALL_ABS)); }
	};

	struct THUMB_INSTRUCTION
	{
		uint16_t instr;

		constexpr void set_register(reg_t reg)
		{
			instr &= ~(0b111 << 8);
			instr |= reg << 8;
		}

		constexpr void set_offset(uint8_t offset)
		{
			instr &= ~0xFF;
			instr |= offset;
		}

		void write_to(void* dst)
		{
			*static_cast<uint16_t*>(dst) = instr;
		}
	};

	struct THUMB_PUSH : THUMB_INSTRUCTION
	{
		constexpr THUMB_PUSH(reg_t reg) : THUMB_INSTRUCTION({ static_cast<uint16_t>(0xB400 | (1 << reg)) }) {}
		void set_offset(uint8_t offset) = delete;
		constexpr void set_register(reg_t reg)
		{
			instr &= ~0xFF;
			if (reg == lr)
				instr |= 1 << 8;
			else
				instr |= 1 << reg;
		}
	};

	struct THUMB_PUSH_REGLIST : THUMB_INSTRUCTION
	{
		constexpr THUMB_PUSH_REGLIST() : THUMB_INSTRUCTION({ 0xB400 }) {}
		void set_offset(uint8_t) = delete;
		void set_register(reg_t) = delete;

		constexpr void append(reg_t reg)
		{
			if (reg == lr)
				instr |= 1 << 8;
			else
				instr |= 1 << reg;
		}
		constexpr void remove(reg_t reg)
		{
			if (reg == lr)
				instr &= ~(1 << 8);
			else
				instr &= ~(1 << reg);
		}
		constexpr bool greatest(reg_t reg)
		{
			if (reg == lr)
				return instr & (1 << 8);
			else
				return (1 << reg) > (instr & 0x1FF);
		}
	};

	struct THUMB_POP : THUMB_INSTRUCTION
	{
		constexpr THUMB_POP(reg_t reg) : THUMB_INSTRUCTION({ static_cast<uint16_t>(0xBC00 | (1 << reg)) }) {}
		void set_offset(uint8_t offset) = delete;
		constexpr void set_register(reg_t reg)
		{
			instr &= ~0xFF;
			if (reg == pc)
				instr |= 1 << 8;
			else
				instr |= 1 << reg;
		}
	};

	struct THUMB_LDR_LITERAL : THUMB_INSTRUCTION
	{
		constexpr THUMB_LDR_LITERAL(reg_t reg, uint8_t offset) : THUMB_INSTRUCTION({ static_cast<uint16_t>(0x4800 | (reg << 8) | offset) }) {}
	};

	struct THUMB_ADD : THUMB_INSTRUCTION
	{
		constexpr THUMB_ADD(reg_t reg, uint8_t offset) : THUMB_INSTRUCTION({ static_cast<uint16_t>(0x3000 | (reg << 8) | offset) }) {}
	};

	// LMAO
	struct NOP : private ARM_INSTRUCTION
	{
		constexpr NOP() : ARM_INSTRUCTION({ 0xE320F000 }) {}
		using ARM_INSTRUCTION::write_to;
	};
	struct THUMB_NOP : private THUMB_INSTRUCTION
	{
		constexpr THUMB_NOP() : THUMB_INSTRUCTION({ 0xBF00 }) {}
		using THUMB_INSTRUCTION::write_to;
	};
	struct THUMB2_NOP : private THUMB2_INSTRUCTION
	{
		constexpr THUMB2_NOP() : THUMB2_INSTRUCTION({ 0xF3AF, 0x8000 }) {}
		using THUMB2_INSTRUCTION::write_to;
	};

	struct THUMB_IT : private THUMB_INSTRUCTION
	{
		enum it_cond { T, E, NONE };

		constexpr THUMB_IT(CondCodes condition, it_cond scond = NONE, it_cond tcond = NONE, it_cond fcond = NONE)
			: THUMB_INSTRUCTION({ static_cast<uint16_t>(0xBF08 | (condition << 4)) })
		{
			set_second_condition(scond);
			set_third_condition(tcond);
			set_fourth_condition(fcond);
		}

		constexpr uint8_t instruction_count() const
		{
			if ((instr & 0b1111) == 0b1000)
				return 1;
			if ((instr & 0b111) == 0b100)
				return 2;
			if ((instr & 0b11) == 0b10)
				return 3;
			return 4;
		}
		constexpr void set_condition(uint8_t pos, it_cond cond)
		{
			switch (pos)
			{
			case 2: return set_second_condition(cond);
			case 3: return set_third_condition(cond);
			case 4: return set_fourth_condition(cond);
			}
		}
		constexpr void set_condition(CondCodes cond)
		{
			instr &= ~(0b1111 << 4);
			instr |= cond << 4;
		}
		constexpr void set_second_condition(it_cond cond)
		{
			if (cond != NONE)
			{
				if (instruction_count() == 1)
					instr ^= 0b1100;
				else
					instr &= ~(1 << 3);
			}

			switch (cond)
			{
			case T:
				instr |= (instr >> 1) & 0b1000;
				break;
			case E:
				instr |= ~(instr >> 1) & 0b1000;
				break;
			}
		}
		constexpr void set_third_condition(it_cond cond)
		{
			if (cond != NONE)
			{
				if (instruction_count() < 3)
					instr ^= 0b110;
				else
					instr &= ~(1 << 2);
			}

			switch (cond)
			{
			case T:
				instr |= (instr >> 2) & 0b100;
				break;
			case E:
				instr |= ~(instr >> 2) & 0b100;
				break;
			}
		}
		constexpr void set_fourth_condition(it_cond cond)
		{
			if (cond != NONE)
			{
				if (instruction_count() < 4)
					instr ^= 0b11;
				else
					instr &= ~(1 << 1);
			}

			switch (cond)
			{
			case T:
				instr |= (instr >> 3) & 0b10;
				break;
			case E:
				instr |= ~(instr >> 3) & 0b10;
				break;
			}
		}
		constexpr void pop_instruction()
		{
			switch (instruction_count())
			{
			case 2:
				instr &= ~0b100;
				instr |= 0b1000;
				break;
			case 3:
				instr &= ~0b10;
				instr |= 0b100;
				break;
			case 4:
				instr &= ~1;
				instr |= 0b10;
				break;
			}
		}
		constexpr void pop(uint8_t count)
		{
			for (uint8_t i = 0; i != count; ++i)
				pop_instruction();
		}
		constexpr it_cond get_condition(uint8_t pos)
		{
			switch (pos)
			{
			case 2: return get_second_condition();
			case 3: return get_third_condition();
			case 4: return get_fourth_condition();
			default: return NONE;
			}
		}
		constexpr CondCodes get_condition() { return static_cast<CondCodes>((instr >> 4) & 0b1111); }
		constexpr it_cond get_second_condition() { return ((instr >> 3) & 1) == ((instr >> 4) & 1) ? T : E; }
		constexpr it_cond get_third_condition() { return ((instr >> 2) & 1) == ((instr >> 4) & 1) ? T : E; }
		constexpr it_cond get_fourth_condition() { return ((instr >> 1) & 1) == ((instr >> 4) & 1) ? T : E; }
		using THUMB_INSTRUCTION::write_to;
	};
}
