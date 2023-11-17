/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

#if utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wswitch"
  #pragma clang diagnostic ignored "-Wmissing-braces"
#endif

#pragma GCC visibility push(hidden)

// all of the following are used to make asm generation look nicer than a mess
// of hardcoded constants
namespace alterhook
{
  enum reg_t
  {
    r0  = 0,
    r1  = 1,
    r2  = 2,
    r3  = 3,
    r4  = 4,
    r5  = 5,
    r6  = 6,
    r7  = 7,
    r8  = 8,
    r9  = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
    sp  = r13,
    lr  = r14,
    pc  = r15
  };

  namespace arm
  {
    struct INSTRUCTION
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
    };

    struct PUSH : INSTRUCTION
    {
      constexpr PUSH(reg_t reg) : INSTRUCTION({ 0xE5'2D'00'04 | (reg << 12) })
      {
      }
    };

    struct PUSH_REGLIST : INSTRUCTION
    {
      constexpr PUSH_REGLIST() : INSTRUCTION({ 0xE9'2D'00'00 }) {}

      void set_register(reg_t) = delete;

      constexpr void append(reg_t reg) { instr |= 1 << reg; }

      constexpr void remove(reg_t reg) { instr &= ~(1 << reg); }

      constexpr bool greatest(reg_t reg)
      {
        return (1 << reg) > (instr & 0xFF'FF);
      }
    };

    struct POP : INSTRUCTION
    {
      constexpr POP(reg_t reg) : INSTRUCTION({ 0xE4'9D'00'04 | (reg << 12) }) {}
    };

    struct MOV : INSTRUCTION
    {
      constexpr MOV(reg_t dest, reg_t src)
          : INSTRUCTION({ 0xE1'A0'00'00 | (dest << 12) | src })
      {
      }

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

    struct ADD : INSTRUCTION
    {
      constexpr ADD(reg_t dstreg, reg_t operandreg, uint16_t offset)
          : INSTRUCTION({ 0xE2'80'00'00 | (operandreg << 16) | (dstreg << 12) |
                          offset })
      {
      }

      constexpr void set_offset(uint16_t offset)
      {
        instr &= ~0xFFF;
        instr |= offset;
      }

      constexpr void set_destination_register(reg_t reg)
      {
        INSTRUCTION::set_register(reg);
      }

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

    struct LDR_LITERAL_LIKE : INSTRUCTION
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
      constexpr LDRD_LITERAL(reg_t reg, int16_t offset)
          : LDR_LITERAL_LIKE({ 0xE1'4F'00'D0 | (reg << 12) })
      {
        set_offset(offset);
      }

      constexpr void set_offset(int16_t offset)
      {
        LDR_LITERAL_LIKE::set_offset(offset);
      }
    };

    struct LDR_LITERAL : LDR_LITERAL_LIKE
    {
      constexpr LDR_LITERAL(reg_t reg, int32_t offset)
          : LDR_LITERAL_LIKE({ 0xE5'1F'00'00 | (reg << 12) })
      {
        set_offset(offset);
      }

      constexpr void set_offset(int32_t offset)
      {
        LDR_LITERAL_LIKE::set_offset(offset);
      }
    };

    struct LDRH_LITERAL : LDR_LITERAL_LIKE
    {
      constexpr LDRH_LITERAL(reg_t reg, int16_t offset)
          : LDR_LITERAL_LIKE({ 0xE1'5F'00'B0 | (reg << 12) })
      {
        set_offset(offset);
      }

      constexpr void set_offset(int16_t offset)
      {
        LDR_LITERAL_LIKE::set_offset(offset);
      }
    };

    struct LDRB_LITERAL : LDR_LITERAL_LIKE
    {
      constexpr LDRB_LITERAL(reg_t reg, int32_t offset)
          : LDR_LITERAL_LIKE({ 0xE5'5F'00'00 | (reg << 12) })
      {
        set_offset(offset);
      }

      constexpr void set_offset(int32_t offset)
      {
        LDR_LITERAL_LIKE::set_offset(offset);
      }
    };

    struct NOP : private INSTRUCTION
    {
      constexpr NOP() : INSTRUCTION({ 0xE3'20'F0'00 }) {}
    };

    namespace custom
    {
      struct JMP
      {
        LDR_LITERAL ldr;

        constexpr JMP() : ldr(pc, -4) {}

        constexpr void set_offset(int32_t offset) { ldr.set_offset(offset); }

        constexpr void set_condition(CondCodes cond)
        {
          ldr.set_condition(cond);
        }
      };

      struct FULL_JMP
      {
        LDR_LITERAL ldr;
        uint32_t    address;

        constexpr FULL_JMP(uint32_t address) : ldr(pc, -4), address(address) {}
      };

      struct CALL_ABS
      {
        MOV         mov;
        LDR_LITERAL ldr;

        constexpr CALL_ABS() : mov(lr, pc), ldr(pc, -4) {}

        constexpr void set_offset(int32_t offset)
        {
          ldr.set_offset(offset - 4);
        }

        constexpr void set_condition(CondCodes cond)
        {
          mov.set_condition(cond);
          ldr.set_condition(cond);
        }
      };
    } // namespace custom
  }   // namespace arm

  namespace thumb2
  {
    struct INSTRUCTION
    {
      uint16_t opcode;
      uint16_t operands;

      constexpr void set_register(reg_t reg)
      {
        operands &= ~(0b1111 << 12);
        operands |= reg << 12;
      }
    };

    struct PUSH_REGLIST : INSTRUCTION
    {
      constexpr PUSH_REGLIST() : INSTRUCTION({ 0xE9'2D, 0x00'00 }) {}

      void set_register(reg_t) = delete;

      constexpr void append(reg_t reg) { operands |= 1 << reg; }

      constexpr void remove(reg_t reg) { operands &= ~(1 << reg); }

      constexpr bool greatest(reg_t reg) { return (1 << reg) > operands; }
    };

    struct LDR_LITERAL_LIKE : INSTRUCTION
    {
      constexpr void set_offset(int32_t offset)
      {
        operands &= ~0xFFF;
        if (offset >= 0)
        {
          opcode   |= 1 << 7;
          operands |= offset;
        }
        else
        {
          opcode   &= ~(1 << 7);
          operands |= -offset;
        }
      }
    };

    struct LDRD_LITERAL : LDR_LITERAL_LIKE
    {
      constexpr LDRD_LITERAL(reg_t reg1, reg_t reg2, int16_t offset)
          : LDR_LITERAL_LIKE(
                { 0xE9'5F, static_cast<uint16_t>((reg1 << 12) | (reg2 << 8)) })
      {
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
          opcode   |= 1 << 7;
          operands |= offset;
        }
        else
        {
          opcode   &= ~(1 << 7);
          operands |= -offset;
        }
      }
    };

    struct LDR_LITERAL : LDR_LITERAL_LIKE
    {
      constexpr LDR_LITERAL(reg_t reg, int32_t offset)
          : LDR_LITERAL_LIKE({ 0xF8'5F, static_cast<uint16_t>(reg << 12) })
      {
        set_offset(offset);
      }
    };

    struct LDRH_LITERAL : LDR_LITERAL_LIKE
    {
      constexpr LDRH_LITERAL(reg_t reg, int32_t offset)
          : LDR_LITERAL_LIKE({ 0xF8'3F, static_cast<uint16_t>(reg << 12) })
      {
        set_offset(offset);
      }
    };

    struct LDRB_LITERAL : LDR_LITERAL_LIKE
    {
      constexpr LDRB_LITERAL(reg_t reg, int32_t offset)
          : LDR_LITERAL_LIKE({ 0xF8'1F, static_cast<uint16_t>(reg << 12) })
      {
        set_offset(offset);
      }
    };

    struct LDR_IMM : INSTRUCTION
    {
      constexpr LDR_IMM(reg_t destreg, reg_t operandreg, uint16_t offset)
          : INSTRUCTION({ static_cast<uint16_t>(0xF8'D0 | operandreg),
                          static_cast<uint16_t>((destreg << 12) | offset) })
      {
      }

      void set_register(reg_t reg) = delete;

      constexpr void set_destination_register(reg_t reg)
      {
        INSTRUCTION::set_register(reg);
      }

      constexpr void set_operand_register(reg_t reg)
      {
        opcode &= ~0b1111;
        opcode |= reg;
      }

      constexpr void set_offset(uint16_t offset)
      {
        operands &= ~0xFFF;
        operands |= offset;
      }
    };

    struct ADD : INSTRUCTION
    {
      constexpr ADD(reg_t destreg, reg_t operandreg, uint16_t offset)
          : INSTRUCTION({ static_cast<uint16_t>(0xF2'00 | operandreg),
                          static_cast<uint16_t>(destreg << 8) })
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
        opcode   &= ~(1 << 10);
        opcode   |= (offset >> 1) & (1 << 10);
        operands &= ~0x70'FF;
        operands |= (offset & (0b111 << 8)) << 4;
        operands |= offset & 0xFF;
      }
    };

    struct INCREMENTAL_ADD : ADD
    {
      constexpr INCREMENTAL_ADD(reg_t reg, uint16_t offset)
          : ADD(reg, reg, offset)
      {
      }

      constexpr void set_register(reg_t reg)
      {
        ADD::set_destination_register(reg);
        ADD::set_operand_register(reg);
      }

      void set_destination_register(reg_t) = delete;
      void set_operand_register(reg_t)     = delete;
    };

    struct NOP : private INSTRUCTION
    {
      constexpr NOP() : INSTRUCTION({ 0xF3'AF, 0x80'00 }) {}
    };

    namespace custom
    {
      struct JMP
      {
        LDR_LITERAL ldr;

        constexpr JMP() : ldr(pc, 0) {}

        constexpr void set_offset(int32_t offset) { ldr.set_offset(offset); }
      };

      struct FULL_JMP
      {
        LDR_LITERAL ldr;
        uint32_t    address;

        constexpr FULL_JMP(uint32_t address) : ldr(pc, 0), address(address) {}
      };

      struct CALL
      {
        ADD         add;
        LDR_LITERAL ldr;

        constexpr CALL() : add(lr, pc, 5), ldr(pc, 0) {}

        constexpr void set_offset(int32_t offset)
        {
          ldr.set_offset(offset - 4);
        }

        constexpr void align() { add.set_offset(7); }
      };
    } // namespace custom
  }   // namespace thumb2

  namespace thumb
  {
    struct INSTRUCTION
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
    };

    struct PUSH : INSTRUCTION
    {
      constexpr PUSH(reg_t reg)
          : INSTRUCTION({ static_cast<uint16_t>(0xB4'00 | (1 << reg)) })
      {
      }

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

    struct PUSH_REGLIST : INSTRUCTION
    {
      constexpr PUSH_REGLIST() : INSTRUCTION({ 0xB4'00 }) {}

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

    struct POP : INSTRUCTION
    {
      constexpr POP(reg_t reg)
          : INSTRUCTION({ static_cast<uint16_t>(0xBC'00 | (1 << reg)) })
      {
      }

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

    struct LDR_LITERAL : INSTRUCTION
    {
      constexpr LDR_LITERAL(reg_t reg, uint8_t offset)
          : INSTRUCTION(
                { static_cast<uint16_t>(0x48'00 | (reg << 8) | offset) })
      {
      }
    };

    struct ADD : INSTRUCTION
    {
      constexpr ADD(reg_t reg, uint8_t offset)
          : INSTRUCTION(
                { static_cast<uint16_t>(0x30'00 | (reg << 8) | offset) })
      {
      }
    };

    struct NOP : private INSTRUCTION
    {
      constexpr NOP() : INSTRUCTION({ 0xBF'00 }) {}
    };

    struct IT : private INSTRUCTION
    {
      enum it_cond
      {
        T,
        E,
        NONE
      };

      constexpr IT(CondCodes condition, it_cond scond = NONE,
                   it_cond tcond = NONE, it_cond fcond = NONE)
          : INSTRUCTION({ static_cast<uint16_t>(0xBF'08 | (condition << 4)) })
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
        case T: instr |= (instr >> 1) & 0b1000; break;
        case E: instr |= ~(instr >> 1) & 0b1000; break;
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
        case T: instr |= (instr >> 2) & 0b100; break;
        case E: instr |= ~(instr >> 2) & 0b100; break;
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
        case T: instr |= (instr >> 3) & 0b10; break;
        case E: instr |= ~(instr >> 3) & 0b10; break;
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

      constexpr CondCodes get_condition()
      {
        return static_cast<CondCodes>((instr >> 4) & 0b1111);
      }

      constexpr it_cond get_second_condition()
      {
        return ((instr >> 3) & 1) == ((instr >> 4) & 1) ? T : E;
      }

      constexpr it_cond get_third_condition()
      {
        return ((instr >> 2) & 1) == ((instr >> 4) & 1) ? T : E;
      }

      constexpr it_cond get_fourth_condition()
      {
        return ((instr >> 1) & 1) == ((instr >> 4) & 1) ? T : E;
      }
    };
  } // namespace thumb
} // namespace alterhook

#pragma GCC visibility pop

#if utils_clang
  #pragma clang diagnostic pop
#endif
