/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#if utils_arm
  #include "arm_instructions.h"
#endif

namespace alterhook
{
  namespace exceptions
  {
    const char* disassembler_exception::get_error_string() const noexcept
    {
      return cs_strerror(static_cast<cs_err>(m_flag));
    }

    std::string trampoline_exception::str() const
    {
      std::stringstream stream;
      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_target);
      return stream.str();
    }

    std::string unsupported_instruction_handling::str() const
    {
      std::stringstream stream;
#if utils_arm
      alterhook::disassembler bin{ m_instr, m_thumb, false };
#else
      alterhook::disassembler bin{ m_instr, false };
#endif
      auto instr = bin.disasm(utils_array_size(m_instr)).begin();

      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(get_target()) << '\n'
             << "0x" << std::setfill('0') << std::setw(8) << instr->address
             << ": " << instr->mnemonic << '\t' << instr->op_str;
      return stream.str();
    }

#if utils_arm
    std::string it_block_exception::str() const
    {
      std::stringstream       stream;
      alterhook::disassembler arm{ m_buffer, true, false };

      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(get_target())
             << "\nIT INSTRUCTION COUNT: " << std::dec << instruction_count()
             << "\nIT REMAINING INSTRUCTION COUNT: " << m_remaining_instructions
             << "\nIT BLOCK:";
      
      for (const cs_insn& instr : arm.disasm(m_size))
        stream << "\n\t0x" << std::hex << std::setfill('0') << std::setw(8)
               << instr.address << ": " << instr.mnemonic << '\t'
               << instr.op_str;
      return stream.str();
    }

    std::string it_block_exception::it_str() const
    {
      std::stringstream       stream;
      alterhook::disassembler arm{ m_buffer, true, false };
      auto                    instr = arm.disasm(m_size).begin();

      stream << "0x" << std::hex << std::setfill('0') << std::setw(8)
             << instr->address << ": " << instr->mnemonic << '\t'
             << instr->op_str;
      return stream.str();
    }

    size_t it_block_exception::instruction_count() const
    {
      return reinterpret_cast<const THUMB_IT*>(m_buffer)->instruction_count();
    }

    std::string pc_relative_handling_fail::str() const
    {
      std::stringstream       stream;
      alterhook::disassembler arm{ m_buffer, m_thumb, false };
      auto instr = arm.disasm(utils_array_size(m_buffer)).begin();

      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(get_target()) << "\n0x"
             << std::setfill('0') << std::setw(8) << instr->address << ": "
             << instr->mnemonic << '\t' << instr->op_str;
      return stream.str();
    }
#endif

    std::string trampoline_max_size_exceeded::str() const
    {
      std::stringstream stream;
      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(get_target())
             << "\nSIZE: " << std::dec << m_size
             << "\nMAX SIZE: " << m_max_size;
      return stream.str();
    }

    std::string insufficient_function_size::str() const
    {
      std::stringstream stream;
      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(get_target())
             << "\nSIZE: " << std::dec << m_size
             << "\nNEEDED SIZE: " << m_needed_size;
      return stream.str();
    }

    std::string invalid_address::str() const
    {
      std::stringstream stream;
      stream << "address: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_address);
      return stream.str();
    }
  } // namespace exceptions
} // namespace alterhook
