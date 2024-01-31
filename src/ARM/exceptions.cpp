/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "instructions.h"

namespace alterhook::exceptions
{
  std::string it_block_exception::info() const
  {
    std::stringstream       stream;
    alterhook::disassembler arm{ m_buffer.data(), true, false };

    stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(get_target())
           << "\nIT ORIGINAL ADDRESS: " << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_it_address)
           << "\nIT INSTRUCTION COUNT: " << std::dec << instruction_count()
           << "\nIT REMAINING INSTRUCTION COUNT: " << m_remaining_instructions
           << "\nIT BLOCK:";

    for (const cs_insn& instr : arm.disasm(m_buffer_size))
      stream << "\n\t0x" << std::hex << std::setfill('0') << std::setw(8)
             << instr.address << ": " << instr.mnemonic << '\t' << instr.op_str;
    return stream.str();
  }

  std::string it_block_exception::it_str() const
  {
    std::stringstream       stream;
    alterhook::disassembler arm{ m_buffer.data(), true, false };
    auto                    instr = arm.disasm(m_buffer_size).begin();

    stream << "0x" << std::hex << std::setfill('0') << std::setw(8)
           << instr->address << ": " << instr->mnemonic << '\t'
           << instr->op_str;
    return stream.str();
  }

  size_t it_block_exception::instruction_count() const
  {
    return reinterpret_cast<const thumb::IT*>(m_buffer.data())->count();
  }

  std::string pc_relative_handling_fail::info() const
  {
    std::stringstream       stream;
    alterhook::disassembler arm{ m_buffer.data(), m_thumb, false };
    auto                    instr = arm.disasm(m_buffer.size()).begin();

    stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(get_target()) << "\n0x"
           << std::setfill('0') << std::setw(8) << instr->address << ": "
           << instr->mnemonic << '\t' << instr->op_str;
    return stream.str();
  }

  std::string ambiguous_instruction_set::info() const
  {
    std::stringstream       stream;
    uint8_t                 instr_pos = 0;
    alterhook::disassembler arm{ m_buffer.data(), m_instruction_sets[instr_pos],
                                 false };
    stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(get_target())
           << "\nBRANCH DESTINATION: " << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_branch_destination) << '\n';

    for (const cs_insn& instr : arm.disasm(m_size))
    {
      stream << "0x" << std::setfill('0') << std::setw(8) << instr.address
             << ": " << instr.mnemonic << '\t' << instr.op_str << '\n';
      instr_pos += instr.size;
      if (arm.is_thumb() != m_instruction_sets[instr_pos])
        arm.switch_instruction_set();
    }

    return stream.str();
  }
} // namespace alterhook::exceptions