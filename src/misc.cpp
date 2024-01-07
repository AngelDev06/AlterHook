/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "modifier.h"

namespace alterhook
{
  ALTERHOOK_HIDDEN std::shared_mutex hook_lock{};

  namespace exceptions
  {
    const char* disassembler_exception::get_error_string() const noexcept
    {
      return cs_strerror(static_cast<cs_err>(m_flag));
    }

    std::string trampoline_exception::info() const
    {
      std::stringstream stream;
      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_target);
      return stream.str();
    }

    std::string unsupported_instruction_handling::info() const
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

    std::string trampoline_max_size_exceeded::info() const
    {
      std::stringstream stream;
      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(get_target())
             << "\nSIZE: " << std::dec << m_size
             << "\nMAX SIZE: " << m_max_size;
      return stream.str();
    }

    std::string insufficient_function_size::info() const
    {
      std::stringstream stream;
      stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(get_target())
             << "\nSIZE: " << std::dec << m_size
             << "\nNEEDED SIZE: " << m_needed_size;
      return stream.str();
    }

    std::string os_exception::info() const
    {
      std::stringstream stream;
      stream << error_function() << " -> " << m_error_code.message();
      return stream.str();
    }

    std::string invalid_address::info() const
    {
      std::stringstream stream;
      stream << "address: 0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_address);
      return stream.str();
    }
  } // namespace exceptions

  hook_manager& hook_manager::get()
  {
    static hook_manager instance{};
    return instance;
  }
} // namespace alterhook
