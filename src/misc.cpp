/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"

namespace alterhook
{
  namespace exceptions
  {
    const char* disassembler_exception::get_error_string() const noexcept
    {
      return cs_strerror(static_cast<cs_err>(m_flag));
    }

#if utils_arm
  #define __alterhook_open_cs(handle)                                          \
    cs_open(CS_ARCH_ARM, m_thumb ? CS_MODE_THUMB : CS_MODE_ARM, &handle)
#elif utils_x64
  #define __alterhook_open_cs(handle) cs_open(CS_ARCH_X86, CS_MODE_64, &handle)
#else
  #define __alterhook_open_cs(handle) cs_open(CS_ARCH_X86, CS_MODE_32, &handle)
#endif

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
      csh               handle  = 0;
      cs_insn*          instr   = nullptr;
      size_t            size    = 24;
      const uint8_t*    buffer  = reinterpret_cast<const uint8_t*>(m_instr);
      uint64_t          address = reinterpret_cast<uintptr_t>(get_target());
      const auto        cleanup = [&]()
      {
        cs_free(instr, 1);
        cs_close(&handle);
      };

      if (__alterhook_open_cs(handle) || !(instr = cs_malloc(handle)) ||
          !cs_disasm_iter(handle, &buffer, &size, &address, instr))
      {
        cleanup();
        return {};
      }

      try
      {
        stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
               << reinterpret_cast<uintptr_t>(get_target()) << '\n';
        stream << "0x" << std::hex << std::setfill('0') << std::setw(8)
               << instr->address << ": " << instr->mnemonic << '\t'
               << instr->op_str;
      }
      catch (...)
      {
        cleanup();
        throw;
      }
      cleanup();
      return stream.str();
    }

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
