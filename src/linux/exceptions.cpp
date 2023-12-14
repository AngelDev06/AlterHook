/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"

namespace alterhook::exceptions
{
  std::string mmap_exception::error_function() const
  {
    std::stringstream stream;
    stream << "mmap(0x" << std::hex << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_target_address) << ", " << std::dec
           << m_size << ", " << m_protection << ", " << m_flags << ", " << m_fd
           << ", " << m_offset << ')';
    return stream.str();
  }

  std::string sigaction_exception::error_function() const
  {
    std::stringstream stream;
    stream << "sigaction(" << m_signal << ", 0x" << std::hex
           << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_action) << ", 0x"
           << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_old_action) << ')';
    return stream.str();
  }

  std::string thread_process_fail::info() const
  {
    std::stringstream stream;
    stream << "trampoline address: 0x" << std::hex << std::setfill('0')
           << std::setw(8) << reinterpret_cast<uintptr_t>(m_trampoline_address)
           << "\ntarget address: 0x" << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_target_address)
           << "\nposition: " << std::dec << m_position;
    return stream.str();
  }

  std::string mprotect_exception::error_function() const
  {
    std::stringstream stream;
    stream << "mprotect(" << std::hex << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_address) << ", " << std::dec
           << m_length << ", " << m_protection << ')';
    return stream.str();
  }
}