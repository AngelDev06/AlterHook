/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"

namespace alterhook::exceptions
{
  std::string virtual_alloc_exception::error_function() const
  {
    std::stringstream stream;
    stream << "VirtualAlloc(0x" << std::hex << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_target_address) << ", " << std::dec
           << m_size << ", " << m_allocation_type << ", " << m_protection
           << ')';
    return stream.str();
  }

  std::string thread_list_traversal_fail::error_function() const
  {
    std::stringstream stream;
    stream << "Thread32Next(0x" << std::hex << std::setfill('0') << std::setw(8)
           << reinterpret_cast<uintptr_t>(m_handle) << ", 0x"
           << std::setfill('0') << std::setw(8) << m_thread_entry_address
           << ')';
    return stream.str();
  }

  std::string virtual_protect_exception::error_function() const
  {
    std::stringstream stream;
    stream << "VirtualProtect(0x" << std::hex << std::setfill('0')
           << std::setw(8) << m_address << ", " << std::dec << m_size << ", 0x"
           << std::hex << std::setfill('0') << std::setw(8) << m_protection
           << ", 0x" << std::setfill('0') << std::setw(8) << m_old_protection
           << ')';
    return stream.str();
  }
}
