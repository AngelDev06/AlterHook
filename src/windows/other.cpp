#include <pch.h>
#include "exceptions.h"

namespace alterhook
{
  namespace exceptions
  {
    // need to use strerror_s because strerror is NOT thread safe on windows
    const char* os_exception::get_error_string() const noexcept
    {
      strerror_s(buffer, 94, m_error_code);
      return buffer;
    }

    std::string virtual_alloc_exception::error_function() const
    {
      std::stringstream stream;
      stream << "VirtualAlloc(0x" << std::hex << std::setfill('0')
             << std::setw(8) << reinterpret_cast<uintptr_t>(m_target_address)
             << ", " << std::dec << m_size << ", " << m_allocation_type << ", "
             << m_protection << ')';
      return stream.str();
    }
  } // namespace exceptions
} // namespace alterhook
