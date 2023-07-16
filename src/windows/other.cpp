#include <pch.h>
#include "exceptions.h"

#if utils_msvc
#pragma warning(push)
#pragma warning(disable : 4996)
#endif

namespace alterhook
{
	namespace exceptions
	{
		const char* os_exception::get_error_string() const noexcept { return strerror(m_error_code); }
		std::string virtual_alloc_exception::error_function() const
		{
			std::stringstream stream;
			stream << "VirtualAlloc(" << std::hex << std::setfill('0') << std::setw(8)
				<< reinterpret_cast<uintptr_t>(m_target_address) << ", " << std::dec << m_size
				<< ", " << m_allocation_type << ", " << m_protection << ')';
			return stream.str();
		}
	}
}

#if utils_msvc
#pragma warning(pop)
#endif
