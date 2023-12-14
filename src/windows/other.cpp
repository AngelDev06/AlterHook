/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "tools.h"

namespace alterhook
{
  constexpr size_t read_flags = PAGE_READONLY | PAGE_READWRITE |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
  constexpr size_t write_flags = PAGE_WRITECOPY | PAGE_READWRITE |
                                 PAGE_EXECUTE_WRITECOPY |
                                 PAGE_EXECUTE_READWRITE;
  constexpr size_t execute_flags = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                   PAGE_EXECUTE_READWRITE |
                                   PAGE_EXECUTE_WRITECOPY;

  protection_info get_protection(const void* address)
  {
    protection_info          info{};
    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(address, &mi, sizeof(mi));

    if (mi.State != MEM_COMMIT)
      return info;

    if (mi.Protect & read_flags)
      info.read = true;
    if (mi.Protect & write_flags)
      info.write = true;
    if (mi.Protect & execute_flags)
      info.execute = true;

    return info;
  }
} // namespace alterhook
