/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "tools.h"

namespace alterhook
{
  protection_info get_protection(const void* address)
  {
    protection_info info{};
    std::ifstream maps{ "/proc/self/maps" };
    utils_assert(maps.is_open(), "get_protection: couldn't open `/proc/self/maps`");

    do
    {
      uintptr_t begin_address = 0;
      uintptr_t end_address   = 0;

      maps >> std::hex >> begin_address;
      maps.seekg(1, std::ios_base::cur);
      maps >> end_address;

      if (reinterpret_cast<uintptr_t>(address) >= begin_address &&
          reinterpret_cast<uintptr_t>(address) < end_address)
      {
        char perms[5]{};
        int  result = PROT_NONE;
        maps >> perms;

        if (perms[0] == 'r')
          info.read = true;
        if (perms[1] == 'w')
          info.write = true;
        if (perms[2] == 'x')
          info.execute = true;
        return info;
      }

      maps.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    } while (maps.good());

    return info;
  }
} // namespace alterhook
