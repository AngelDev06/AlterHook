/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "buffer.h"
#include "exceptions.h"

namespace alterhook
{
  inline const auto memory_block_size = sysconf(_SC_PAGE_SIZE);

#if utils_64bit
  ALTERHOOK_HIDDEN std::pair<std::byte*, std::byte*>
                   get_minmax_address(std::byte* origin) noexcept
  {
    return { reinterpret_cast<uintptr_t>(origin) > max_memory_range
                 ? reinterpret_cast<std::byte*>(utils_align(
                       reinterpret_cast<uintptr_t>(origin) - max_memory_range,
                       memory_block_size))
                 : nullptr,
             reinterpret_cast<std::byte*>(utils_align(
                 reinterpret_cast<uintptr_t>(origin) + max_memory_range,
                 memory_block_size)) };
  }

  ALTERHOOK_HIDDEN std::byte* try_valloc(std::byte* origin)
  {
    auto [minaddr, maxaddr]         = get_minmax_address(origin);
    std::byte*       result         = nullptr;
    std::byte* const origin_aligned = reinterpret_cast<std::byte*>(
        utils_align(reinterpret_cast<uintptr_t>(origin), memory_block_size));
    std::byte* region = origin_aligned - memory_block_size;

    while (region >= minaddr)
    {
      errno  = 0;
      result = static_cast<std::byte*>(
          mmap(region, memory_block_size, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0, 0));
      if (!errno)
        return result;
      region -= memory_block_size;
    }

    region = origin_aligned + memory_block_size;
    while (region <= maxaddr)
    {
      errno  = 0;
      result = static_cast<std::byte*>(
          mmap(region, memory_block_size, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0, 0));
      if (!errno)
        return result;
      region += memory_block_size;
    }

    throw(exceptions::mmap_exception(
        errno, region, memory_block_size, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0, 0));
  }
#else
  ALTERHOOK_HIDDEN std::byte* try_valloc()
  {
    if (void* result =
            mmap(nullptr, memory_block_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0))
      return static_cast<std::byte*>(result);

    throw(exceptions::mmap_exception(errno, nullptr, memory_block_size,
                                     PROT_READ | PROT_WRITE | PROT_EXEC,
                                     MAP_PRIVATE | MAP_ANONYMOUS, 0, 0));
  }
#endif
} // namespace alterhook