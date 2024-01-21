/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "buffer.h"
#include "exceptions.h"
#pragma GCC visibility push(hidden)

namespace alterhook
{
  inline const size_t memory_block_size = sysconf(_SC_PAGE_SIZE);
  constexpr auto      executable_memory = PROT_READ | PROT_WRITE | PROT_EXEC;

#if allocate_nearby
  std::pair<const std::byte*, const std::byte*>
      get_minmax_address(std::byte* origin)
  {
    const std::byte* const minaddr =
        reinterpret_cast<uintptr_t>(origin) > max_memory_range
            ? utils::align(origin - max_memory_range, memory_block_size)
            : nullptr;
    const std::byte* const maxaddr =
        (std::numeric_limits<uintptr_t>::max() - max_memory_range) >
                reinterpret_cast<uintptr_t>(origin)
            ? utils::align(origin + max_memory_range, memory_block_size)
            : reinterpret_cast<std::byte*>(
                  std::numeric_limits<uintptr_t>::max());
    return { minaddr, maxaddr };
  }

  constexpr auto mmap_config =
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
  constexpr auto mmap_random_config = MAP_PRIVATE | MAP_ANONYMOUS;

  memory_block* try_valloc(std::byte* origin)
  {
    auto [minaddr, maxaddr]         = get_minmax_address(origin);
    memory_block*    result         = nullptr;
    std::byte* const origin_aligned = utils::align(origin, memory_block_size);
    std::byte*       region         = origin_aligned - memory_block_size;

    while (region >= minaddr)
    {
      errno  = 0;
      result = static_cast<memory_block*>(mmap(
          region, memory_block_size, executable_memory, mmap_config, 0, 0));
      if (!errno)
        return result;
      region -= memory_block_size;
    }

    region = origin_aligned + memory_block_size;
    while (region <= maxaddr)
    {
      errno  = 0;
      result = static_cast<memory_block*>(mmap(
          region, memory_block_size, executable_memory, mmap_config, 0, 0));
      if (!errno)
        return result;
      region += memory_block_size;
    }

  #if !utils_x64
    if (result = static_cast<memory_block*>(mmap(nullptr, memory_block_size,
                                                 executable_memory,
                                                 mmap_random_config, 0, 0)))
      return result;
  #endif
    throw(exceptions::mmap_exception(errno, region, memory_block_size,
                                     executable_memory, mmap_config, 0, 0));
  }
#else
  constexpr auto mmap_config = MAP_PRIVATE | MAP_ANONYMOUS;

  memory_block* try_valloc()
  {
    if (auto* result = static_cast<memory_block*>(mmap(
            nullptr, memory_block_size, executable_memory, mmap_config, 0, 0)))
      return result;

    throw(exceptions::mmap_exception(errno, nullptr, memory_block_size,
                                     executable_memory, mmap_config, 0, 0));
  }
#endif
} // namespace alterhook

#pragma GCC visibility pop