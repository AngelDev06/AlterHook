/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "buffer.h"
#include "exceptions.h"
#pragma GCC visibility push(hidden)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

namespace alterhook
{
  constexpr size_t memory_block_size = 0x10'00;
  constexpr auto   valloc_config     = MEM_COMMIT | MEM_RESERVE;
  constexpr auto   executable_memory = PAGE_EXECUTE_READWRITE;

#if allocate_nearby
  static const std::tuple<std::byte*, std::byte*, DWORD>&
      get_alloc_info() noexcept
  {
    static auto getter = []() -> std::tuple<std::byte*, std::byte*, DWORD>
    {
      SYSTEM_INFO info;
      GetSystemInfo(&info);
      return { static_cast<std::byte*>(info.lpMinimumApplicationAddress),
               static_cast<std::byte*>(info.lpMaximumApplicationAddress),
               info.dwAllocationGranularity };
    };
    static std::tuple data = getter();
    return data;
  }

  static DWORD get_allocation_granularity() noexcept
  {
    const auto& [minmaxaddr, maxaddr, ag] = get_alloc_info();
    return ag;
  }

  std::pair<const std::byte*, const std::byte*>
      get_minmax_address(std::byte* origin) noexcept
  {
    auto [minaddr, maxaddr, ag] = get_alloc_info();

    if (reinterpret_cast<uintptr_t>(origin) > max_memory_range &&
        minaddr < (origin - max_memory_range))
      minaddr = origin - max_memory_range;
    if ((maxaddr - max_memory_range) > origin)
      maxaddr = origin + max_memory_range;

    return { minaddr, maxaddr };
  }

  memory_block* try_valloc(std::byte* origin)
  {
    auto [minaddr, maxaddr]                 = get_minmax_address(origin);
    DWORD                    ag             = get_allocation_granularity();
    memory_block*            result         = nullptr;
    std::byte* const         origin_aligned = utils::align(origin, ag);
    std::byte*               region         = origin_aligned - ag;
    MEMORY_BASIC_INFORMATION mbi;

    for (; region >= minaddr && VirtualQuery(region, &mbi, sizeof(mbi));
         region = static_cast<std::byte*>(mbi.AllocationBase) - ag)
    {
      if (mbi.State != MEM_FREE)
        continue;
      if ((result = static_cast<memory_block*>(VirtualAlloc(
               region, memory_block_size, valloc_config, executable_memory))))
        return result;
      if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) < ag)
        break;
    }

    region = origin_aligned + ag;
    for (; region <= maxaddr && VirtualQuery(region, &mbi, sizeof(mbi));
         region = utils::align_up(
             static_cast<std::byte*>(mbi.AllocationBase) + mbi.RegionSize, ag))
    {
      if (mbi.State != MEM_FREE)
        continue;
      if ((result = static_cast<memory_block*>(VirtualAlloc(
               region, memory_block_size, valloc_config, executable_memory))))
        return result;
    }

  #if !utils_x64
    if (result = static_cast<memory_block*>(VirtualAlloc(
            nullptr, memory_block_size, valloc_config, executable_memory)))
      return result;
  #endif

    throw(exceptions::virtual_alloc_exception(GetLastError(), region,
                                              memory_block_size, valloc_config,
                                              executable_memory));
  }
#else
  memory_block* try_valloc()
  {
    if (auto* result = static_cast<memory_block*>(VirtualAlloc(
            nullptr, memory_block_size, valloc_config, executable_memory)))
      return result;

    throw(exceptions::virtual_alloc_exception(
        GetLastError(), nullptr, memory_block_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
  }
#endif
} // namespace alterhook

#pragma GCC diagnostic pop
#pragma GCC visibility pop
