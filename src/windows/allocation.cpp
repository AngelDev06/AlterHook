/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "buffer.h"
#include "exceptions.h"

namespace alterhook
{
  constexpr size_t memory_block_size = 0x10'00;
#if utils_64bit
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

  std::pair<std::byte*, std::byte*>
      get_minmax_address(std::byte* origin) noexcept
  {
    auto [minaddr, maxaddr, ag] = get_alloc_info();

    if (reinterpret_cast<uintptr_t>(origin) > max_memory_range &&
        minaddr < (origin - max_memory_range))
      minaddr = origin - max_memory_range;
    if (maxaddr > (origin + max_memory_range))
      maxaddr = origin + max_memory_range;

    return { minaddr, maxaddr };
  }

  std::byte* try_valloc(std::byte* origin)
  {
    auto [minaddr, maxaddr]         = get_minmax_address(origin);
    DWORD            ag             = get_allocation_granularity();
    std::byte*       result         = nullptr;
    std::byte* const origin_aligned = reinterpret_cast<std::byte*>(
        utils_align(reinterpret_cast<uintptr_t>(origin), ag));
    std::byte*               region = origin_aligned - ag;
    MEMORY_BASIC_INFORMATION mbi;

    for (; region >= minaddr && VirtualQuery(region, &mbi, sizeof(mbi));
         region = static_cast<std::byte*>(mbi.AllocationBase) - ag)
    {
      if (mbi.State != MEM_FREE)
        continue;
      if ((result = static_cast<std::byte*>(
               VirtualAlloc(region, memory_block_size, MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE))))
        return result;
      if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) < ag)
        break;
    }

    region = origin_aligned + ag;
    for (; region <= maxaddr && VirtualQuery(region, &mbi, sizeof(mbi));
         region = reinterpret_cast<std::byte*>(
             utils_align(reinterpret_cast<uintptr_t>(mbi.AllocationBase) +
                             mbi.RegionSize + (ag - 1),
                         ag)))
    {
      if (mbi.State != MEM_FREE)
        continue;
      if ((result = static_cast<std::byte*>(
               VirtualAlloc(region, memory_block_size, MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE))))
        return result;
    }
    throw(exceptions::virtual_alloc_exception(
        GetLastError(), region, memory_block_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
  }
#else
  std::byte* try_valloc()
  {
    if (void* result =
            VirtualAlloc(nullptr, memory_block_size, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE))
      return static_cast<std::byte*>(result);

    throw(exceptions::virtual_alloc_exception(
        GetLastError(), nullptr, memory_block_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
  }
#endif
} // namespace alterhook