/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "buffer.h"
#include "exceptions.h"

#if !defined(NDEBUG) && (utils_x86 || utils_x64)
  #define __alterhook_return_pslot(block)                                      \
    do                                                                         \
    {                                                                          \
      auto pslottmp = block->get_slot();                                       \
      pslottmp->buffer.fill(std::byte(0xCC));                                  \
      return reinterpret_cast<std::byte*>(pslottmp);                           \
    } while (false)
#else
  #define __alterhook_return_pslot(block)                                      \
    return reinterpret_cast<std::byte*>(block->get_slot())
#endif

#if utils_x64
  #define __alterhook_range_check(block)                                       \
    block&& reinterpret_cast<std::byte*>(block) >                              \
        minaddr&& reinterpret_cast<std::byte*>(block) < maxaddr
#else
  #define __alterhook_range_check(block) block
  #define __alterhook_set_min_max_addr() ((void)0)
  #define __alterhook_try_valloc()       try_valloc()
#endif

#if utils_windows64
  #if utils_cpp20
    #define __alterhook_unpack_static_tuple(...)                               \
      static auto [__VA_ARGS__] = get_min_max_addr()
  #else
    #define __alterhook_unpack_static_tuple(...)                               \
      static auto __tmp_tuple = get_min_max_addr();                            \
      auto [__VA_ARGS__]      = __tmp_tuple
  #endif

  #define __alterhook_set_min_max_addr()                                       \
    __alterhook_unpack_static_tuple(minaddr, maxaddr, ag);                     \
    do                                                                         \
    {                                                                          \
      if (reinterpret_cast<uintptr_t>(origin) > max_memory_range &&            \
          minaddr < origin - max_memory_range)                                 \
        minaddr = origin - max_memory_range;                                   \
      if (maxaddr > origin + max_memory_range)                                 \
        maxaddr = origin + max_memory_range;                                   \
    } while (false)

  #define __alterhook_try_valloc() try_valloc(origin, minaddr, maxaddr, ag)

  #define __alterhook_alloc_mem_block()                                        \
    static_cast<memory_block*>(VirtualAlloc(reg, memory_block_size,            \
                                            MEM_COMMIT | MEM_RESERVE,          \
                                            PAGE_EXECUTE_READWRITE))
  #define __alterhook_raise_alloc_exception()                                  \
    throw(exceptions::virtual_alloc_exception(                                 \
        GetLastError(), reg, memory_block_size, MEM_COMMIT | MEM_RESERVE,      \
        PAGE_EXECUTE_READWRITE))
#elif utils_x64
  #define __alterhook_set_min_max_addr()                                       \
    std::byte *minaddr =                                                       \
                  reinterpret_cast<uintptr_t>(origin) > max_memory_range       \
                      ? reinterpret_cast<std::byte*>(                          \
                            utils_align(reinterpret_cast<uintptr_t>(origin) -  \
                                            max_memory_range,                  \
                                        memory_block_size))                    \
                      : nullptr,                                               \
              *maxaddr = reinterpret_cast<std::byte*>(utils_align(             \
                  reinterpret_cast<uintptr_t>(origin) + max_memory_range,      \
                  memory_block_size));                                         \
    ((void)0)
  #define __alterhook_try_valloc() try_valloc(origin, minaddr, maxaddr)
#endif

namespace alterhook
{
#if utils_windows
  constexpr size_t memory_block_size = 0x10'00;
#else
  inline const auto memory_block_size = sysconf(_SC_PAGE_SIZE);
#endif
#if utils_x64
  constexpr size_t max_memory_range = 0x40'00'00'00;
#endif
  // to enforce thread safety on allocations & deallocations
  static std::mutex buffer_lock;

  void memory_block::init()
  {
    auto pfree = reinterpret_cast<memory_slot*>(this) + 1;
    free       = nullptr;
    used_count = 0;

    do
    {
      pfree->next = free;
      free        = pfree;
      ++pfree;
    } while (reinterpret_cast<uintptr_t>(pfree) -
                 reinterpret_cast<uintptr_t>(this) <=
             memory_block_size - memory_slot_size);

    join();
  }

  void memory_block::join()
  {
    next                      = trampoline_buffer::buffer;
    trampoline_buffer::buffer = this;
  }

  memory_block::memory_slot* memory_block::get_slot()
  {
    memory_slot* pslot = free;
    free               = pslot->next;
    ++used_count;
    return pslot;
  }

  void memory_block::free_slot(memory_slot* pslot)
  {
    utils_assert(is_valid_slot(pslot),
                 "memory_block::free_slot: Memory slot passed is invalid");
    pslot->next = free;
    free        = pslot;
    --used_count;
  }
#ifndef NDEBUG
  bool memory_block::is_valid_slot(memory_slot* pslot)
  {
    ptrdiff_t slot_offset =
        reinterpret_cast<uintptr_t>(pslot) - reinterpret_cast<uintptr_t>(this);
    return slot_offset && !(slot_offset % memory_slot_size) &&
           slot_offset < memory_block_size;
  }
#endif

#if utils_windows64
  static std::byte* try_valloc(std::byte* origin, std::byte* minaddr,
                               std::byte* maxaddr, DWORD ag)
  {
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

  static std::tuple<std::byte*, std::byte*, DWORD> get_min_max_addr()
  {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return { static_cast<std::byte*>(info.lpMinimumApplicationAddress),
             static_cast<std::byte*>(info.lpMaximumApplicationAddress),
             info.dwAllocationGranularity };
  }
#elif utils_x64
  static std::byte* try_valloc(std::byte* origin, std::byte* minaddr,
                               std::byte* maxaddr)
  {
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
#elif utils_windows
  static std::byte* try_valloc()
  {
    if (void* result =
            VirtualAlloc(nullptr, memory_block_size, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE))
      return static_cast<std::byte*>(result);

    throw(exceptions::virtual_alloc_exception(
        GetLastError(), nullptr, memory_block_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
  }
#else
  static std::byte* try_valloc()
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

  memory_block* trampoline_buffer::buffer = nullptr;

  std::byte* trampoline_buffer::allocate(__alterhook_alloc_arg)
  {
    std::scoped_lock lock{ buffer_lock };
    __alterhook_set_min_max_addr();

    memory_block* pblock = nullptr;
    for (memory_block* itr = buffer; __alterhook_range_check(itr);
         itr               = itr->next)
    {
      if (itr->free)
      {
        pblock = itr;
        break;
      }
    }

    if (!pblock)
    {
      pblock = reinterpret_cast<memory_block*>(__alterhook_try_valloc());
      pblock->init();
    }

    __alterhook_return_pslot(pblock);
  }

  void trampoline_buffer::deallocate(void* src) noexcept
  {
    if (!src)
      return;
    std::scoped_lock lock{ buffer_lock };

    for (memory_block *target = reinterpret_cast<memory_block*>(utils_align(
                          reinterpret_cast<uintptr_t>(src), memory_block_size)),
                      *prev = nullptr, *pblock = buffer;
         pblock; prev = pblock, pblock = pblock->next)
    {
      if (pblock == target)
      {
        auto pslot = static_cast<memory_block::memory_slot*>(src);
        utils_assert(
            pblock->is_valid_slot(pslot),
            "trampoline_buffer::deallocate: Memory slot passed is invalid");
#ifndef NDEBUG
        pslot->buffer.fill(std::byte());
#endif
        pblock->free_slot(pslot);

        if (!pblock->used_count)
        {
          if (prev)
            prev->next = pblock->next;
          else
            buffer = pblock->next;

// no error checking is performed to keep this function noexcept
#if utils_windows
          VirtualFree(pblock, 0, MEM_RELEASE);
#else
          munmap(pblock, memory_block_size);
#endif
        }
        break;
      }
    }
  }
} // namespace alterhook
