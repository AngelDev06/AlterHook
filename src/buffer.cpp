/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "buffer.h"
#include "exceptions.h"

namespace alterhook
{
#if utils_windows
  constexpr size_t memory_block_size = 0x10'00;
  #if utils_windows64
  constexpr size_t max_memory_range = 0x40'00'00'00;
  #endif
#else
  inline const auto memory_block_size = sysconf(_SC_PAGE_SIZE);
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
  static std::byte* find_prev_free_region(std::byte* address,
                                          std::byte* minaddr, DWORD ag)
  {
    MEMORY_BASIC_INFORMATION mbi;
    for (uintptr_t regaddr =
             utils_align(reinterpret_cast<uintptr_t>(address), ag) - ag;
         regaddr >= reinterpret_cast<uintptr_t>(minaddr) &&
         VirtualQuery(reinterpret_cast<void*>(regaddr), &mbi, sizeof(mbi));
         regaddr = reinterpret_cast<uintptr_t>(mbi.AllocationBase) - ag)
    {
      if (mbi.State == MEM_FREE)
        return reinterpret_cast<std::byte*>(regaddr);
      // needed to not underflow
      if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) < ag)
        break;
    }
    return nullptr;
  }

  static std::byte* find_next_free_region(std::byte* address,
                                          std::byte* maxaddr, DWORD ag)
  {
    MEMORY_BASIC_INFORMATION mbi;
    for (uintptr_t regaddr =
             utils_align(reinterpret_cast<uintptr_t>(address), ag) + ag;
         regaddr <= reinterpret_cast<uintptr_t>(maxaddr) &&
         VirtualQuery(reinterpret_cast<void*>(regaddr), &mbi, sizeof(mbi));
         regaddr = utils_align(reinterpret_cast<uintptr_t>(mbi.AllocationBase) +
                                   mbi.RegionSize + (ag - 1),
                               ag))
    {
      if (mbi.State == MEM_FREE)
        return reinterpret_cast<std::byte*>(regaddr);
    }
    return nullptr;
  }

  static std::tuple<std::byte*, std::byte*, DWORD> get_min_max_addr()
  {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return { static_cast<std::byte*>(info.lpMinimumApplicationAddress),
             static_cast<std::byte*>(info.lpMaximumApplicationAddress),
             info.dwAllocationGranularity };
  }
#endif

#if !defined(NDEBUG) && utils_x86
  #define __alterhook_return_pslot                                             \
    {                                                                          \
      auto pslottmp = pblock->get_slot();                                      \
      pslottmp->buffer.fill(std::byte(0xCC));                                  \
      return reinterpret_cast<std::byte*>(pslottmp);                           \
    }
#else
  #define __alterhook_return_pslot                                             \
    return reinterpret_cast<std::byte*>(pblock->get_slot())
#endif

  memory_block* trampoline_buffer::buffer = nullptr;

  std::byte* trampoline_buffer::allocate(__alterhook_alloc_arg)
  {
    std::scoped_lock lock{ buffer_lock };
#if utils_windows64
    static auto [minaddr, maxaddr, ag] = get_min_max_addr();
    if (reinterpret_cast<uintptr_t>(origin) > max_memory_range &&
        minaddr < origin - max_memory_range)
      minaddr = origin - max_memory_range;
    if (maxaddr > origin + max_memory_range)
      maxaddr = origin + max_memory_range;
  #define __alterhook_range_check                                              \
    &&reinterpret_cast<std::byte*>(pblock) >                                   \
        minaddr&& reinterpret_cast<std::byte*>(pblock) < maxaddr
  #define __alterhook_alloc_mem_block()                                        \
    static_cast<memory_block*>(VirtualAlloc(reg, memory_block_size,            \
                                            MEM_COMMIT | MEM_RESERVE,          \
                                            PAGE_EXECUTE_READWRITE))
  #define __alterhook_raise_alloc_exception()                                  \
    throw(exceptions::virtual_alloc_exception(                                 \
        GetLastError(), reg, memory_block_size, MEM_COMMIT | MEM_RESERVE,      \
        PAGE_EXECUTE_READWRITE))
#else
  #define __alterhook_range_check
  #if !utils_windows
    #define __alterhook_alloc_mem_block()                                      \
      static_cast<memory_block*>(mmap(nullptr, memory_block_size,              \
                                      PROT_READ | PROT_WRITE | PROT_EXEC,      \
                                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0))
    #define __alterhook_raise_alloc_exception()                                \
      throw(exceptions::mmap_exception(errno, nullptr, memory_block_size,      \
                                       PROT_READ | PROT_WRITE | PROT_EXEC,     \
                                       MAP_PRIVATE | MAP_ANONYMOUS, 0, 0))
  #else
    #define __alterhook_alloc_mem_block()                                      \
      static_cast<memory_block*>(VirtualAlloc(nullptr, memory_block_size,      \
                                              MEM_COMMIT | MEM_RESERVE,        \
                                              PAGE_EXECUTE_READWRITE))
    #define __alterhook_raise_alloc_exception()                                \
      throw(exceptions::virtual_alloc_exception(                               \
          GetLastError(), nullptr, memory_block_size,                          \
          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
  #endif
#endif

    memory_block* pblock = nullptr;
    for (memory_block* pblocktmp = buffer; pblock __alterhook_range_check;
         pblock                  = pblock->next)
    {
      if (pblocktmp->free)
      {
        pblock = pblocktmp;
        break;
      }
    }
    if (pblock)
      __alterhook_return_pslot;

#if utils_windows64
    std::byte* reg = origin;
    while (reg >= minaddr && (reg = find_prev_free_region(reg, minaddr, ag)) &&
           !(pblock = __alterhook_alloc_mem_block()))
      ;
    if (!pblock)
    {
      reg = origin;
      while (reg <= maxaddr &&
             (reg = find_next_free_region(reg, minaddr, ag)) &&
             !(pblock = __alterhook_alloc_mem_block()))
        ;
    }
#else
    pblock = __alterhook_alloc_mem_block();
#endif

    if (pblock)
    {
      pblock->init();
      __alterhook_return_pslot;
    }

    __alterhook_raise_alloc_exception();
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
