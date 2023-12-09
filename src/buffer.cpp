/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "buffer.h"
#include "exceptions.h"

namespace alterhook
{
#if utils_windows
  constexpr size_t memory_block_size = 0x10'00;

  #define vdealloc(block) VirtualFree(block, 0, MEM_RELEASE)
#else
  extern const long memory_block_size;

  #define vdealloc(block) munmap(block, memory_block_size)
#endif

#if utils_64bit
  std::pair<std::byte*, std::byte*>
             get_minmax_address(std::byte* origin) noexcept;
  std::byte* try_valloc(std::byte* origin);

  #define __define_minmax_addresses(origin)                                    \
    auto [minaddr, maxaddr] = get_minmax_address(origin)
  #define __range_check(block)                                                 \
    block&& reinterpret_cast<std::byte*>(block) >                              \
        minaddr&& reinterpret_cast<std::byte*>(block) < maxaddr
  #define valloc(origin)   try_valloc(origin)
#else
  std::byte* try_valloc();

  #define __define_minmax_addresses(origin) ((void)0)
  #define __range_check(block)              block
  #define valloc(origin)                    try_valloc()
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
#if !defined(NDEBUG) && (utils_x86 || utils_x64)
    pslot->buffer.fill(std::byte(0xCC));
#endif
    return pslot;
  }

  void memory_block::free_slot(memory_slot* pslot)
  {
    utils_assert(is_valid_slot(pslot),
                 "memory_block::free_slot: Memory slot passed is invalid");
#ifndef NDEBUG
    pslot->buffer.fill(std::byte());
#endif
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

  memory_block* trampoline_buffer::buffer = nullptr;

  std::byte* trampoline_buffer::allocate(__origin_address)
  {
    std::scoped_lock lock{ buffer_lock };
    __define_minmax_addresses(origin);

    memory_block* pblock = nullptr;
    for (memory_block* itr = buffer; __range_check(itr); itr = itr->next)
    {
      if (itr->free)
      {
        pblock = itr;
        break;
      }
    }

    if (!pblock)
    {
      pblock = reinterpret_cast<memory_block*>(valloc(origin));
      pblock->init();
    }

    return reinterpret_cast<std::byte*>(pblock->get_slot());
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
        pblock->free_slot(pslot);

        if (!pblock->used_count)
        {
          if (prev)
            prev->next = pblock->next;
          else
            buffer = pblock->next;

          // no error checking is performed to keep this function noexcept
          vdealloc(pblock);
        }
        break;
      }
    }
  }
} // namespace alterhook
