/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "buffer.h"
#include "exceptions.h"
#pragma GCC visibility push(hidden)

namespace alterhook
{
#if utils_windows
  constexpr size_t memory_block_size = 0x10'00;

  static void vdealloc(memory_block* block) noexcept
  {
    VirtualFree(block, 0, MEM_RELEASE);
  }
#else
  extern const size_t memory_block_size;

  static void vdealloc(memory_block* block) noexcept
  {
    munmap(block, memory_block_size);
  }
#endif

#if allocate_nearby
  std::pair<const std::byte*, const std::byte*>
                get_minmax_address(std::byte* origin) noexcept;
  memory_block* try_valloc(std::byte* origin);
#else
  memory_block* try_valloc();
#endif

  memory_block* memory_block::find(__origin(std::byte* origin)) noexcept
  {
    memory_block* pblock = nullptr;
#if allocate_nearby
    const auto limits   = get_minmax_address(origin);
    const auto in_range = [=](const memory_block* const itr)
    {
      return utils::in_between(
          limits.first, reinterpret_cast<const std::byte*>(itr), limits.second);
    };
#endif
#if utils_x64
    const auto is_valid_block = [&](const memory_block* const itr) -> bool
    { return itr && in_range(itr); };
#else
    const auto is_valid_block = [](const memory_block* const itr) -> bool
    { return itr; };
#endif

    for (memory_block* itr = this; is_valid_block(itr); itr = itr->next)
    {
      if (!itr->free)
        continue;
      pblock = itr;
#if !utils_x64 && allocate_nearby
      if (in_range(itr))
#endif
        break;
    }
    return pblock;
  }

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
    return slot_offset > 0 && !(slot_offset % memory_slot_size) &&
           static_cast<size_t>(slot_offset) < memory_block_size;
  }
#endif

  memory_block* trampoline_buffer::buffer = nullptr;

  std::byte* trampoline_buffer::allocate(__origin(std::byte* origin))
  {
    std::scoped_lock lock{ buffer_lock };

    memory_block* pblock = buffer ? buffer->find(__origin(origin)) : nullptr;
    if (!pblock)
    {
      pblock = try_valloc(__origin(origin));
      pblock->init();
    }

    return reinterpret_cast<std::byte*>(pblock->get_slot());
  }

  void trampoline_buffer::deallocate(void* src) noexcept
  {
    if (!src)
      return;
    std::scoped_lock lock{ buffer_lock };

    for (memory_block *target = utils::align(static_cast<memory_block*>(src),
                                             memory_block_size),
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

#pragma GCC visibility pop
