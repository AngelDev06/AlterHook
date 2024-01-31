/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#pragma GCC visibility push(hidden)

namespace alterhook
{
#if utils_64bit || utils_arm
  constexpr size_t memory_slot_size = 64;
#else
  constexpr size_t memory_slot_size = 32;
#endif

#if allocate_nearby
  #define __origin(...) __VA_ARGS__
  #if utils_arm
  constexpr size_t max_memory_range = 33'554'428;
  #elif utils_aarch64
  constexpr size_t max_memory_range = 134'217'728;
  #else
  constexpr size_t max_memory_range = 0x40'00'00'00;
  #endif
#else
  #define __origin(...)
#endif

  struct memory_block
  {
    memory_block* next;
    size_t        used_count;

    union memory_slot
    {
      memory_slot*                            next;
      std::array<std::byte, memory_slot_size> buffer;
    }* free;

    void          init();
    void          join();
    memory_slot*  get_slot();
    void          free_slot(memory_slot* pslot);
    memory_block* find(__origin(std::byte* origin)) noexcept;
#ifndef NDEBUG
    bool is_valid_slot(memory_slot* pslot);
#endif
  };

  // the allocator for trampolines
  class trampoline_buffer
  {
  private:
    friend struct memory_block;
    static memory_block* buffer;

  public:
    static std::byte* allocate(__origin(std::byte* origin));
    static void       deallocate(void* src) noexcept;
  };
} // namespace alterhook

#pragma GCC visibility pop
