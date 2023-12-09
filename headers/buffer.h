/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
#if utils_64bit || utils_arm
  constexpr size_t memory_slot_size = 64;
#else
  constexpr size_t memory_slot_size = 32;
#endif

#if utils_64bit
  #define __origin_address std::byte* origin
  constexpr size_t max_memory_range = 0x40'00'00'00;
#else
  #define __origin_address
#endif

  struct ALTERHOOK_HIDDEN memory_block
  {
    memory_block* next;
    size_t        used_count;

    union memory_slot
    {
      memory_slot*                            next;
      std::array<std::byte, memory_slot_size> buffer;
    }* free;

    void         init();
    void         join();
    memory_slot* get_slot();
    void         free_slot(memory_slot* pslot);
#ifndef NDEBUG
    bool is_valid_slot(memory_slot* pslot);
#endif
  };

  // the allocator for trampolines
  class ALTERHOOK_HIDDEN trampoline_buffer
  {
  private:
    friend struct memory_block;
    static memory_block* buffer;

  public:
    static std::byte* allocate(__origin_address);
    static void       deallocate(void* src) noexcept;
  };
} // namespace alterhook
