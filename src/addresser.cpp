/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "addresser.h"

// Addresser inspiration from:
// https://gist.github.com/altalk23/29b97969e9f0624f783b673f6c1cd279
namespace alterhook
{
#define __alterhook_noseperator()
#define __alterhook_comma_seperator() ,

// clang-format off
#define __alterhook_for_hex_digit0(FN, PREFIX, SEPERATOR) \
  FN(PREFIX##0)SEPERATOR()                                \
  FN(PREFIX##1)SEPERATOR()                                \
  FN(PREFIX##2)SEPERATOR()                                \
  FN(PREFIX##3)SEPERATOR()                                \
  FN(PREFIX##4)SEPERATOR()                                \
  FN(PREFIX##5)SEPERATOR()                                \
  FN(PREFIX##6)SEPERATOR()                                \
  FN(PREFIX##7)SEPERATOR()                                \
  FN(PREFIX##8)SEPERATOR()                                \
  FN(PREFIX##9)SEPERATOR()                                \
  FN(PREFIX##A)SEPERATOR()                                \
  FN(PREFIX##B)SEPERATOR()                                \
  FN(PREFIX##C)SEPERATOR()                                \
  FN(PREFIX##D)SEPERATOR()                                \
  FN(PREFIX##E)SEPERATOR()                                \
  FN(PREFIX##F)

#define __alterhook_for_hex_digit(FN, SEPERATOR) \
  __alterhook_for_hex_digit0(                    \
      FN, 0x0, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x1, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x2, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x3, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x4, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x5, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x6, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x7, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x8, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0x9, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0xA, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0xB, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0xC, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0xD, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0xE, SEPERATOR)SEPERATOR()             \
  __alterhook_for_hex_digit0(                    \
      FN, 0xF, SEPERATOR)
  // clang-format on

#define __alterhook_vtable_element(hex)                                        \
  reinterpret_cast<intptr_t>(&index_func<hex * sizeof(intptr_t)>)
#define __alterhook_instance_vpointer(hex)                                     \
  reinterpret_cast<intptr_t>(&custom_vtable)
#define __alterhook_virtual_function_def(hex)                                  \
  virtual void vfunction##hex() {}
#define __alterhook_function_array_element(hex)                                \
  &virtual_function_array::vfunction##hex

#define __alterhook_custom_vtable_set()                                        \
  {                                                                            \
    __alterhook_for_hex_digit(__alterhook_vtable_element,                      \
                              __alterhook_comma_seperator)                     \
  }
#define __alterhook_vpointer_array_set()                                       \
  {                                                                            \
    __alterhook_for_hex_digit(__alterhook_instance_vpointer,                   \
                              __alterhook_comma_seperator)                     \
  }
#define __alterhook_generate_virtual_functions()                               \
  __alterhook_for_hex_digit(__alterhook_virtual_function_def,                  \
                            __alterhook_noseperator)
#define __alterhook_virtual_function_array_set()                               \
  {                                                                            \
    __alterhook_for_hex_digit(__alterhook_function_array_element,              \
                              __alterhook_comma_seperator)                     \
  }

  template <ptrdiff_t index>
  static ptrdiff_t index_func()
  {
    return index;
  }

  constexpr size_t table_size = 0x100;
  typedef intptr_t table_t[table_size];
  static table_t   custom_vtable  = __alterhook_custom_vtable_set();
  static table_t   vpointer_array = __alterhook_vpointer_array_set();

#if utils_gcc
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wctor-dtor-privacy"
#endif

  // clang-format off

  class virtual_function_array
  {
  private:
    __alterhook_generate_virtual_functions() 
  public: 
    typedef void (virtual_function_array::*vmethod_t)();
    typedef vmethod_t vtable_t[table_size];

    static vtable_t array;
  };

  // clang-format on

#if utils_gcc
  #pragma GCC diagnostic pop
#endif

  virtual_function_array::vtable_t virtual_function_array::array =
      __alterhook_virtual_function_array_set();

  addresser::multiple_inheritance* addresser::instance() noexcept
  {
    return reinterpret_cast<addresser::multiple_inheritance*>(&vpointer_array);
  }

#if utils_windows
  uintptr_t addresser::follow_thunk_function(uintptr_t address) noexcept
  {
    uintptr_t result = address;
    if (*reinterpret_cast<std::byte*>(address) == std::byte(0xFF) &&
        *reinterpret_cast<std::byte*>(address + 1) == std::byte(0x25))
    {
      result = *reinterpret_cast<uintptr_t*>(address + 2);
      if (!result)
        return address;
      result = *reinterpret_cast<uintptr_t*>(address);
    }
    return result;
  }

  #ifndef NDEBUG
  uintptr_t addresser::follow_msvc_debug_jmp(uintptr_t address) noexcept
  {
    intptr_t result = address;
    if (*reinterpret_cast<std::byte*>(address) == std::byte(0xE9))
      result += *reinterpret_cast<int32_t*>(address + 1) + 5;
    return result;
  }
  #endif

  bool addresser::is_virtual_msvc_impl(void* address) noexcept
  {
    constexpr std::byte ecx = std::byte(1);
    uint8_t             reg = (std::numeric_limits<uint8_t>::max)();
    uintptr_t           ip  = *reinterpret_cast<uintptr_t*>(address);

    const auto update_ip = [&](intptr_t offset)
    {
      intptr_t current  = ip;
      current          += offset;
      ip                = current;
    };
    enum class instr_opcodes : uint8_t
    {
      MOV        = 0x8B,
      JMP_ABS    = 0xFF,
      JMP_SHORT  = 0xEB,
      JMP        = 0xE9,
      X64_PREFIX = 0x48
    };

    while (true)
    {
      switch (*reinterpret_cast<instr_opcodes*>(ip))
      {
      case instr_opcodes::MOV:
        // if ecx is already loaded or if the register from which mov loads
        // isn't ecx (determined from modr/m byte) we exit here
        if (reg != (std::numeric_limits<uint8_t>::max)() ||
            (*reinterpret_cast<std::byte*>(ip + 1) & std::byte(0b111)) != ecx)
          return false;

        // gets the register that will hold ecx
        reg  = (*reinterpret_cast<uint8_t*>(ip + 1) >> 3) & 0b111;
        ip  += sizeof(uint16_t);
        break;
      case instr_opcodes::JMP_ABS:
      {
        const std::byte modrm = *reinterpret_cast<std::byte*>(ip + 1);

        // check if it uses the register specified in mov instruction or if this
        // is the type of instruction we need
        if (((modrm >> 3) & std::byte(0b111)) != std::byte(4) ||
            (modrm & std::byte(0b111)) != std::byte(reg) ||
            (modrm >> 6) == std::byte(3))
          return false;
        return true;
      }
      case instr_opcodes::JMP_SHORT:
        update_ip(static_cast<intptr_t>(*reinterpret_cast<int8_t*>(ip + 1)) +
                  sizeof(uint16_t));
        continue;
      case instr_opcodes::JMP:
        update_ip(*reinterpret_cast<int32_t*>(ip + 1) + 5);
        continue;
      case instr_opcodes::X64_PREFIX: ++ip; continue;
      default: return false;
      }
    }
  }
#else
  bool addresser::is_virtual_impl(void* address) noexcept
  {
    auto memfunc =
        *reinterpret_cast<virtual_function_array::vmethod_t*>(address);
    for (auto element : virtual_function_array::array)
    {
      if (element == memfunc)
        return true;
    }
    return false;
  }
#endif
} // namespace alterhook
