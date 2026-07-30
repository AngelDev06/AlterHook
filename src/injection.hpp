/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "tools.hpp"
#include <sys/mman.h>
#pragma GCC visibility push(hidden)

namespace alterhook
{
  inline std::shared_mutex global_inject_lock{};

#if utils_windows
  #define __define_old_protect(flags) DWORD old_protect = 0
  #define __prot_data(address, size)  std::pair(address, size)
  #define execset(address, size)                                               \
    VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old_protect)
  #define execunset(address, size)                                             \
    VirtualProtect(address, size, old_protect, &old_protect)
  #define execthrow(address, size)                                             \
    nested_throw(exceptions::virtual_protect_exception(                        \
        GetLastError(), address, size, PAGE_EXECUTE_READWRITE,                 \
        reinterpret_cast<uintptr_t>(&old_protect)))
  #define execflush(address, size)                                             \
    FlushInstructionCache(GetCurrentProcess(), address, size)
#else
  extern const size_t memory_block_size;

  #define __define_old_protect(flags)                                          \
    int old_protect = to_linux_prot(flags.old_protect)

  inline std::pair<std::byte*, size_t> __prot_data(std::byte* address,
                                                   size_t     size) noexcept
  {
    std::byte* const prot_addr = utils::align(address, memory_block_size);
    const size_t     prot_size =
        utils::align_up((address - prot_addr) + size, memory_block_size);
    return { prot_addr, prot_size };
  }

  inline bool execset(std::byte* address, size_t size) noexcept
  {
    constexpr int execprot = PROT_READ | PROT_WRITE | PROT_EXEC;
    return mprotect(address, size, execprot) != -1;
  }

  inline int to_linux_prot(protection_info protinfo) noexcept
  {
    int result = PROT_NONE;

    if (protinfo.read)
      result |= PROT_READ;
    if (protinfo.write)
      result |= PROT_WRITE;
    if (protinfo.execute)
      result |= PROT_EXEC;

    return result;
  }

  #define execunset(address, size) mprotect(address, size, old_protect)
  #define execthrow(address, size)                                             \
    nested_throw(exceptions::mprotect_exception(                               \
        errno, address, size, PROT_READ | PROT_WRITE | PROT_EXEC))
  #define execflush(address, size)                                             \
    __builtin___clear_cache(reinterpret_cast<char*>(address),                  \
                            reinterpret_cast<char*>(address + size))
#endif

  namespace detail
  {
    struct injector_flags
    {
      bool patch_above : 1;
      bool enable      : 1;
#if !utils_x86 && !always_use_relay
      bool use_small_jmp : 1;
#endif
#if !utils_windows
      protection_info old_protect;
#endif
    };

    struct patcher_flags
    {
      bool patch_above : 1;
#if !utils_x86 && !always_use_relay
      bool use_small_jmp : 1;
#endif
#if !utils_windows
      protection_info old_protect;
#endif
    };
  } // namespace detail

  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        detail::injector_flags flags);

#if utils_x86 || !always_use_relay
  void patch_jmp(std::byte* target, const std::byte* detour,
                 detail::patcher_flags flags);
#endif

#if !utils_x86
  void set_relay(std::byte* prelay, const std::byte* detour);
#endif
} // namespace alterhook

#pragma GCC visibility pop
