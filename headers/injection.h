/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if !utils_windows
  #include "linux_thread_handler.h"
#else
  #include "windows_thread_handler.h"
#endif

namespace alterhook
{
  extern std::shared_mutex hook_lock;

#if utils_windows
  #define __int_old_protect
  #define __old_protect_from(other)
  #define __define_old_protect()     DWORD old_protect = 0
  #define __prot_data(address, size) std::pair(address, size)
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
  extern const long memory_block_size;

  #define __int_old_protect         , int old_protect
  #define __old_protect_from(other) , other.old_protect
  #define __define_old_protect()    ((void)0)

  ALTERHOOK_HIDDEN inline std::pair<std::byte*, size_t>
      __prot_data(std::byte* address, size_t size) noexcept
  {
    std::byte* const prot_addr = reinterpret_cast<std::byte*>(
        utils_align(reinterpret_cast<uintptr_t>(address), memory_block_size));
    const size_t prot_size =
        utils_align((address - prot_addr) + size + (memory_block_size - 1),
                    memory_block_size);
    return { prot_addr, prot_size };
  }

  ALTERHOOK_HIDDEN inline bool execset(std::byte* address, size_t size) noexcept
  {
    constexpr int execprot = PROT_READ | PROT_WRITE | PROT_EXEC;
    return mprotect(address, size, execprot) != -1;
  }

  #define execunset(address, size) mprotect(address, size, old_protect)
  #define execthrow(address, size)                                             \
    nested_throw(exceptions::mprotect_exception(                               \
        errno, address, size, PROT_READ | PROT_WRITE | PROT_EXEC))
  #define execflush(address, size)                                             \
    __builtin___clear_cache(reinterpret_cast<char*>(address),                  \
                            reinterpret_cast<char*>(address + size))
#endif

  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        bool patch_above, bool enable __int_old_protect);
#if !utils_x64
  void patch_jmp(std::byte* target, const std::byte* detour,
                 bool patch_above __int_old_protect);
#endif

  struct injectors
  {
    template <typename obj>
    ALTERHOOK_HIDDEN static void
        inject(obj&& instance, const std::byte* backup_or_detour, bool enable)
    {
#if utils_x64
      if (enable)
      {
        *reinterpret_cast<uint64_t*>(instance.prelay + 6) =
            reinterpret_cast<uintptr_t>(backup_or_detour);
        inject_to_target(instance.ptarget, instance.prelay,
                         instance.patch_above,
                         true __old_protect_from(instance));
        return;
      }
#endif
      inject_to_target(instance.ptarget, backup_or_detour, instance.patch_above,
                       enable __old_protect_from(instance));
    }

    template <typename obj>
    ALTERHOOK_HIDDEN static void patch(obj&& instance, const std::byte* detour)
    {
#if utils_x64
      *reinterpret_cast<uint64_t*>(instance.prelay + 6) =
          reinterpret_cast<uintptr_t>(detour);
#else
      patch_jmp(instance.ptarget, detour,
                instance.patch_above __old_protect_from(instance));
#endif
    }
  };

#define __inject3(other, backup_or_detour, enable)                             \
  ::alterhook::injectors::inject(other, backup_or_detour, enable)
#define __inject2(backup_or_detour, enable)                                    \
  ::alterhook::injectors::inject(*this, backup_or_detour, enable)
#define inject(...)                                                            \
  __utils_call(utils_concat(__inject, utils_sizeof(__VA_ARGS__)), (__VA_ARGS__))

#define __patch2(other, detour) ::alterhook::injectors::patch(other, detour)
#define __patch1(detour)        ::alterhook::injectors::patch(*this, detour)
#define patch(...)                                                             \
  __utils_call(utils_concat(__patch, utils_sizeof(__VA_ARGS__)), (__VA_ARGS__))
} // namespace alterhook
