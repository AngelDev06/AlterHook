/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "thread_handler.h"
#pragma GCC visibility push(hidden)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

namespace alterhook
{
  extern std::shared_mutex hook_lock;

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

  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        injector_flags flags);

#if utils_x86 || !always_use_relay
  void patch_jmp(std::byte* target, const std::byte* detour,
                 patcher_flags flags);
#endif

#if !utils_x86
  void set_relay(std::byte* prelay, const std::byte* detour);
#endif

  struct injectors
  {
  private:
    template <typename T, typename obj>
    static T make_flags_impl(obj&& instance) noexcept
    {
      static_assert(std::is_same_v<T, injector_flags> ||
                    std::is_same_v<T, patcher_flags>);
      T flags{ instance.patch_above };

#if !utils_x86 && !always_use_relay
      flags.use_small_jmp = instance.prelay;
#endif
#if !utils_windows
      flags.old_protect = instance.old_protect;
#endif
      return flags;
    }

  public:
    template <typename obj>
    static injector_flags make_injector_flags(obj&& instance,
                                              bool  enable) noexcept
    {
      auto flags   = make_flags_impl<injector_flags>(instance);
      flags.enable = enable;
      return flags;
    }

    template <typename obj>
    static patcher_flags make_patcher_flags(obj&& instance) noexcept
    {
      return make_flags_impl<patcher_flags>(instance);
    }

    template <typename obj>
    static void inject(obj&& instance, const std::byte* backup_or_detour,
                       bool enable)
    {
#if !utils_x86
      if (enable && instance.prelay)
      {
        set_relay(instance.prelay, backup_or_detour);
        inject_to_target(instance.ptarget, instance.prelay,
                         make_injector_flags(instance, enable));
        return;
      }
#endif

      inject_to_target(instance.ptarget, backup_or_detour,
                       make_injector_flags(instance, enable));
    }

    template <typename obj>
    static void patch(obj&& instance, const std::byte* detour)
    {
#if !utils_x86
  #if !always_use_relay
      if (instance.prelay)
  #endif
      {
        set_relay(instance.prelay, detour);
        return;
      }
#endif

#if utils_x86 || !always_use_relay
      patch_jmp(instance.ptarget, detour, make_patcher_flags(instance));
#endif
    }
  };

#define __inject3(other, backup_or_detour, enable)                             \
  ::alterhook::injectors::inject(other, backup_or_detour, enable)
#define __inject2(backup_or_detour, enable)                                    \
  ::alterhook::injectors::inject(*this, backup_or_detour, enable)
#define inject(...)                                                            \
  utils_if(utils_equal(utils_sizeof(__VA_ARGS__), 3))(__inject3,               \
                                                      __inject2)(__VA_ARGS__)

#define __patch2(other, detour) ::alterhook::injectors::patch(other, detour)
#define __patch1(detour)        ::alterhook::injectors::patch(*this, detour)
#define patch(...)                                                             \
  utils_if(utils_equal(utils_sizeof(__VA_ARGS__), 2))(__patch2,                \
                                                      __patch1)(__VA_ARGS__)
} // namespace alterhook

#pragma GCC diagnostic pop
#pragma GCC visibility pop
