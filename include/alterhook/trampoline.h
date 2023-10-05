#pragma once
#include <memory>
#include <string>
#include "tools.h"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4251)
#endif

namespace alterhook
{
  class ALTERHOOK_API trampoline
  {
  public:
    trampoline() noexcept {}

    trampoline(std::byte* target) { init(target); }

    trampoline(const trampoline& other);
    trampoline(trampoline&& other) noexcept;
    trampoline& operator=(const trampoline& other);
    trampoline& operator=(trampoline&& other) noexcept;

    ~trampoline() noexcept {}

    void init(std::byte* target);

    template <typename fn, typename... types>
    auto invoke(types&&... values) const;

    std::byte* get_target() const noexcept { return ptarget; }

    size_t size() const noexcept { return tramp_size; }

    size_t count() const noexcept { return positions.size(); }

    std::string str() const;

  protected:
#ifdef __alterhook_expose_impl
  #if utils_windows
    friend void process_frozen_threads(const trampoline& tramp,
                                       bool enable_hook, HANDLE thread_handle);
  #elif utils_arm
    friend void process_frozen_threads(const trampoline& tramp,
                                       bool enable_hook, unsigned long& pc);
  #else
    friend void process_frozen_threads(const trampoline& tramp,
                                       bool enable_hook, greg_t& ip);
  #endif
#endif
    struct ALTERHOOK_API deleter
    {
      constexpr deleter() noexcept = default;

      constexpr deleter(const deleter&) noexcept {}

      void operator()(std::byte* ptrampoline) const noexcept;
    };

    typedef std::unique_ptr<std::byte, deleter> trampoline_ptr;
    std::byte*                                  ptarget = nullptr;
    trampoline_ptr                              ptrampoline{};
#if utils_x64
    std::byte* prelay = nullptr;
#elif utils_arm
    std::bitset<8> instruction_sets{};
#endif
    bool   patch_above = false;
    size_t tramp_size  = 0;
#if utils_arm
    std::pair<bool, uint8_t> pc_handling{};
#endif
#if !utils_windows
    int old_protect = 0;
#endif
    utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions{};
  };

  template <typename fn, typename... types>
  auto trampoline::invoke(types&&... args) const
  {
    utils_assert(
        ptrampoline,
        "trampoline::invoke: attempt to invoke an uninitialized trampoline");
    __alterhook_def_thumb_var(ptarget);
    std::byte* func = __alterhook_add_thumb_bit(ptrampoline.get());
    return std::invoke(function_cast<fn>(func), std::forward<types>(args)...);
  }

#if utils_arm
  inline constexpr size_t __patch_above_backup_size   = sizeof(uint64_t);
  inline constexpr size_t __patch_above_target_offset = sizeof(uint32_t);
  inline constexpr size_t __backup_size               = sizeof(uint64_t);
#else
  inline constexpr size_t __patch_above_backup_size   = 7;
  inline constexpr size_t __patch_above_target_offset = 5;
  inline constexpr size_t __backup_size               = 5;
#endif
}

#if utils_msvc
  #pragma warning(pop)
#endif
