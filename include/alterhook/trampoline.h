/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <memory>
#include <string>
#include "tools.h"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4251)
#else
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wdeprecated-copy"
#endif

namespace alterhook
{
  class ALTERHOOK_API trampoline
  {
  public:
    trampoline() noexcept {}

    trampoline(std::byte* target) { init(target); }

    template <__alterhook_is_target(trg)>
    trampoline(trg&& target)
        : trampoline(get_target_address(std::forward<trg>(target)))
    {
    }

    trampoline(const trampoline& other);
    trampoline(trampoline&& other) noexcept;
    trampoline& operator=(const trampoline& other);
    trampoline& operator=(trampoline&& other) noexcept;

    ~trampoline() noexcept {}

    void init(std::byte* target);

    void reset();

    template <typename fn, typename... types>
    auto invoke(types&&... values) const;

    template <__alterhook_is_original(fn)>
    auto get_callback() const;

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

      constexpr deleter(const deleter&) noexcept = default;

      void operator()(std::byte* ptrampoline) const noexcept;
    };

    typedef utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions_t;
    typedef std::pair<bool, uint8_t>                             pc_handling_t;
    typedef std::unique_ptr<std::byte, deleter>                  trampoline_ptr;
    std::byte*     ptarget = nullptr;
    trampoline_ptr ptrampoline{};
#if utils_64bit
    std::byte* prelay = nullptr;
#elif utils_arm
    std::bitset<8> instruction_sets{};
#endif
    bool   patch_above = false;
    size_t tramp_size  = 0;
#if utils_arm
    pc_handling_t pc_handling{};
#endif
#if !utils_windows
    int old_protect = 0;
#endif
    positions_t positions{};
  };

  template <typename fn, typename... types>
  auto trampoline::invoke(types&&... args) const
  {
    utils_assert(
        ptarget,
        "trampoline::invoke: attempt to invoke an uninitialized trampoline");
    __alterhook_def_thumb_var(ptarget);
    std::byte* func = __alterhook_add_thumb_bit(ptrampoline.get());
    return std::invoke(function_cast<fn>(func), std::forward<types>(args)...);
  }

  template <__alterhook_is_original_impl(fn)>
  auto trampoline::get_callback() const
  {
    __alterhook_def_thumb_var(ptarget);
    return function_cast<fn>(__alterhook_add_thumb_bit(ptrampoline.get()));
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#else
  #pragma GCC diagnostic pop
#endif
