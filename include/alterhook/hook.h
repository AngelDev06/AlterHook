/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <array>
#include "detail/constants.h"
#include "trampoline.h"

namespace alterhook
{
  class ALTERHOOK_API hook : trampoline
  {
  public:
    template <__alterhook_is_detour_and_original(dtr, orig)>
    hook(std::byte* target, dtr&& detour, orig& original,
         bool enable_hook = true);

    template <__alterhook_is_detour(dtr)>
    hook(std::byte* target, dtr&& detour, bool enable_hook = true);

    template <__alterhook_is_target_detour_and_original(trg, dtr, orig)>
    hook(trg&& target, dtr&& detour, orig& original, bool enable_hook = true);

    template <__alterhook_is_target_and_detour(trg, dtr)>
    hook(trg&& target, dtr&& detour, bool enable_hook = true);

    hook(const hook& other);
    hook(hook&& other) noexcept;

    hook(const trampoline& tramp) : trampoline(tramp)
    {
      __alterhook_make_backup();
    }

    hook(trampoline&& tramp) noexcept : trampoline(std::move(tramp))
    {
      __alterhook_make_backup();
    }

    hook() noexcept {}

    ~hook() noexcept;

    hook& operator=(const hook& other);
    hook& operator=(hook&& other) noexcept;
    hook& operator=(const trampoline& other);
    hook& operator=(trampoline&& other);

    void enable();
    void disable();

    using trampoline::get_target;

    const std::byte* get_detour() const noexcept
    {
      return __alterhook_get_dtr();
    }

    size_t trampoline_size() const noexcept { return size(); }

    size_t trampoline_count() const noexcept { return count(); }

    std::string trampoline_str() const { return str(); }

    bool is_enabled() const noexcept { return enabled; }

    explicit operator bool() const noexcept { return enabled; }

    void set_target(std::byte* target);

    template <__alterhook_is_target(trg)>
    void set_target(trg&& target)
    {
      set_target(get_target_address(std::forward<trg>(target)));
    }

    template <__alterhook_is_detour(dtr)>
    void set_detour(dtr&& detour);
    template <__alterhook_is_original(orig)>
    void set_original(orig& original);
    void reset_original();

    bool operator==(const hook& other) const noexcept;
    bool operator!=(const hook& other) const noexcept;

  private:
    friend class hook_chain;
#ifdef __alterhook_expose_impl
    friend struct injectors;
#endif

    typedef std::array<std::byte, detail::constants::backup_size> backup_t;

#if !utils_64bit
    const std::byte* pdetour = nullptr;
#endif
    bool                 enabled = false;
    backup_t             backup{};
    helpers::orig_buff_t original_buffer{};
    helpers::original*   original_wrap = nullptr;

    void set_detour(std::byte* detour);
    void set_original(const helpers::orig_buff_t& original);
  };

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  hook::hook(std::byte* target, dtr&& detour, orig& original, bool enable_hook)
      : trampoline(target)
  {
    helpers::assert_valid_detour_original_pair<dtr, orig>();
    __alterhook_def_thumb_var(target);
    new (&original_buffer) helpers::original_wrapper(original);
    original_wrap =
        std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
    __alterhook_make_backup();
    __alterhook_set_dtr(get_target_address(std::forward<dtr>(detour)));
    original =
        function_cast<orig>(__alterhook_add_thumb_bit(ptrampoline.get()));
    utils_assert(target != __alterhook_get_dtr(),
                 "hook::hook: detour & target have the same address");
    if (enable_hook)
      enable();
  }

  template <__alterhook_is_detour_impl(dtr)>
  hook::hook(std::byte* target, dtr&& detour, bool enable_hook)
      : trampoline(target)
  {
    __alterhook_make_backup();
    __alterhook_set_dtr(get_target_address(std::forward<dtr>(detour)));
    utils_assert(target != __alterhook_get_dtr(),
                 "hook::hook: detour & target have the same address");
    if (enable_hook)
      enable();
  }

  template <__alterhook_is_target_detour_and_original_impl(trg, dtr, orig)>
  hook::hook(trg&& target, dtr&& detour, orig& original, bool enable_hook)
      : hook(get_target_address(std::forward<trg>(target)),
             std::forward<dtr>(detour), original, enable_hook)
  {
    helpers::assert_valid_target_and_detour_pair<trg, dtr>();
  }

  template <__alterhook_is_target_and_detour_impl(trg, dtr)>
  hook::hook(trg&& target, dtr&& detour, bool enable_hook)
      : hook(get_target_address(std::forward<trg>(target)),
             std::forward<dtr>(detour), enable_hook)
  {
    helpers::assert_valid_target_and_detour_pair<trg, dtr>();
  }

  template <__alterhook_is_detour_impl(dtr)>
  void hook::set_detour(dtr&& detour)
  {
    set_detour(get_target_address(std::forward<dtr>(detour)));
  }

  template <__alterhook_is_original_impl(orig)>
  void hook::set_original(orig& original)
  {
    if (original_wrap && original_wrap->contains_ref(original))
      return;
    helpers::orig_buff_t origbuff{};
    new (&origbuff) helpers::original_wrapper(original);
    set_original(origbuff);
  }
} // namespace alterhook
