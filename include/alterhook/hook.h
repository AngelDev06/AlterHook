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
    /**
     * @name Constructors with Target, Detour and Original Callback
     * @brief Takes in the target, the detour and the original callback and
     * proceeds to fully initialize the hook instance. It also enables the hook
     * if the additional parameter `enable_hook` is set to true (the default)
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @{
     */

    /**
     * @tparam dtr the callable type of the detour instance (must satisfy
     * @ref alterhook::utils::callable_type)
     * @tparam orig the function-like type of the original callback (must
     * satisfy @ref alterhook::utils::function_type)
     * @param target the target to use
     * @param detour the detour to redirect execution to
     * @param original the reference to the original callback which will be used
     * to pass control back to the original function
     * @param enable_hook an optional flag determining whether the hook should
     * be immediately enabled after construction (defaults to true)
     */
    template <
        typename dtr, typename orig,
        typename = std::enable_if_t<utils::detours_and_originals<dtr, orig&>>>
    hook(std::byte* target, dtr&& detour, orig& original,
         bool enable_hook = true);

    /**
     * @tparam trg the callable type of the target (must satisfy
     * @ref alterhook::utils::callable_type)
     * @tparam dtr the callable type of the detour instance (must satisfy
     * @ref alterhook::utils::callable_type)
     * @tparam orig the function-like type of the original callback (must
     * satisfy @ref alterhook::utils::function_type)
     * @param target the target to use
     * @param detour the detour to redirect execution to
     * @param original the reference to the original callback which will be used
     * to pass control back to the original function
     * @param enable_hook an optional flag determining whether the hook should
     * be immediately enabled after construction (defaults to true)
     */
    template <
        typename trg, typename dtr, typename orig,
        typename = std::enable_if_t<utils::callable_type<trg> &&
                                    utils::detours_and_originals<dtr, orig&>>>
    hook(trg&& target, dtr&& detour, orig& original, bool enable_hook = true);

    /// @}

    /**
     * @name Constructors with Target and Detour
     * @brief Takes in the target and the detour and proceeds to initialize the
     * hook instance. It also enables the hook if the additional parameter
     * `enable_hook` is set to true (the default).
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @{
     */

    /**
     * @tparam dtr the callable type of the detour instance (must satisfy
     * @ref alterhook::utils::callable_type)
     * @param target the target to use
     * @param detour the detour to redirect execution to
     * @param enable_hook an optional flag determining whether the hook should
     * be immediately enabled after construction (defaults to true)
     */
    template <typename dtr,
              typename = std::enable_if_t<utils::callable_type<dtr>>>
    hook(std::byte* target, dtr&& detour, bool enable_hook = true);

    /**
     * @tparam trg the callable type of the target (must satisfy
     * @ref alterhook::utils::callable_type)
     * @tparam dtr the callable type of the detour instance (must satisfy
     * @ref alterhook::utils::callable_type)
     * @param target the target to use
     * @param detour the detour to redirect execution to
     * @param enable_hook an optional flag determining whether the hook should
     * be immediately enabled after construction (defaults to true)
     */
    template <typename trg, typename dtr,
              typename = std::enable_if_t<utils::callable_type<trg> &&
                                          utils::callable_type<dtr>>>
    hook(trg&& target, dtr&& detour, bool enable_hook = true);

    /// @}

    /**
     * @brief Copies the trampoline and all the other properties (except for the
     * state) from `other` to `*this`.
     * @param other the hook to copy from
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     *
     * As mentioned the state isn't copied, which means that regardless of
     * whether `other` is enabled or not, the new hook will stay as disabled.
     */
    hook(const hook& other);
    /**
     * @brief Moves the trampoline and all the other properties from `other` to
     * `*this` leaving `other` uninitialized but reusable.
     * @param other the hook to move from
     *
     * The new hook instance will now be responsible for managing what was
     * previously managed by `other` and `other` can be reused by subsequent
     * calls to @ref alterhook::hook::set_target(std::byte*),
     * @ref alterhook::hook::set_detour etc.
     */
    hook(hook&& other) noexcept;

    /**
     * @brief Constructs a new hook with a copy of the trampoline `tramp`.
     * @param tramp the trampoline to copy from
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     */
    hook(const trampoline& tramp) : trampoline(tramp)
    {
      __alterhook_make_backup();
    }

    /**
     * @brief Constructs a new hook while claiming ownership of the trampoline
     * `tramp`
     * @param tramp the trampoline to move from
     */
    hook(trampoline&& tramp) noexcept : trampoline(std::move(tramp))
    {
      __alterhook_make_backup();
    }

    /// Default constructs a hook and leaves it uninitialized
    hook() noexcept {}

    /// Disables the hook (if enabled) and destructs the trampoline
    ~hook() noexcept;

    /**
     * @brief Disables the current hook and replaces all properties of `*this`
     * with a copy of those of `other`.
     * @param other the hook to copy from
     * @returns a reference to `*this`
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     *
     * The trampoline is copy assigned via a call to
     * @ref alterhook::trampoline::operator=(const trampoline&) which means that
     * if an executable buffer is already allocated it will be reused.
     */
    hook& operator=(const hook& other);
    hook& operator=(hook&& other) noexcept;
    hook& operator=(const trampoline& other);
    hook& operator=(trampoline&& other);

    void enable();
    void disable();

    using trampoline::get_target;

    const std::byte* get_detour() const noexcept { return pdetour; }

    size_t trampoline_size() const noexcept { return size(); }

    size_t trampoline_count() const noexcept { return count(); }

    std::string trampoline_str() const { return str(); }

    bool is_enabled() const noexcept { return enabled; }

    explicit operator bool() const noexcept { return enabled; }

    void set_target(std::byte* target);

    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    void set_target(trg&& target)
    {
      set_target(get_target_address(std::forward<trg>(target)));
    }

    template <typename dtr,
              typename = std::enable_if_t<utils::callable_type<dtr>>>
    void set_detour(dtr&& detour);
    template <typename orig,
              typename = std::enable_if_t<utils::function_type<orig>>>
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

    const std::byte*     pdetour = nullptr;
    bool                 enabled = false;
    backup_t             backup{};
    helpers::orig_buff_t original_buffer{};
    helpers::original*   original_wrap = nullptr;

    void set_detour(std::byte* detour);
    void set_original(const helpers::orig_buff_t& original);
  };

  template <typename dtr, typename orig, typename>
  hook::hook(std::byte* target, dtr&& detour, orig& original, bool enable_hook)
      : trampoline(target),
        pdetour(get_target_address(std::forward<dtr>(detour))),
        original_wrap(std::launder(
            reinterpret_cast<helpers::original*>(&original_buffer)))
  {
    helpers::assert_valid_detour_original_pair<dtr, orig>();
    new (&original_buffer) helpers::original_wrapper(original);
    __alterhook_def_thumb_var(target);
    __alterhook_make_backup();
    original =
        function_cast<orig>(__alterhook_add_thumb_bit(ptrampoline.get()));
    utils_assert(target != pdetour,
                 "hook::hook: detour & target have the same address");
    if (enable_hook)
      enable();
  }

  template <typename dtr, typename>
  hook::hook(std::byte* target, dtr&& detour, bool enable_hook)
      : trampoline(target),
        pdetour(get_target_address(std::forward<dtr>(detour)))
  {
    __alterhook_make_backup();
    utils_assert(target != pdetour,
                 "hook::hook: detour & target have the same address");
    if (enable_hook)
      enable();
  }

  template <typename trg, typename dtr, typename orig, typename>
  hook::hook(trg&& target, dtr&& detour, orig& original, bool enable_hook)
      : hook(get_target_address(std::forward<trg>(target)),
             std::forward<dtr>(detour), original, enable_hook)
  {
    helpers::assert_valid_target_and_detour_pair<trg, dtr>();
  }

  template <typename trg, typename dtr, typename>
  hook::hook(trg&& target, dtr&& detour, bool enable_hook)
      : hook(get_target_address(std::forward<trg>(target)),
             std::forward<dtr>(detour), enable_hook)
  {
    helpers::assert_valid_target_and_detour_pair<trg, dtr>();
  }

  template <typename dtr, typename>
  void hook::set_detour(dtr&& detour)
  {
    set_detour(get_target_address(std::forward<dtr>(detour)));
  }

  template <typename orig, typename>
  void hook::set_original(orig& original)
  {
    if (original_wrap && original_wrap->contains_ref(original))
      return;
    helpers::orig_buff_t origbuff{};
    new (&origbuff) helpers::original_wrapper(original);
    set_original(origbuff);
  }
} // namespace alterhook
