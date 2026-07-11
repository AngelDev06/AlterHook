/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook::detail
{
  struct injector_flags;
  struct patcher_flags;

  // This is a mixin that provides the common preparation process that all hook
  // containers need and it also does the actual calls to the low level private
  // api that does the injection. It is not meant to be publicly accessible and
  // therefore no definitions provided for this header file. The specific
  // template instantiations and definitions needed are in a cpp file.
  template <typename derived>
  class injectable
  {
  public:
    injector_flags make_injector_flags(bool enable) const noexcept;

    patcher_flags make_patcher_flags() const noexcept;

    void inject(const std::byte* backup_or_detour, bool enable) const;

    void patch(const std::byte* detour) const;

  private:
    template <typename T>
    T make_general_flags() const noexcept;
  };
} // namespace alterhook::detail
