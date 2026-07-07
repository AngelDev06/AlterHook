/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook::detail
{
  struct injector_flags;
  struct patcher_flags;

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
