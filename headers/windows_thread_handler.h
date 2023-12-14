/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
  class trampoline;

  class thread_freezer
  {
  private:
    std::vector<DWORD> tids;

    void scan_threads();

  public:
    void init(const trampoline& tramp, bool enable_hook);
    void init(std::nullptr_t);

    thread_freezer(const trampoline& tramp, bool enable_hook)
    {
      init(tramp, enable_hook);
    }

    thread_freezer(std::nullptr_t) { init(nullptr); }

    thread_freezer() {}

    ~thread_freezer() noexcept;
  };

  uintptr_t process_frozen_threads(const trampoline& tramp, bool enable_hook,
                                   uintptr_t ip) noexcept;
} // namespace alterhook
