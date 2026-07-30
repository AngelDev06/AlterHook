/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "injection.hpp"
#pragma GCC visibility push(hidden)

namespace alterhook
{
  class trampoline;

  struct defer_freeze_t
  {
    explicit constexpr defer_freeze_t() = default;
  };

  inline constexpr defer_freeze_t defer_freeze{};

  class thread_freezer
  {
  private:
    using args_t = std::pair<const trampoline*, bool>;
    using result_t =
        std::pair<std::atomic_bool, std::tuple<std::byte*, std::byte*, size_t>>;
    using signal_data_t = struct sigaction;

    // when ref count reaches 0, the old signal handler will be reset
    inline static size_t             ref_count = 0;
    // the lock is needed here because the ref count may be incremented or
    // decremented at the same time causing issues. and no the use of atomic
    // wouldn't really fix the problem as one thread could be suspending threads
    // the moment another thread is trying to setup the signal handler. so a
    // mutex is the safest solution
    inline static std::mutex         ref_count_lock{};
    // when a thread is successfully processed this is incremented by one
    // this is needed in order to make sure no further actions are taken before
    // all threads are processed
    inline static std::atomic_size_t processed_threads_count{};
    inline static std::atomic_bool   should_suspend = false;
    inline static signal_data_t      old_action{};
    inline static args_t             args{};
#if utils_arm || utils_aarch64
    inline static result_t result{};
#endif
    // these are tids and not pids. pids & tids just share the same type
    // underlying
    std::vector<pid_t>                  tids;
    std::unique_lock<std::shared_mutex> instance_lock{ global_inject_lock,
                                                       std::defer_lock };
    bool                                is_managing_signals = false;

    static bool suspend(pid_t tid) noexcept;
    static void set_signal_handler();
    static void unset_signal_handler() noexcept;
    static void thread_control_handler(int sig, siginfo_t* siginfo,
                                       void* sigcontext);
    void        scan_threads();
    void        setup_signal_handler();
    void        wait_until_threads_are_processed();
    void        handle_errors();
    void        suspend_all_and_wait();
    void        cleanup() noexcept;

// ARM/AArch64 specific
#if utils_arm || utils_aarch64
    friend void report_error(std::byte* tramp, std::byte* target,
                             uint8_t pos) noexcept;
#endif

  public:
    void init(const trampoline& tramp, bool enable_hook);
    void init();

    thread_freezer(const trampoline& tramp, bool enable_hook)
    {
      try
      {
        init(tramp, enable_hook);
      }
      catch (...)
      {
        cleanup();
        throw;
      }
    }

    thread_freezer()
    {
      try
      {
        init();
      }
      catch (...)
      {
        cleanup();
        throw;
      }
    }

    thread_freezer(defer_freeze_t) noexcept {}

    ~thread_freezer() noexcept { cleanup(); }

    bool initialized() const noexcept { return instance_lock.owns_lock(); }
  };

  uintptr_t process_frozen_threads(const trampoline& tramp, bool enable_hook,
                                   uintptr_t ip) noexcept;
} // namespace alterhook

#pragma GCC visibility pop
