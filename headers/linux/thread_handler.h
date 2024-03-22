/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
  class trampoline;

  class [[gnu::visibility("hidden")]] thread_freezer
  {
  private:
    // when ref count reaches 0, the old signal handler will be reset
    static size_t                             ref_count;
    // the lock is needed here because the ref count may be incremented or
    // decremented at the same time causing issues. and no the use of atomic
    // wouldn't really fix the problem as one thread could be suspending threads
    // the moment another thread is trying to setup the signal handler. so a
    // mutex is the safest solution
    static std::mutex                         ref_count_lock;
    // when a thread is successfully processed this is incremented by one
    // this is needed in order to make sure no further actions are taken before
    // all threads are processed
    static std::atomic_size_t                 processed_threads_count;
    static std::shared_mutex                  freezer_lock;
    static bool                               should_suspend;
    static struct sigaction                   old_action;
    static std::pair<const trampoline*, bool> args;
#if utils_arm || utils_aarch64
    static std::pair<std::atomic_bool,
                     std::tuple<std::byte*, std::byte*, size_t>>
        result;
#endif
    // these are tids and not pids. pids & tids just share the same type
    // underlying
    std::vector<pid_t> tids;

    // gets all the current active threads
    void        scan_threads();
    void        wait_until_threads_are_processed();
    static bool suspend(pid_t tid) noexcept;
    static void resume(pid_t tid) noexcept;
    static void set_signal_handler();
    static void unset_signal_handler() noexcept;
    static void thread_control_handler(int sig, siginfo_t* siginfo,
                                       void* sigcontext);

// ARM/AArch64 specific
#if utils_arm || utils_aarch64
    void        handle_errors();
    friend void report_error(std::byte* tramp, std::byte* target,
                             uint8_t pos) noexcept;
#endif

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
