/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "linux_thread_handler.h"
#include "tools.h"

#if utils_arm
  #define report_any_errors() handle_errors()
#else
  #define report_any_errors() ((void)0)
#endif

namespace fs = std::filesystem;

namespace alterhook
{
  static uintptr_t getip(void* sigcontext) noexcept
  {
#if utils_arm
    return static_cast<ucontext_t*>(sigcontext)->uc_mcontext.arm_pc;
#elif utils_x64
    return static_cast<ucontext_t*>(sigcontext)->uc_mcontext.gregs[REG_RIP];
#elif utils_x86
    return static_cast<ucontext_t*>(sigcontext)->uc_mcontext.gregs[REG_EIP];
#endif
  }

  static void setip(void* sigcontext, uintptr_t ip) noexcept
  {
#if utils_arm
    static_cast<ucontext_t*>(sigcontext)->uc_mcontext.arm_pc = ip;
#elif utils_x64
    static_cast<ucontext_t*>(sigcontext)->uc_mcontext.gregs[REG_RIP] = ip;
#elif utils_x86
    static_cast<ucontext_t*>(sigcontext)->uc_mcontext.gregs[REG_EIP] = ip;
#endif
  }

  size_t             thread_freezer::ref_count = 0;
  std::mutex         thread_freezer::ref_count_lock{};
  std::atomic_size_t thread_freezer::processed_threads_count{};
  std::shared_mutex  thread_freezer::freezer_lock{};
  bool               thread_freezer::should_suspend = false;

  struct sigaction thread_freezer::old_action
  {
  };

  std::pair<const trampoline*, bool> thread_freezer::args{};
#if utils_arm
  std::pair<std::atomic_bool, std::tuple<std::byte*, std::byte*, size_t>>
      thread_freezer::result{};
#endif

  void thread_freezer::scan_threads()
  {
    // we don't want to scan threads while another thread is freezing them (or
    // the other way around) but we can have multiple threads scanning the
    // thread list in parallel without issues so this is the perfect use case
    // for a shared lock
    std::shared_lock lock{ freezer_lock };
    pid_t            current_tid = gettid();

    for (const fs::directory_entry& entry :
         fs::directory_iterator("/proc/self/task"))
    {
      pid_t tid = std::stoi(entry.path().stem().string());
      if (tid == current_tid)
        continue;

      std::ifstream status{ entry.path() / "stat" };
      if (!status.is_open())
        continue;
      char state{};
      status.ignore(std::numeric_limits<std::streamsize>::max(), ')');
      status >> state;

      if (state == 'R')
      {
        if (tids.empty())
          tids.reserve(10);
        tids.push_back(tid);
      }
    }
  }

  void thread_freezer::wait_until_threads_are_processed()
  {
    while (processed_threads_count.load(std::memory_order_acquire) <
           tids.size())
      std::this_thread::yield();
  }

  bool thread_freezer::suspend(pid_t tid) noexcept
  {
    should_suspend = true;
    return !tgkill(getpid(), tid, SIGURG);
  }

  void thread_freezer::resume(pid_t tid) noexcept
  {
    should_suspend = false;
    tgkill(getpid(), tid, SIGURG);
  }

  void thread_freezer::set_signal_handler()
  {
    struct sigaction act
    {
    };

    act.sa_sigaction = thread_control_handler;
    act.sa_flags     = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&act.sa_mask);
    // we cannot proceed if signal handler isn't set so this
    // is exception worthy
    if (sigaction(SIGURG, &act, &old_action))
      nested_throw(
          exceptions::sigaction_exception(errno, SIGURG, &act, &old_action));
  }

  void thread_freezer::unset_signal_handler() noexcept
  {
    sigaction(SIGURG, &old_action, nullptr);
  }

  void thread_freezer::thread_control_handler(int, siginfo_t*, void* sigcontext)
  {
    if (!should_suspend)
    {
      processed_threads_count.fetch_add(1, std::memory_order_acq_rel);
      return;
    }

    if (args.first)
    {
      if (uintptr_t result = process_frozen_threads(*args.first, args.second,
                                                    getip(sigcontext)))
        setip(sigcontext, result);
    }

    processed_threads_count.fetch_add(1, std::memory_order_acq_rel);
    pause();
  }

  void thread_freezer::init(const trampoline& tramp, bool enable_hook)
  {
    // read only operation, it can work in parallel
    scan_threads();
    {
      std::scoped_lock lock{ ref_count_lock };
      if (!ref_count)
        set_signal_handler();
      ++ref_count;
    }
    std::unique_lock lock{ freezer_lock };
    args = { &tramp, enable_hook };
    // iterating with indexes on purpose since we are modifying the list at the
    // same time also note that erase in this case is noexcept
    for (size_t i = 0; i != tids.size(); ++i)
    {
      if (!suspend(tids[i]))
        tids.erase(tids.begin() + i);
    }

    wait_until_threads_are_processed();
    report_any_errors();
  }

  void thread_freezer::init(std::nullptr_t)
  {
    scan_threads();
    {
      std::scoped_lock lock{ ref_count_lock };
      if (!ref_count)
        set_signal_handler();
      ++ref_count;
    }
    std::unique_lock lock{ freezer_lock };
    args = { nullptr, 0 };

    for (size_t i = 0; i != tids.size(); ++i)
    {
      if (!suspend(tids[i]))
        tids.erase(tids.begin() + i);
    }

    wait_until_threads_are_processed();
  }

  thread_freezer::~thread_freezer() noexcept
  {
    if (!tids.empty())
    {
      std::unique_lock lock{ freezer_lock };
      for (pid_t tid : tids)
        resume(tid);
    }
    {
      std::scoped_lock lock{ ref_count_lock };
      --ref_count;
      if (!ref_count)
        unset_signal_handler();
    }
  }

#if utils_arm
  void thread_freezer::handle_errors()
  {
    if (!result.first.load(std::memory_order_relaxed))
      return;

    for (pid_t tid : tids)
      resume(tid);

    std::scoped_lock lock{ ref_count_lock };
    --ref_count;
    if (!ref_count)
      unset_signal_handler();

    result.first.store(false, std::memory_order_relaxed);
    auto [tramp_addr, target_addr, pos] = result.second;
    nested_throw(exceptions::thread_process_fail(tramp_addr, target_addr, pos));
  }

  ALTERHOOK_HIDDEN void report_error(std::byte* tramp, std::byte* target,
                                     uint8_t pos) noexcept
  {
    auto& [status, data] = thread_freezer::result;
    bool expected        = false;

    if (!status.compare_exchange_strong(expected, true,
                                        std::memory_order_acq_rel,
                                        std::memory_order_acquire))
      return;

    data = std::tie(tramp, target, pos);
  }
#endif
} // namespace alterhook