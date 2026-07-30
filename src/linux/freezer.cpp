/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.hpp>
#include <thread>
#include "exceptions.hpp"
#include "thread_handler.hpp"
#include "tools.hpp"

namespace fs = std::filesystem;

namespace alterhook
{
  static uintptr_t getip(void* sigcontext) noexcept
  {
#if utils_aarch64
    return static_cast<ucontext_t*>(sigcontext)->uc_mcontext.pc;
#elif utils_arm
    return static_cast<ucontext_t*>(sigcontext)->uc_mcontext.arm_pc;
#elif utils_x64
    return static_cast<ucontext_t*>(sigcontext)->uc_mcontext.gregs[REG_RIP];
#elif utils_x86
    return static_cast<ucontext_t*>(sigcontext)->uc_mcontext.gregs[REG_EIP];
#endif
  }

  static void setip(void* sigcontext, uintptr_t ip) noexcept
  {
#if utils_aarch64
    static_cast<ucontext_t*>(sigcontext)->uc_mcontext.pc = ip;
#elif utils_arm
    static_cast<ucontext_t*>(sigcontext)->uc_mcontext.arm_pc = ip;
#elif utils_x64
    static_cast<ucontext_t*>(sigcontext)->uc_mcontext.gregs[REG_RIP] = ip;
#elif utils_x86
    static_cast<ucontext_t*>(sigcontext)->uc_mcontext.gregs[REG_EIP] = ip;
#endif
  }

  bool thread_freezer::suspend(pid_t tid) noexcept
  {
    return !tgkill(getpid(), tid, SIGURG);
  }

  void thread_freezer::set_signal_handler()
  {
    signal_data_t act{};

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
    if (!should_suspend.load(std::memory_order_acquire))
      return;

    if (args.first)
    {
      if (uintptr_t result = process_frozen_threads(*args.first, args.second,
                                                    getip(sigcontext)))
        setip(sigcontext, result);
    }

    processed_threads_count.fetch_add(1, std::memory_order_acq_rel);

    while (should_suspend.load(std::memory_order_acquire))
      std::this_thread::yield();
  }

  void thread_freezer::scan_threads()
  {
    // we don't want to scan threads while another thread is freezing them (or
    // the other way around) but we can have multiple threads scanning the
    // thread list in parallel without issues so this is the perfect use case
    // for a shared unique
    std::shared_lock lock{ global_inject_lock };
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

  void thread_freezer::setup_signal_handler()
  {
    std::scoped_lock lock{ ref_count_lock };
    if (!ref_count)
      set_signal_handler();
    ++ref_count;

    is_managing_signals = true;
  }

  void thread_freezer::wait_until_threads_are_processed()
  {
    while (processed_threads_count.load(std::memory_order_acquire) <
           tids.size())
      std::this_thread::yield();
  }

  void thread_freezer::handle_errors()
  {
#if utils_arm || utils_aarch64
    if (!result.first.load(std::memory_order_relaxed))
      return;
    result.first.store(false, std::memory_order_relaxed);
    auto [tramp_addr, target_addr, pos] = result.second;
    nested_throw(exceptions::thread_process_fail(tramp_addr, target_addr, pos));
#endif
  }

  void thread_freezer::suspend_all_and_wait()
  {
    should_suspend.store(true, std::memory_order_release);
    processed_threads_count.store(0, std::memory_order_release);
    // iterating with indexes on purpose since we are modifying the list at the
    // same time also note that erase in this case is noexcept
    for (size_t i = 0; i != tids.size(); ++i)
    {
      if (!suspend(tids[i]))
        tids.erase(tids.begin() + i);
    }

    wait_until_threads_are_processed();
  }

  void thread_freezer::cleanup() noexcept
  {
    if (!tids.empty())
    {
      should_suspend.store(false, std::memory_order_release);
      tids.clear();
    }

    if (is_managing_signals)
    {
      std::scoped_lock lock{ ref_count_lock };
      --ref_count;
      if (!ref_count)
        unset_signal_handler();

      is_managing_signals = false;
    }
  }

  void thread_freezer::init(const trampoline& tramp, bool enable_hook)
  {
    // read only operation, it can work in parallel
    scan_threads();
    setup_signal_handler();
    instance_lock.lock();
    args = { &tramp, enable_hook };
    suspend_all_and_wait();
    handle_errors();
  }

  void thread_freezer::init()
  {
    scan_threads();
    setup_signal_handler();
    instance_lock.lock();
    args = { nullptr, 0 };
    suspend_all_and_wait();
  }

#if utils_arm || utils_aarch64
  [[gnu::visibility("hidden")]] void
      report_error(std::byte* tramp, std::byte* target, uint8_t pos) noexcept
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
