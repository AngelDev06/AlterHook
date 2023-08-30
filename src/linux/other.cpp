/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "linux_thread_handler.h"
#include "addresser.h"
#include "tools.h"
#define __alterhook_expose_impl
#include "api.h"
#if utils_arm
  #include "arm_instructions.h"
#endif
namespace fs = std::filesystem;

#ifdef __GNUC__
  #define __alterhook_flush_cache(address, size)                               \
    __builtin___clear_cache(reinterpret_cast<char*>(address),                  \
                            reinterpret_cast<char*>(address) + size)
#else
  #define __alterhook_flush_cache(address, size)                               \
    cacheflush(reinterpret_cast<uintptr_t>(address), size, 0)
#endif

namespace alterhook
{
  extern const long memory_block_size;

  namespace exceptions
  {
    const char* os_exception::get_error_string() const noexcept
    {
      return strerror(m_error_code);
    }

    std::string mmap_exception::error_function() const
    {
      std::stringstream stream;
      stream << "mmap(0x" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_target_address) << ", "
             << std::dec << m_size << ", " << m_protection << ", " << m_flags
             << ", " << m_fd << ", " << m_offset << ')';
      return stream.str();
    }

    std::string sigaction_exception::error_function() const
    {
      std::stringstream stream;
      stream << "sigaction(" << m_signal << ", 0x" << std::hex
             << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_action) << ", 0x"
             << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_old_action) << ')';
      return stream.str();
    }

    std::string thread_process_fail::str() const
    {
      std::stringstream stream;
      stream << "trampoline address: 0x" << std::hex << std::setfill('0')
             << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_trampoline_address)
             << "\ntarget address: 0x" << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_target_address)
             << "\nposition: " << std::dec << m_position;
      return stream.str();
    }

    std::string mprotect_exception::error_function() const
    {
      std::stringstream stream;
      stream << "mprotect(" << std::hex << std::setfill('0') << std::setw(8)
             << reinterpret_cast<uintptr_t>(m_address) << ", " << std::dec
             << m_length << ", " << m_protection << ')';
      return stream.str();
    }
  } // namespace exceptions

#if utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wrange-loop-construct"
#endif

#if utils_arm
  void process_frozen_threads(const trampoline& tramp, bool enable_hook,
                              unsigned long& pc)
  {
    auto& [status, data] = thread_freezer::result;
    uint8_t exceptpos    = 0;
    if (enable_hook)
    {
      const uintptr_t target = reinterpret_cast<uintptr_t>(tramp.ptarget) & ~1;
      for (const auto [oldpos, newpos] : tramp.positions)
      {
        if (pc == (target + oldpos))
        {
          const uintptr_t dest =
              reinterpret_cast<uintptr_t>(tramp.ptrampoline.get()) + newpos;
          const uintptr_t pushloc =
              reinterpret_cast<uintptr_t>(tramp.ptrampoline.get()) +
              tramp.pc_handling.second;
          if (tramp.pc_handling.first && dest > pushloc)
          {
            bool expected = false;
            if (status.compare_exchange_strong(expected, true,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire))
            {
              exceptpos = oldpos;
              goto PUT_EXCEPTION;
            }
            return;
          }
          pc = dest;
          return;
        }
      }
      return;
    }
    else
    {
      uint8_t prevpos = 0;
      for (const auto [oldpos, newpos] : tramp.positions)
      {
        const uintptr_t dest =
            reinterpret_cast<uintptr_t>(tramp.ptarget) + oldpos;
        const uintptr_t src =
            reinterpret_cast<uintptr_t>(tramp.ptrampoline.get()) + newpos;
        const uintptr_t prevsrc =
            reinterpret_cast<uintptr_t>(tramp.ptrampoline.get()) + prevpos;
        const uintptr_t pushloc =
            reinterpret_cast<uintptr_t>(tramp.ptrampoline.get()) +
            tramp.pc_handling.second;
        if (pc <= src && pc >= prevsrc)
        {
          if (pc < src || (tramp.pc_handling.first && pc > pushloc))
          {
            bool expected = false;
            if (status.compare_exchange_strong(expected, true,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire))
            {
              exceptpos = static_cast<uint8_t>(
                  pc - reinterpret_cast<uintptr_t>(tramp.ptrampoline.get()));
              goto PUT_EXCEPTION;
            }
            return;
          }
          pc = dest;
          return;
        }
        prevpos = newpos;
      }
      return;
    }
  PUT_EXCEPTION:
    auto& [ptramp, ptarget, pos] = data;
    ptramp                       = tramp.ptrampoline.get();
    ptarget                      = tramp.ptarget;
    pos                          = exceptpos;
  }
#endif

#if utils_clang
  #pragma clang diagnostic pop
#endif

  size_t             thread_freezer::ref_count = 0;
  std::mutex         thread_freezer::ref_count_lock{};
  std::atomic_size_t thread_freezer::processed_threads_count{};
  std::shared_mutex  thread_freezer::freezer_lock{};
  bool               thread_freezer::should_suspend = false;

  struct sigaction thread_freezer::old_action
  {
  };

  std::pair<const trampoline*, bool> thread_freezer::args{};
  std::pair<std::atomic_bool, std::tuple<std::byte*, std::byte*, size_t>>
      thread_freezer::result{};

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
      std::throw_with_nested(
          exceptions::sigaction_exception(errno, SIGURG, &act, &old_action));
  }

  void thread_freezer::unset_signal_handler() noexcept
  {
    sigaction(SIGURG, &old_action, nullptr);
  }

  void thread_freezer::thread_control_handler(int sig, siginfo_t* siginfo,
                                              void* sigcontext)
  {
    if (should_suspend)
    {
      if (args.first)
        process_frozen_threads(
            *args.first, args.second,
            static_cast<ucontext_t*>(sigcontext)->uc_mcontext.arm_pc);
      processed_threads_count.fetch_add(1, std::memory_order_acq_rel);
      pause();
    }
    else
      processed_threads_count.fetch_add(1, std::memory_order_acq_rel);
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

    // to be able to freely throw exceptions we first need to resume & unset
    // handler if needed
    if (result.first.load(std::memory_order_relaxed))
    {
      for (pid_t tid : tids)
        resume(tid);
      std::scoped_lock lock{ ref_count_lock };
      --ref_count;
      if (!ref_count)
        unset_signal_handler();

      result.first.store(false, std::memory_order_relaxed);
      auto [tramp_addr, target_addr, pos] = result.second;
      std::throw_with_nested(
          exceptions::thread_process_fail(tramp_addr, target_addr, pos));
    }
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

  std::pair<bool, int> ALTERHOOK_HIDDEN get_prot(const std::byte* address)
  {
    std::ifstream maps{ "/proc/self/maps" };
    utils_assert(maps.is_open(), "get_prot: couldn't open `/proc/self/maps`");

    do
    {
      uintptr_t begin_address = 0;
      uintptr_t end_address   = 0;

      maps >> std::hex >> begin_address;
      maps.seekg(1, std::ios_base::cur);
      maps >> end_address;

      if (reinterpret_cast<uintptr_t>(address) >= begin_address &&
          reinterpret_cast<uintptr_t>(address) < end_address)
      {
        char perms[5]{};
        int  result = PROT_NONE;
        maps >> perms;

        if (perms[0] == 'r')
          result |= PROT_READ;
        if (perms[1] == 'w')
          result |= PROT_WRITE;
        if (perms[2] == 'x')
          result |= PROT_EXEC;
        return { true, result };
      }

      maps.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    } while (maps.good());

    return { false, PROT_NONE };
  }

  bool is_executable_address(const void* address)
  {
    auto [status, value] = get_prot(static_cast<const std::byte*>(address));
    if (status && (value & PROT_EXEC))
      return true;
    return false;
  }

#if utils_arm
  ALTERHOOK_HIDDEN void inject_to_target(std::byte*       target,
                                         const std::byte* backup_or_detour,
                                         bool patch_above, bool enable,
                                         int old_protect)
  {
    utils_assert(target, "inject_to_target: no target address specified");
    utils_assert(backup_or_detour,
                 "inject_to_target: no backup or detour specified");
    const bool uses_thumb = reinterpret_cast<uintptr_t>(target) & 1;
    reinterpret_cast<uintptr_t&>(target) &= ~1;
    const auto [address, size] =
        patch_above ? std::pair(target - sizeof(uint32_t), sizeof(FULL_JMP_ABS))
                    : std::pair(target, reinterpret_cast<uintptr_t>(target) % 4
                                            ? sizeof(FULL_JMP_ABS) + 2
                                            : sizeof(FULL_JMP_ABS));
    std::byte* const prot_addr = reinterpret_cast<std::byte*>(
        utils_align(reinterpret_cast<uintptr_t>(address), memory_block_size));
    const size_t prot_len =
        utils_align((address - prot_addr) + size + (memory_block_size - 1),
                    memory_block_size);
    constexpr int protection = PROT_READ | PROT_WRITE | PROT_EXEC;

    if (mprotect(prot_addr, prot_len, protection) == -1)
      std::throw_with_nested(exceptions::mprotect_exception(
          errno, prot_addr, prot_len, protection));
    if (enable)
    {
      std::byte buffer[sizeof(FULL_JMP_ABS) + 2]{};
      if (uses_thumb)
      {
        if (patch_above)
        {
          THUMB2_JMP_ABS tjmp{};
          tjmp.set_offset(address -
                          reinterpret_cast<std::byte*>(utils_align(
                              reinterpret_cast<uintptr_t>(target) + 4, 4)));
          new (buffer) auto(backup_or_detour);
          new (&buffer[sizeof(backup_or_detour)]) auto(tjmp);
        }
        else
        {
          if (reinterpret_cast<uintptr_t>(target) % 4)
          {
            THUMB2_JMP_ABS tjmp{};
            tjmp.set_offset(2);
            new (buffer) auto(tjmp);
            new (&buffer[sizeof(tjmp) + 2]) auto(backup_or_detour);
          }
          else
            new (buffer) THUMB2_FULL_JMP_ABS(
                reinterpret_cast<uintptr_t>(backup_or_detour));
        }
      }
      else
      {
        if (patch_above)
        {
          JMP_ABS jmp{};
          jmp.set_offset(address - (target + 8));
          new (buffer) auto(backup_or_detour);
          new (&buffer[sizeof(backup_or_detour)]) auto(jmp);
        }
        else
          new (buffer)
              FULL_JMP_ABS(reinterpret_cast<uintptr_t>(backup_or_detour));
      }
      memcpy(address, buffer, size);
    }
    else
      memcpy(address, backup_or_detour, size);

    mprotect(prot_addr, prot_len, old_protect);
    __alterhook_flush_cache(address, size);
  }

  ALTERHOOK_HIDDEN void patch_jmp(std::byte* target, const std::byte* detour,
                                  bool patch_above, int old_protect)
  {
    utils_assert(target, "patch_jmp: no target address specified");
    utils_assert(detour, "patch_jmp: no detour specified");
    reinterpret_cast<uintptr_t&>(target) &= ~1;
    std::byte*       address   = patch_above ? target - sizeof(uint32_t)
                                 : reinterpret_cast<uintptr_t>(target) % 4
                                     ? target + sizeof(JMP_ABS) + 2
                                     : target + sizeof(JMP_ABS);
    std::byte* const prot_addr = reinterpret_cast<std::byte*>(
        utils_align(reinterpret_cast<uintptr_t>(address), memory_block_size));
    const size_t prot_len = utils_align(
        (address - prot_addr) + sizeof(uint32_t) + (memory_block_size - 1),
        memory_block_size);
    constexpr int protection = PROT_READ | PROT_WRITE | PROT_EXEC;

    if (mprotect(prot_addr, prot_len, protection) == -1)
      std::throw_with_nested(exceptions::mprotect_exception(
          errno, prot_addr, prot_len, protection));
    *reinterpret_cast<uint32_t*>(address) = reinterpret_cast<uintptr_t>(detour);
    mprotect(prot_addr, prot_len, protection);
    __alterhook_flush_cache(address, sizeof(uint32_t));
  }
#endif
} // namespace alterhook
