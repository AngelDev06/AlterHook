/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "thread_handler.h"
#include "tools.h"

namespace alterhook
{
  constexpr DWORD thread_access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                  THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT;

  static uintptr_t getip(const CONTEXT& ctx) noexcept
  {
#if utils_x64
    return ctx.Rip;
#else
    return ctx.Eip;
#endif
  }

  static void setip(CONTEXT& ctx, uintptr_t ip) noexcept
  {
#if utils_x64
    ctx.Rip = ip;
#else
    ctx.Eip = ip;
#endif
  }

  struct handle_cleanup
  {
    void operator()(HANDLE handle) const noexcept
    {
      if (handle)
        CloseHandle(handle);
    }
  };

  typedef std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_cleanup>
      unique_handle;

  template <typename callable>
  static void walk_threads(HANDLE snapshot, callable&& fn)
  {
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snapshot, &te))
    {
      do
      {
        fn(te);
        te.dwSize = sizeof(te);
      } while (Thread32Next(snapshot, &te));

      DWORD last_error = GetLastError();
      if (last_error != ERROR_NO_MORE_FILES)
        nested_throw(exceptions::thread_list_traversal_fail(
            last_error, snapshot, reinterpret_cast<uintptr_t>(&te)));
    }
  }

  void thread_freezer::scan_threads()
  {
    unique_handle handle{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };

    if (handle.get() == INVALID_HANDLE_VALUE)
      return;

    walk_threads(handle.get(),
                 [this](THREADENTRY32& entry)
                 {
                   if (entry.dwSize <
                           (offsetof(THREADENTRY32, th32OwnerProcessID) +
                            sizeof(DWORD)) ||
                       entry.th32OwnerProcessID != GetCurrentProcessId() ||
                       entry.th32ThreadID == GetCurrentThreadId())
                     return;

                   if (tids.empty())
                     tids.reserve(10);

                   tids.push_back(entry.th32ThreadID);
                 });
  }

  static void process(const trampoline& tramp, bool enable_hook, HANDLE handle)
  {
    CONTEXT thread_context;
    thread_context.ContextFlags = CONTEXT_CONTROL;

    if (!GetThreadContext(handle, &thread_context))
      return;

    if (uintptr_t result =
            process_frozen_threads(tramp, enable_hook, getip(thread_context)))
    {
      setip(thread_context, result);
      SetThreadContext(handle, &thread_context);
    }
  }

  void thread_freezer::init(const trampoline& tramp, bool enable_hook)
  {
    scan_threads();

    for (DWORD tid : tids)
    {
      unique_handle handle{ OpenThread(thread_access, false, tid) };
      if (handle)
      {
        SuspendThread(handle.get());
        process(tramp, enable_hook, handle.get());
      }
    }
  }

  void thread_freezer::init(std::nullptr_t)
  {
    scan_threads();

    for (DWORD tid : tids)
    {
      unique_handle handle{ OpenThread(thread_access, false, tid) };
      if (handle)
        SuspendThread(handle.get());
    }
  }

  thread_freezer::~thread_freezer() noexcept
  {
    for (DWORD tid : tids)
    {
      unique_handle handle{ OpenThread(THREAD_SUSPEND_RESUME, false, tid) };
      if (handle)
        ResumeThread(handle.get());
    }
  }
} // namespace alterhook
