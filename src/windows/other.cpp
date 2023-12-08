#include <pch.h>
#include "exceptions.h"
#include "trampoline.h"
#include "windows_thread_handler.h"
#include "x86_instructions.h"

namespace alterhook
{
#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4244)
#endif

  namespace exceptions
  {
    std::string virtual_alloc_exception::error_function() const
    {
      std::stringstream stream;
      stream << "VirtualAlloc(0x" << std::hex << std::setfill('0')
             << std::setw(8) << reinterpret_cast<uintptr_t>(m_target_address)
             << ", " << std::dec << m_size << ", " << m_allocation_type << ", "
             << m_protection << ')';
      return stream.str();
    }

    std::string thread_list_traversal_fail::error_function() const
    {
      std::stringstream stream;
      stream << "Thread32Next(0x" << std::hex << std::setfill('0')
             << std::setw(8) << reinterpret_cast<uintptr_t>(m_handle) << ", 0x"
             << std::setfill('0') << std::setw(8) << m_thread_entry_address
             << ')';
      return stream.str();
    }

    std::string virtual_protect_exception::error_function() const
    {
      std::stringstream stream;
      stream << "VirtualProtect(0x" << std::hex << std::setfill('0')
             << std::setw(8) << m_address << ", " << std::dec << m_size
             << ", 0x" << std::hex << std::setfill('0') << std::setw(8)
             << m_protection << ", 0x" << std::setfill('0') << std::setw(8)
             << m_old_protection << ')';
      return stream.str();
    }
  } // namespace exceptions

#if utils_msvc
  #pragma warning(pop)
#endif

  bool is_executable_address(const void* address)
  {
    constexpr size_t flags = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(address, &mi, sizeof(mi));
    return (mi.State == MEM_COMMIT && (mi.Protect & flags));
  }

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

  struct handle_wrapper
  {
    HANDLE handle;

    operator HANDLE() { return handle; }

    ~handle_wrapper()
    {
      if (handle)
        CloseHandle(handle);
    }
  };

  void process_frozen_threads(const trampoline& tramp, bool enable_hook,
                              HANDLE thread_handle)
  {
    CONTEXT tcontext;
    bool    set_ip = false;
#if utils_x64
    DWORD64& ip = tcontext.Rip;
#else
    DWORD& ip = tcontext.Eip;
#endif
    tcontext.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread_handle, &tcontext))
      return;

    if (enable_hook)
    {
      for (const auto [oldpos, newpos] : tramp.positions)
      {
        if (ip == reinterpret_cast<uintptr_t>(tramp.ptarget + oldpos))
        {
          set_ip = true;
          ip = reinterpret_cast<uintptr_t>(tramp.ptrampoline.get() + newpos);
          break;
        }
      }
    }
    else
    {
      for (const auto [oldpos, newpos] : tramp.positions)
      {
        if (ip == reinterpret_cast<uintptr_t>(tramp.ptrampoline.get() + newpos))
        {
          set_ip = true;
          ip     = reinterpret_cast<uintptr_t>(tramp.ptarget + oldpos);
          break;
        }
      }
    }

    if (set_ip)
      SetThreadContext(thread_handle, &tcontext);
  }

  void thread_freezer::scan_threads()
  {
    handle_wrapper handle{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if (handle != INVALID_HANDLE_VALUE)
    {
      walk_threads(handle,
                   [this](THREADENTRY32& entry)
                   {
                     if (entry.dwSize >=
                             (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                              sizeof(DWORD)) &&
                         entry.th32OwnerProcessID == GetCurrentProcessId() &&
                         entry.th32ThreadID != GetCurrentThreadId())
                     {
                       if (tids.empty())
                         tids.reserve(10);

                       tids.push_back(entry.th32ThreadID);
                     }
                   });
    }
  }

  constexpr DWORD thread_access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                  THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT;

  void thread_freezer::init(const trampoline& tramp, bool enable_hook)
  {
    scan_threads();

    for (DWORD tid : tids)
    {
      handle_wrapper handle{ OpenThread(thread_access, false, tid) };
      if (handle)
      {
        SuspendThread(handle);
        process_frozen_threads(tramp, enable_hook, handle);
      }
    }
  }

  void thread_freezer::init(std::nullptr_t)
  {
    scan_threads();

    for (DWORD tid : tids)
    {
      handle_wrapper handle{ OpenThread(thread_access, false, tid) };
      if (handle)
        SuspendThread(handle);
    }
  }

  thread_freezer::~thread_freezer() noexcept
  {
    for (DWORD tid : tids)
    {
      handle_wrapper handle{ OpenThread(THREAD_SUSPEND_RESUME, false, tid) };
      if (handle)
        ResumeThread(handle);
    }
  }
} // namespace alterhook
