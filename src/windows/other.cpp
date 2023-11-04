#include <pch.h>
#include "exceptions.h"
#define __alterhook_expose_impl
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
        std::throw_with_nested(exceptions::thread_list_traversal_fail(
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
    if (!tids.empty())
    {
      for (DWORD tid : tids)
      {
        handle_wrapper handle{ OpenThread(THREAD_SUSPEND_RESUME, false, tid) };
        if (handle)
          ResumeThread(handle);
      }
    }
  }

  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        bool patch_above, bool enable)
  {
    utils_assert(target, "inject_to_target: no target address specified");
    utils_assert(backup_or_detour,
                 "inject_to_target: no backup or detour specified");
    DWORD old_protection = 0;
    const auto [address, size] =
        patch_above
            ? std::pair(target - sizeof(JMP), sizeof(JMP) + sizeof(JMP_SHORT))
            : std::pair(target, sizeof(JMP));

    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old_protection))
      throw(exceptions::virtual_protect_exception(
          GetLastError(), address, size, PAGE_EXECUTE_READWRITE,
          reinterpret_cast<uintptr_t>(&old_protection)));

    if (enable)
    {
      new (address) JMP(
          static_cast<uint32_t>(backup_or_detour - (address + sizeof(JMP))));

      if (patch_above)
        new (address + sizeof(JMP)) JMP_SHORT(
            static_cast<uint8_t>(0 - (sizeof(JMP) + sizeof(JMP_SHORT))));
    }
    else
      memcpy(address, backup_or_detour, size);

    VirtualProtect(address, size, old_protection, &old_protection);
    FlushInstructionCache(GetCurrentProcess(), address, size);
  }

#if utils_x86
  void patch_jmp(std::byte* target, const std::byte* detour, bool patch_above)
  {
    utils_assert(target, "patch_jmp: no target address specified");
    utils_assert(detour, "patch_jmp: no detour specified");
    DWORD old_protection = 0;
    std::byte* const address = patch_above ? target - sizeof(JMP) : target;

    if (!VirtualProtect(address, sizeof(JMP), PAGE_EXECUTE_READWRITE,
                        &old_protection))
      throw(exceptions::virtual_protect_exception(
          GetLastError(), address, sizeof(JMP), PAGE_EXECUTE_READWRITE,
          reinterpret_cast<uintptr_t>(&old_protection)));

    reinterpret_cast<JMP*>(address)->offset =
        static_cast<uint32_t>(detour - (address + sizeof(JMP)));

    VirtualProtect(address, sizeof(JMP), old_protection, &old_protection);
    FlushInstructionCache(GetCurrentProcess(), address, sizeof(JMP));
  }
#endif
} // namespace alterhook
