/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "trampoline.h"

#if !utils_msvc
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wrange-loop-construct"
#endif

namespace alterhook
{
  ALTERHOOK_HIDDEN uintptr_t process_frozen_threads(const trampoline& tramp,
                                                    bool      enable_hook,
                                                    uintptr_t ip) noexcept
  {
    for (const auto [oldpos, newpos] : tramp.positions)
    {
      auto [src, dst, current_pos, next_pos] =
          enable_hook ? std::tuple(tramp.ptarget, tramp.ptrampoline.get(),
                                   oldpos, newpos)
                      : std::tuple(tramp.ptrampoline.get(), tramp.ptarget,
                                   newpos, oldpos);

      if (ip == reinterpret_cast<uintptr_t>(src + current_pos))
        return reinterpret_cast<uintptr_t>(dst + next_pos);
    }
    return 0;
  }
} // namespace alterhook

#if !utils_msvc
  #pragma GCC diagnostic pop
#endif