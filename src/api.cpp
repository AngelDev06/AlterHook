/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "addresser.h"
#include "tools.h"
#if !utils_windows
#include "linux_thread_handler.h"
#endif
#include "api.h"

namespace alterhook
{
	extern std::shared_mutex hook_lock;
	#if !utils_windows
	void inject_to_target(std::byte* target, const std::byte* backup_or_detour, bool patch_above, bool enable, int old_protect);
	#define __alterhook_inject(backup_or_detour, enable) \
		inject_to_target(ptarget, backup_or_detour, patch_above, enable, old_protect)
	#endif

	hook::hook(const hook& other) : trampoline(other)
	{
		__alterhook_copy_dtr(other);
		memcpy(backup.data(), other.backup.data(), backup.size());
	}

	hook::hook(hook&& other) noexcept : trampoline(std::move(other)), enabled(other.enabled), original_buffer(other.original_buffer)
	{
		__alterhook_exchange_dtr(other);
		memcpy(backup.data(), other.backup.data(), backup.size());
		if (other.original_wrap)
		{
			other.original_wrap = nullptr;
			original_wrap = std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
		}
	}

	hook& hook::operator=(const hook& other)
	{
		if (this != &other)
		{
			if (enabled)
				disable();
			trampoline::operator=(other);
			__alterhook_copy_dtr(other);
			memcpy(backup.data(), other.backup.data(), backup.size());
		}
		return *this;
	}

	hook& hook::operator=(hook&& other) noexcept
	{
		if (this != &other)
		{
			if (enabled) try
			{
				disable();
			} catch (...) {}
			trampoline::operator=(std::move(other));
			enabled = other.enabled;
			original_buffer = other.original_buffer;
			__alterhook_exchange_dtr(other);
			memcpy(backup.data(), other.backup.data(), backup.size());
			if (other.original_wrap)
			{
				other.original_wrap = nullptr;
				original_wrap = std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
			}
		}
		return *this;
	}

	hook::~hook() noexcept
	try
	{
		if (__alterhook_get_dtr())
			disable();
	} catch (...) {}

	void hook::enable()
	{
		utils_assert(__alterhook_get_dtr(), "hook::enable: invalid detour");
		if (!enabled)
		{
			std::unique_lock lock{ hook_lock };
			thread_freezer freeze{ *this, true };
			__alterhook_inject(__alterhook_get_real_dtr(), true);
			enabled = true;
		}
	}

	void hook::disable()
	{
		if (enabled)
		{
			std::unique_lock lock{ hook_lock };
			if (original_wrap)
				*original_wrap = nullptr;
			thread_freezer freeze{ *this, false };
			__alterhook_inject(backup.data(), false);
			enabled = false;
		}
	}
}