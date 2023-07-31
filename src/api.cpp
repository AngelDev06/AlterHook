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
	void patch_jmp(std::byte* target, const std::byte* detour, bool patch_above, int old_protect);
	#define __alterhook_inject(backup_or_detour, enable) \
		inject_to_target(ptarget, backup_or_detour, patch_above, enable, old_protect)
	#define __alterhook_inject_base_node(backup_or_detour, enable) \
		inject_to_target(chain.ptarget, backup_or_detour, chain.patch_above, enable, chain.old_protect)
	#define __alterhook_patch_jmp(detour) \
		patch_jmp(ptarget, detour, patch_above, old_protect)
	#define __alterhook_patch_base_node_jmp(detour) \
		patch_jmp(chain.ptarget, detour, chain.patch_above, chain.old_protect)
	#define __alterhook_set_base_node_prelay(pdetour)
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
		if (original_wrap)
			*original_wrap = nullptr;
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
			thread_freezer freeze{ *this, false };
			__alterhook_inject(backup.data(), false);
			enabled = false;
		}
	}

	void hook::set_target(std::byte* target)
	{
		if (enabled)
			disable();
		init(target);
		__alterhook_make_backup();
	}

	void hook::set_detour(std::byte* detour)
	{
		__alterhook_set_dtr(detour);
		#if !utils_windows64
		if (enabled)
		{
			std::unique_lock lock{ hook_lock };
			__alterhook_patch_jmp(detour);
		}
		#endif
	}

	void hook::set_original(std::nullptr_t)
	{
		if (original_wrap)
		{
			*original_wrap = nullptr;
			original_wrap = nullptr;
		}
	}

	void hook_chain::init_chain()
	{
		std::unique_lock lock{ hook_lock };
		thread_freezer freeze{ *this, true };
		__alterhook_inject(std::prev(enabled.end())->pdetour, true);
	}

	void hook_chain::hook::enable()
	{
		utils_assert(chain.ptarget != pdetour, "hook_chain::hook::enable: target & detour have the same address");
		if (enabled)
			return;
		iterator target{};
		// re-setup if empty
		if (chain.enabled.empty())
		{
			{
				__alterhook_def_thumb_var(chain.ptarget);
				poriginal = __alterhook_add_thumb_bit(chain.ptrampoline.get());
				*origwrap = poriginal;
				std::unique_lock lock{ hook_lock };
				thread_freezer freeze{ chain, true };
				__alterhook_set_base_node_prelay(pdetour);
				__alterhook_inject_base_node(__alterhook_get_real_dtr(), true);
			}
			other = std::next(current);
			has_other = other != chain.disabled.end();
			target = chain.enabled.end();
		}
		else
		{
			iterator new_other{};
			bool new_has_other = false;
			// put next as other to current and search for other to splice to
			// otherwise remove other
			if (!has_other)
			{
				iterator result = std::next(current);
				new_other = result;
				new_has_other = result != chain.disabled.end();
				while (result != chain.disabled.end() && !result->has_other)
					++result;
				target = result == chain.disabled.end() ? chain.enabled.end() : result->other;
			}
			else
				target = other;
			
			if (target == chain.enabled.end())
			{
				poriginal = reinterpret_cast<std::byte*>(*chain.base);
				*origwrap = poriginal;
				__alterhook_set_base_node_prelay(pdetour);
				#if !utils_windows64
				// no need to freeze, we are just replacing old instruction address with a new one
				std::unique_lock lock{ hook_lock };
				__alterhook_patch_base_node_jmp(pdetour);
				#endif
			}
			else
			{
				poriginal = target->poriginal;
				*origwrap = target->poriginal;
				target->poriginal = pdetour;
				*target->origwrap = pdetour;
			}
			other = new_other;
			has_other = new_has_other;
		}

		// put current as other on prev if needed
		if (current != chain.disabled.begin())
		{
			iterator prev = std::prev(current);
			if (!prev->has_other)
			{
				prev->has_other = true;
				prev->other = current;
			}
		}

		// remove other on new prev if needed
		if (target != chain.enabled.begin())
		{
			iterator prev = std::prev(current);
			if (prev->has_other && prev->other == current)
				prev->has_other = false;
		}
		enabled = true;
		chain.enabled.splice(target, chain.disabled, current);
	}

	void hook_chain::hook::disable()
	{
		if (!enabled)
			return;
		iterator target{};
		iterator new_other{};
		bool new_has_other = false;
		if (chain.disabled.empty())
		{
			new_other = std::next(current);
			new_has_other = other != chain.enabled.end();
			target = chain.disabled.end();
		}
		else if (!has_other)
		{
			iterator result = std::next(current);
			new_other = result;
			new_has_other = other != chain.enabled.end();
			while (result != chain.enabled.end() && !result->has_other)
				++result;
			target = result == chain.enabled.end() ? chain.disabled.end() : result->other;
		}
		else
			target = other;

		// if enabled list is going to be left empty, we are disabling setup
		if (chain.enabled.size() == 1)
		{
			std::unique_lock lock{ hook_lock };
			thread_freezer freeze{ chain, false };
			__alterhook_inject_base_node(chain.backup.data(), false);
		}
		else
		{
			iterator next = std::next(current);
			if (next == chain.enabled.end())
			{
				__alterhook_set_base_node_prelay(poriginal);
				#if !utils_windows64
				std::unique_lock lock{ hook_lock };
				__alterhook_patch_base_node_jmp(poriginal);
				#endif
			}
			else
			{
				next->poriginal = poriginal;
				*next->origwrap = poriginal;
			}
		}

		if (current != chain.enabled.begin())
		{
			iterator prev = std::prev(current);
			if (!prev->has_other)
			{
				prev->has_other = true;
				prev->other = current;
			}
		}

		if (target != chain.disabled.begin())
		{
			iterator prev = std::prev(target);
			if (prev->has_other && prev->other == current)
				prev->has_other = false;
		}
		other = new_other;
		has_other = new_has_other;
		enabled = false;
		chain.disabled.splice(target, chain.enabled, current);
	}
}