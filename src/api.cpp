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
		inject_to_target(pchain->ptarget, backup_or_detour, pchain->patch_above, enable, pchain->old_protect)
	#define __alterhook_patch_jmp(detour) \
		patch_jmp(ptarget, detour, patch_above, old_protect)
	#define __alterhook_patch_base_node_jmp(detour) \
		patch_jmp(pchain->ptarget, detour, pchain->patch_above, pchain->old_protect)
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

	hook_chain::hook_chain(alterhook::hook&& other) : trampoline(std::move(other))
	{
		memcpy(backup.data(), other.backup.data(), backup.size());
		__alterhook_def_thumb_var(ptarget);
		hook::iterator itr = disabled.emplace(disabled.end());
		itr->init(*this, itr, other.pdetour, __alterhook_add_thumb_bit(ptrampoline.get()), other.original_buffer);
	}

	hook_chain::hook_chain(const hook_chain& other)
		: trampoline(other)
	{
		memcpy(backup.data(), other.backup.data(), backup.size());
		for (const hook& h : other)
		{
			hook::iterator itr = disabled.emplace(disabled.end());
			itr->init(*this, itr, h.pdetour, h.poriginal, h.origbuff);
		}
	}

	hook_chain::hook_chain(hook_chain&& other) noexcept
		: trampoline(std::move(other)), disabled(std::move(other.disabled)), enabled(std::move(other.enabled)), starts_enabled(other.starts_enabled)
	{
		for (hook& h : *this)
			h.pchain = this;
	}

	hook_chain::~hook_chain() noexcept
	try
	{
		clear();
	} catch (...) {}

	void hook_chain::init_chain()
	{
		std::unique_lock lock{ hook_lock };
		thread_freezer freeze{ *this, true };
		__alterhook_inject(enabled.back().pdetour, true);
	}

	void hook_chain::clear()
	{
		if (empty())
			return;
		if (!enabled.empty())
		{
			std::unique_lock lock{ hook_lock };
			thread_freezer freeze{ *this, false };
			__alterhook_inject(backup.data(), false);
		}
		enabled.clear();
		disabled.clear();
		starts_enabled = false;
	}

	void hook_chain::enable_all()
	{
		if (disabled.empty())
			return;
		if (enabled.empty())
		{
			reverse_list_iterator rbegin = disabled.rbegin();
			__alterhook_def_thumb_var(ptarget);
			rbegin->poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
			*rbegin->origwrap = rbegin->poriginal;
			{
				std::unique_lock lock{ hook_lock };
				thread_freezer freeze{ *this, true };
				__alterhook_inject(rbegin->pdetour, true);
			}
			rbegin->enabled = true;

			for (auto prev = rbegin, itr = std::next(rbegin), enditr = disabled.rend(); itr != enditr; ++itr, ++prev)
			{
				itr->enabled = true;
				itr->poriginal = prev->poriginal;
				*itr->origwrap = prev->poriginal;
				prev->poriginal = itr->pdetour;
				*prev->origwrap = itr->pdetour;
			}
			enabled.splice(enabled.begin(), disabled);
		}
		else
		{
			hook::iterator previtr = std::prev(disabled.end());
			hook& dlast = *previtr;
			// if disabled doesn't have other then we got to touch the target
			if (!dlast.has_other)
			{
				hook& elast = enabled.back();
				dlast.poriginal = elast.pdetour;
				*dlast.origwrap = elast.pdetour;
				dlast.enabled = true;
				elast.has_other = false;
				__alterhook_set_base_node_prelay(dlast.pdetour);
				#if !utils_windows64
				std::unique_lock lock{ hook_lock };
				__alterhook_patch_jmp(dlast.pdetour);
				#endif
				enabled.splice(enabled.end(), disabled, previtr);
			}

			while (!disabled.empty())
			{
				hook::iterator curritr = std::prev(disabled.end());
				hook::iterator trgitr = previtr;
				hook& curr = *curritr;
				
				if (curr.has_other)
				{
					if (curr.other != enabled.begin())
						std::prev(curr.other)->has_other = false;
					trgitr = curr.other;
					curr.has_other = false;
				}

				hook& trg = *trgitr;
				curr.poriginal = trg.poriginal;
				*curr.origwrap = trg.poriginal;
				trg.poriginal = curr.pdetour;
				*trg.origwrap = curr.pdetour;
				curr.enabled = true;
				enabled.splice(trgitr, disabled, curritr);
				previtr = curritr;
			}
		}
	}

	void hook_chain::disable_all()
	{
		if (enabled.empty())
			return;

		{
			std::unique_lock lock{ hook_lock };
			thread_freezer freeze{ *this, false };
			__alterhook_inject(backup.data(), false);
		}

		hook::iterator previtr = disabled.end();
		while (!enabled.empty())
		{
			hook::iterator curritr = std::prev(enabled.end());
			hook::iterator trgitr = previtr;
			hook& curr = *curritr;

			if (curr.has_other)
			{
				if (curr.other != disabled.begin())
					std::prev(curr.other)->has_other = false;
				trgitr = curr.other;
				curr.has_other = false;
			}

			curr.enabled = false;
			disabled.splice(trgitr, enabled, curritr);
			previtr = curritr;
		}
	}

	void hook_chain::hook::enable()
	{
		utils_assert(pchain->ptarget != pdetour, "hook_chain::hook::enable: target & detour have the same address");
		if (enabled)
			return;
		iterator target{};
		// re-setup if empty
		if (pchain->enabled.empty())
		{
			{
				__alterhook_def_thumb_var(pchain->ptarget);
				poriginal = __alterhook_add_thumb_bit(pchain->ptrampoline.get());
				*origwrap = poriginal;
				std::unique_lock lock{ hook_lock };
				thread_freezer freeze{ *pchain, true };
				__alterhook_set_base_node_prelay(pdetour);
				__alterhook_inject_base_node(__alterhook_get_real_dtr(), true);
			}
			other = std::next(current);
			has_other = other != pchain->disabled.end();
			target = pchain->enabled.end();
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
				new_has_other = result != pchain->disabled.end();
				while (result != pchain->disabled.end() && !result->has_other)
					++result;
				target = result == pchain->disabled.end() ? pchain->enabled.end() : result->other;
			}
			else
				target = other;
			
			if (target == pchain->enabled.end())
			{
				poriginal = pchain->enabled.back().pdetour;
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
		if (current != pchain->disabled.begin())
		{
			iterator prev = std::prev(current);
			if (!prev->has_other)
			{
				prev->has_other = true;
				prev->other = current;
			}
		}
		else
			pchain->starts_enabled = true;

		// remove other on new prev if needed
		if (target != pchain->enabled.begin())
		{
			iterator prev = std::prev(current);
			if (prev->has_other && prev->other == current)
				prev->has_other = false;
		}
		enabled = true;
		pchain->enabled.splice(target, pchain->disabled, current);
	}

	void hook_chain::hook::disable()
	{
		if (!enabled)
			return;
		iterator target{};
		iterator new_other{};
		bool new_has_other = false;
		if (pchain->disabled.empty())
		{
			new_other = std::next(current);
			new_has_other = other != pchain->enabled.end();
			target = pchain->disabled.end();
		}
		else if (!has_other)
		{
			iterator result = std::next(current);
			new_other = result;
			new_has_other = other != pchain->enabled.end();
			while (result != pchain->enabled.end() && !result->has_other)
				++result;
			target = result == pchain->enabled.end() ? pchain->disabled.end() : result->other;
		}
		else
			target = other;

		// if enabled list is going to be left empty, we are disabling setup
		if (pchain->enabled.size() == 1)
		{
			std::unique_lock lock{ hook_lock };
			thread_freezer freeze{ *pchain, false };
			__alterhook_inject_base_node(pchain->backup.data(), false);
		}
		else
		{
			iterator next = std::next(current);
			if (next == pchain->enabled.end())
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

		if (current != pchain->enabled.begin())
		{
			iterator prev = std::prev(current);
			if (!prev->has_other)
			{
				prev->has_other = true;
				prev->other = current;
			}
		}
		else
			pchain->starts_enabled = false;

		if (target != pchain->disabled.begin())
		{
			iterator prev = std::prev(target);
			if (prev->has_other && prev->other == current)
				prev->has_other = false;
		}
		other = new_other;
		has_other = new_has_other;
		enabled = false;
		pchain->disabled.splice(target, pchain->enabled, current);
	}
}