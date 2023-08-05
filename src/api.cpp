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
	#define __alterhook_inject_other(other, backup_or_detour, enable) \
		inject_to_target(other.ptarget, backup_or_detour, other.patch_above, enable, other.old_protect)
	#define __alterhook_inject_base_node(backup_or_detour, enable) \
		inject_to_target(pchain->ptarget, backup_or_detour, pchain->patch_above, enable, pchain->old_protect)
	#define __alterhook_patch_jmp(detour) \
		patch_jmp(ptarget, detour, patch_above, old_protect)
	#define __alterhook_patch_other_jmp(other, detour) \
		patch_jmp(other.ptarget, detour, other.patch_above, other.old_protect)
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
		const bool should_enable = enabled;
		if (enabled)
			disable();
		init(target);
		__alterhook_make_backup();
		if (should_enable)
			enable();
	}

	void hook::set_detour(std::byte* detour)
	{
		if (detour == pdetour)
			return;
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
		memcpy(backup.data(), other.backup.data(), backup.size());
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

	hook_chain& hook_chain::operator=(const hook_chain& other)
	{
		if (this != &other)
		{
			disable_all();
			trampoline::operator=(other);
			starts_enabled = false;
			memcpy(backup.data(), other.backup.data(), backup.size());

			if (size() >= other.size())
			{
				auto thisitr = disabled.begin();
				for (auto otheritr = other.begin(), otherend = other.end(); otheritr != otherend; ++otheritr, ++thisitr)
				{
					thisitr->pdetour = otheritr->pdetour;
					thisitr->origbuff = otheritr->origbuff;
				}
				disabled.erase(thisitr, disabled.end());
			}
			else
			{
				auto otheritr = other.begin();
				for (auto thisitr = disabled.begin(), thisend = disabled.end(); thisitr != thisend; ++thisitr, ++otheritr)
				{
					thisitr->pdetour = otheritr->pdetour;
					thisitr->origbuff = otheritr->origbuff;
				}
				for (auto otherend = other.end(); otheritr != otherend; ++otheritr)
				{
					auto itr = disabled.emplace(disabled.end());
					itr->init(*this, itr, otheritr->pdetour, otheritr->origbuff);
				}
			}
		}
		return *this;
	}

	hook_chain& hook_chain::operator=(hook_chain&& other) noexcept
	{
		if (this != &other)
		{
			if (!enabled.empty()) try
			{
				std::unique_lock lock{ hook_lock };
				thread_freezer freeze{ *this, false };
				__alterhook_inject(backup.data(), false);
			} catch (...) {}
			trampoline::operator=(std::move(other));
			disabled = std::move(other.disabled);
			enabled = std::move(other.enabled);
			starts_enabled = other.starts_enabled;

			for (hook& h : *this)
				h.pchain = this;
		}
		return *this;
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
		starts_enabled = true;
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

		if (!disabled.empty())
			disabled.back().has_other = false;
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

	void hook_chain::splice(list_iterator newpos, hook_chain& other, list_iterator oldpos)
	{
		auto oldnext = std::next(oldpos);
		if (&other == this && (newpos == oldpos || oldnext == newpos))
			return;
		utils_assert(oldpos != other.disabled.end() && oldpos != other.enabled.end(), "hook_chain::splice: oldpos can't be the end iterator");

		// covers transfer from enabled
		bool should_handle = false;
		if (oldpos->enabled)
		{
			// covers transfer from enabled end
			if (oldnext == other.enabled.end())
			{
				std::unique_lock lock{ hook_lock };
				if (other.enabled.size() == 1)
				{
					thread_freezer freeze{ other, false };
					__alterhook_inject_other(other, other.backup.data(), false);
				}
				else
					__alterhook_patch_other_jmp(other, oldpos->poriginal);
			}
			else
			{
				oldnext->poriginal = oldpos->poriginal;
				*oldnext->origwrap = oldpos->poriginal;
			}
			should_handle = true;
		}

		// covers transfer to enabled end
		if (newpos == enabled.end())
		{
			try
			{
				std::unique_lock lock{ hook_lock };
				if (enabled.empty())
				{
					__alterhook_def_thumb_var(ptarget);
					oldpos->poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
					*oldpos->origwrap = oldpos->poriginal;
					thread_freezer freeze{ *this, true };
					__alterhook_inject(oldpos->pdetour, true);
				}
				else
				{
					hook& elast = enabled.back();
					oldpos->poriginal = elast.pdetour;
					*oldpos->origwrap = elast.pdetour;
					__alterhook_patch_jmp(oldpos->pdetour);
				}
			}
			catch (...)
			{
				// provide strong guarantee
				// so we attempt to rebind the old node back to where it was before exiting
				if (should_handle)
				{
					if (oldnext == other.enabled.end())
					{
						// if an attempt to rebind old at enabled end fails with exception
						// then provide basic guarantee by disabling the old one
						try
						{
							std::unique_lock lock{ hook_lock };
							if (other.enabled.size() == 1)
							{
								__alterhook_def_thumb_var(other.ptarget);
								oldpos->poriginal = __alterhook_add_thumb_bit(other.ptrampoline.get());
								*oldpos->origwrap = oldpos->poriginal;
								thread_freezer freeze{ other, true };
								__alterhook_inject_other(other, oldpos->pdetour, true);
							}
							else
							{
								hook& elast = other.enabled.back();
								oldpos->poriginal = elast.pdetour;
								*oldpos->origwrap = elast.pdetour;
								__alterhook_patch_other_jmp(other, oldpos->pdetour);
							}
						}
						catch (...)
						{
							if (oldpos != other.enabled.begin())
							{
								auto oldprev = std::prev(oldpos);
								if (!oldprev->has_other)
								{
									oldprev->has_other = true;
									oldprev->other = oldpos;
								}
							}
							else
								other.starts_enabled = false;

							if (!other.disabled.empty())
							{
								hook& dlast = other.disabled.back();
								if (dlast.has_other && dlast.other == oldpos)
									dlast.has_other = false;
							}

							list_iterator target = other.disabled.end();
							if (oldpos->has_other)
							{
								oldpos->has_other = false;
								target = oldpos->other;
							}

							oldpos->enabled = false;
							other.disabled.splice(target, other.enabled, oldpos);
							throw;
						}
					}
					else
					{
						oldpos->poriginal = oldnext->poriginal;
						*oldpos->origwrap = oldnext->poriginal;
						oldnext->poriginal = oldpos->pdetour;
						*oldnext->origwrap = oldpos->pdetour;
					}
				}
				throw;
			}
		}
		// covers transfer to enabled
		else if (newpos != disabled.end() && newpos->enabled)
		{
			oldpos->poriginal = newpos->poriginal;
			*oldpos->origwrap = newpos->poriginal;
			newpos->poriginal = oldpos->pdetour;
			*newpos->origwrap = oldpos->pdetour;
		}

		bool should_search = false;
		bool extra_check = false;
		list_iterator oldsearchitr{};

		if (oldpos == other.enabled.begin())
		{
			if (!other.starts_enabled)
			{
				oldsearchitr = other.disabled.begin();
				should_search = true;
				extra_check = oldpos->has_other || oldnext == other.enabled.end();
			}
			else if (oldpos->has_other)
				other.starts_enabled = false;
		}
		else if (oldpos == other.disabled.begin())
		{
			if (other.starts_enabled)
			{
				oldsearchitr = other.enabled.begin();
				should_search = true;
				extra_check = oldpos->has_other || oldnext == other.disabled.end();
			}
			else if (oldpos->has_other)
				other.starts_enabled = true;
		}
		else
		{
			auto oldprev = std::prev(oldpos);
			if (oldprev->has_other)
			{
				oldsearchitr = oldprev->other;
				should_search = true;
				extra_check = oldpos->has_other || oldnext == other.enabled.end() || oldnext == other.disabled.end();
			}
			else if (oldpos->has_other)
			{
				oldprev->has_other = true;
				oldprev->other = oldpos->other;
			}
		}

		if (should_search)
		{
			while (!oldsearchitr->has_other)
				++oldsearchitr;

			if (extra_check)
				oldsearchitr->has_other = false;
			else
				oldsearchitr->other = oldnext;
		}

		list_iterator newsearchitr{};
		enum
		{
			SEARCH, HANDLE_ENABLED_END, HANDLE_DISABLED_END, DO_NOTHING
		} newpos_strategy = DO_NOTHING;

		if (newpos == enabled.begin())
		{
			if (!starts_enabled)
			{
				if (newpos == enabled.end())
					newpos_strategy = HANDLE_ENABLED_END;
				else
				{
					newsearchitr = disabled.begin();
					newpos_strategy = SEARCH;
				}
			}
		}
		else if (newpos == disabled.begin())
		{
			if (starts_enabled)
			{
				if (newpos == disabled.end())
					newpos_strategy = HANDLE_DISABLED_END;
				else
				{
					newsearchitr = enabled.begin();
					newpos_strategy = SEARCH;
				}
			}
		}
		else
		{
			auto newprev = std::prev(newpos);
			if (newprev->has_other)
			{
				if (newpos == enabled.end())
					newpos_strategy = HANDLE_ENABLED_END;
				else if (newpos == disabled.end())
					newpos_strategy = HANDLE_DISABLED_END;
				else
				{
					newsearchitr = newprev->other;
					newpos_strategy = SEARCH;
				}
			}
		}

		switch (newpos_strategy)
		{
		case SEARCH:
			while (!newsearchitr->has_other)
				++newsearchitr;
			newsearchitr->other = oldpos;
			break;
		case HANDLE_ENABLED_END:
		{
			hook& dlast = disabled.back();
			dlast.has_other = true;
			dlast.other = oldpos;
			break;
		}
		case HANDLE_DISABLED_END:
		{
			hook& elast = enabled.back();
			elast.has_other = true;
			elast.other = oldpos;
		}
		}

		oldpos->has_other = false;
		std::list<hook>& to = newpos == enabled.end() || (newpos != disabled.end() && newpos->enabled) ? enabled : disabled;
		std::list<hook>& from = oldpos->enabled ? other.enabled : other.disabled;

		if (&to == &enabled)
			oldpos->enabled = true;
		to.splice(newpos, from, oldpos);
	}

	void hook_chain::splice(list_iterator newpos, hook_chain& other, list_iterator first, list_iterator last)
	{
		if (first == last || (&other == this && newpos == last))
			return;
		if (std::next(first) == last)
			return splice(newpos, other, first);
		utils_assert(first != other.enabled.end() && first != other.disabled.end(), "hook_chain::splice: A range can't start from the end iterator");
		std::list<hook>& to = newpos == enabled.end() || (newpos != disabled.end() && newpos->enabled) ? enabled : disabled;
		std::list<hook>& from = first->enabled ? other.enabled : other.disabled;

		// if we are transfering from disabled to enabled
		// we want to connect the pieces together
		if (&to == &enabled && &from == &other.disabled)
		{
			for (auto prev = first, current = std::next(first); current != last; ++prev, ++current)
			{
				current->poriginal = prev->pdetour;
				*current->origwrap = prev->pdetour;
			}
		}

		// covers transfer from enabled
		bool should_handle = false;
		if (first->enabled)
		{
			// covers transfer from enabled end
			if (last == other.enabled.end())
			{
				std::unique_lock lock{ hook_lock };
				if (first == other.enabled.begin())
				{
					thread_freezer freeze{ other, false };
					__alterhook_inject_other(other, other.backup.data(), false);
				}
				else
					__alterhook_patch_other_jmp(other, first->poriginal);
			}
			else
			{
				last->poriginal = first->poriginal;
				*last->origwrap = first->poriginal;
			}
			should_handle = true;
		}
		auto lastprev = std::prev(last);

		// covers transfer to enabled end
		if (newpos == enabled.end())
		{
			try
			{
				std::unique_lock lock{ hook_lock };
				if (enabled.empty())
				{
					__alterhook_def_thumb_var(ptarget);
					first->poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
					*first->origwrap = first->poriginal;
					thread_freezer freeze{ *this, true };
					__alterhook_inject(lastprev->pdetour, true);
				}
				else
				{
					hook& elast = enabled.back();
					first->poriginal = elast.pdetour;
					*first->origwrap = elast.pdetour;
					__alterhook_patch_jmp(lastprev->pdetour);
				}
			}
			catch (...)
			{
				if (should_handle)
				{
					if (last == other.enabled.end())
					{
						try
						{
							std::unique_lock lock{ hook_lock };
							if (first == other.enabled.begin())
							{
								__alterhook_def_thumb_var(other.ptarget);
								first->poriginal = __alterhook_add_thumb_bit(other.ptrampoline.get());
								*first->origwrap = first->poriginal;
								thread_freezer freeze{ other, true };
								__alterhook_inject_other(other, lastprev->pdetour, true);
							}
							else
							{
								hook& elast = other.enabled.back();
								first->poriginal = elast.pdetour;
								*first->origwrap = elast.pdetour;
								__alterhook_patch_other_jmp(other, lastprev->pdetour);
							}
						}
						catch (...)
						{
							if (first != other.enabled.begin())
							{
								auto firstprev = std::prev(first);
								if (!firstprev->has_other)
								{
									firstprev->has_other = true;
									firstprev->other = first;
								}
							}
							else
								other.starts_enabled = false;
							if (!other.disabled.empty())
								other.disabled.back().has_other = false;

							list_iterator previtr = other.disabled.end();
							do
							{
								auto curritr = std::prev(last);
								auto trgitr = previtr;
								hook& curr = *curritr;

								if (curr.has_other)
								{
									if (curr.other != other.disabled.begin())
										std::prev(curr.other)->has_other = false;
									trgitr = curr.other;
									curr.has_other = false;
								}

								curr.enabled = false;
								other.disabled.splice(trgitr, other.enabled, curritr);
								previtr = curritr;
							} while (first->enabled);

							throw;
						}
					}
					else
					{
						first->poriginal = last->poriginal;
						*first->origwrap = last->poriginal;
						last->poriginal = lastprev->pdetour;
						*last->origwrap = lastprev->pdetour;
					}
				}
				throw;
			}
		}
		// covers transfer to enabled
		else if (newpos != disabled.end() && newpos->enabled)
		{
			first->poriginal = newpos->poriginal;
			*first->origwrap = newpos->poriginal;
			newpos->poriginal = lastprev->pdetour;
			*newpos->origwrap = lastprev->pdetour;
		}

		auto searchbegin = first;
		auto searchend = last;
		auto first_range_switch_pos = first;
		auto last_range_switch_pos = last;
		bool has_search = false;
		bool has_search_begin = false;

		do
		{
			--searchend;
			if (searchend->has_other)
			{
				has_search = true;
				last_range_switch_pos = std::next(searchend);
				searchend = searchend->other;
				while (!searchend->has_other)
					++searchend;
				break;
			}
		} while (searchend != first);

		if (first == other.disabled.begin())
		{
			if (starts_enabled)
			{
				searchbegin = other.enabled.begin();
				has_search_begin = true;
			}
			else if (lastprev->has_other || has_search)
				other.starts_enabled = true;
		}
		else if (first == other.enabled.begin())
		{
			if (!starts_enabled)
			{
				searchbegin = other.disabled.begin();
				has_search_begin = true;
			}
			else if (lastprev->has_other || has_search)
				other.starts_enabled = false;
		}
		else
		{
			auto firstprev = std::prev(first);
			if (firstprev->has_other)
			{
				searchbegin = firstprev->other;
				has_search_begin = true;
			}
			else if (lastprev->has_other || has_search)
			{
				while (!searchbegin->has_other)
					++searchbegin;
				has_search_begin = true;
				first_range_switch_pos = searchbegin;
				searchbegin = searchbegin->other;
				firstprev->has_other = true;
				firstprev->other = searchbegin;
			}
		}

		if (has_search)
		{
			if (!has_search_begin)
			{
				while (!searchbegin->has_other)
					++searchbegin;
				searchbegin = searchbegin->other;
			}

			while (searchbegin != searchend)
			{
				searchbegin->has_other = false;
				++searchbegin;
			}

			if (lastprev->has_other || last == other.enabled.end() || last == other.disabled.end())
				searchbegin->has_other = false;
			else
				searchbegin->other = last;

			while (first_range_switch_pos != last_range_switch_pos)
			{
				first_range_switch_pos->has_other = false;
				++first_range_switch_pos;
			}
		}
		else if (has_search_begin)
		{
			while (!searchbegin->has_other)
				++searchbegin;
			searchbegin->other = last;
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
			new_has_other = new_other != pchain->enabled.end();
			target = pchain->disabled.end();
		}
		else if (!has_other)
		{
			iterator result = std::next(current);
			new_other = result;
			new_has_other = new_other != pchain->enabled.end();
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