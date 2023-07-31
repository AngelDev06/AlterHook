/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
	#if utils_arm
	inline constexpr size_t __patch_above_backup_size = sizeof(uint64_t);
	inline constexpr size_t __patch_above_target_offset = sizeof(uint32_t);
	inline constexpr size_t __backup_size = sizeof(uint64_t);
	#endif

	class ALTERHOOK_API trampoline
	{
	public:
		trampoline() {}
		trampoline(std::byte* target) { init(target); }
		trampoline(const trampoline& other);
		trampoline(trampoline&& other) noexcept;
		trampoline& operator=(const trampoline& other);
		trampoline& operator=(trampoline&& other) noexcept;
		~trampoline() noexcept {}

		void init(std::byte* target);
		template <typename fn, typename... types>
		auto invoke(types&&... values) const
		{
			utils_assert(ptrampoline, "trampoline::invoke: attempt to invoke an uninitialized trampoline");
			// for arm we need to add the thumb bit to the trampoline address if needed. (we check if the target has it)
			#if utils_arm
			std::byte* func = reinterpret_cast<uintptr_t>(ptarget) & 1 ?
				reinterpret_cast<std::byte*>(reinterpret_cast<uintptr_t>(ptrampoline.get()) | 1)
				: ptrampoline.get();
			#else
			std::byte* func = ptrampoline.get();
			#endif
			return std::invoke(function_cast<fn>(func), std::forward<types>(values)...);
		}
		std::byte* get_target() const noexcept { return ptarget; }
		size_t size() const noexcept { return tramp_size; }
		size_t count() const noexcept { return positions.size(); }
		std::string str() const;
	protected:
		#ifdef __alterhook_expose_impl
		friend void process_frozen_threads(const trampoline& tramp, bool enable_hook, unsigned long& pc);
		#endif
		friend class hook_chain;
		struct deleter
		{
			constexpr deleter() noexcept = default;
			constexpr deleter(const deleter&) noexcept {}
			void operator()(std::byte* ptrampoline) const noexcept;
		};
		typedef std::unique_ptr<std::byte, deleter> trampoline_ptr;
		std::byte* ptarget = nullptr;
		trampoline_ptr ptrampoline{};
		#if utils_windows64
		std::byte* prelay = nullptr;
		#elif utils_arm
		std::bitset<8> instruction_sets{};
		#endif
		bool patch_above = false;
		size_t tramp_size = 0;
		#if utils_arm
		std::pair<bool, uint8_t> pc_handling{};
		#endif
		#if !utils_windows
		int old_protect = 0;
		#endif
		utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions{};
	};

	class ALTERHOOK_API hook final : trampoline
	{
	public:
		template <__alterhook_must_be_callable_t dtr, __alterhook_must_be_fn_t orig __alterhook_fn_callable_sfinae_templ>
		hook(std::byte* target, dtr&& detour, orig& original, bool enable_hook = true);

		template <__alterhook_must_be_callable_t dtr __alterhook_callable_sfinae_templ>
		hook(std::byte* target, dtr&& detour, bool enable_hook = true);

		template <__alterhook_must_be_callable_t trg, __alterhook_must_be_callable_t dtr, __alterhook_must_be_fn_t orig __alterhook_fn_callable2_sfinae_templ>
		hook(trg&& target, dtr&& detour, orig& original, bool enable_hook = true);

		template <__alterhook_must_be_callable_t trg, __alterhook_must_be_callable_t dtr __alterhook_callable2_sfinae_templ>
		hook(trg&& target, dtr&& detour, bool enable_hook = true);

		hook(const hook& other);
		hook(hook&& other) noexcept;
		hook(const trampoline& tramp) : trampoline(tramp) {}
		hook(trampoline&& tramp) noexcept : trampoline(std::move(tramp)) {}
		hook() {}
		~hook() noexcept;

		hook& operator=(const hook& other);
		hook& operator=(hook&& other) noexcept;

		void enable();
		void disable();

		using trampoline::get_target;
		const std::byte* get_detour() const { return pdetour; }
		size_t trampoline_size() const { return size(); }
		size_t trampoline_count() const { return count(); }
		std::string trampoline_str() const { return str(); }
		bool is_enabled() const { return enabled; }
		operator bool() const { return enabled; }

		void set_target(std::byte* target);
		template <__alterhook_must_be_callable_t trg __alterhook_callable_trg_sfinae_templ>
		void set_target(trg&& target) { set_target(get_target_address(std::forward<trg>(target))); }
		template <__alterhook_must_be_callable_t dtr __alterhook_callable_sfinae_templ>
		void set_detour(dtr&& detour);
		template <__alterhook_must_be_fn_t orig __alterhook_fn_sfinae_templ>
		void set_original(orig& original);
		void set_original(std::nullptr_t);
	private:
		#if !utils_windows64
		const std::byte* pdetour = nullptr;
		#endif
		bool enabled = false;
		std::array<std::byte, __backup_size> backup{};
		helpers::orig_buff_t original_buffer{};
		helpers::original* original_wrap = nullptr;

		void set_detour(std::byte* detour);
	};

	class ALTERHOOK_API hook_chain final : trampoline
	{
	public:
		class ALTERHOOK_API hook;

		void enable_all();
		void disable_all();
	private:
		uintptr_t* base = nullptr;
		std::array<std::byte, __backup_size> backup{};
		std::list<hook> disabled{};
		std::list<hook> enabled{};

		template <typename detour_t, typename original_t, size_t... d_indexes, size_t... o_indexes, typename... types>
		void init_chain(
			std::index_sequence<d_indexes...>,
			std::index_sequence<o_indexes...>,
			std::tuple<detour_t, original_t, types...>&& args
		);
		void init_chain();
	};

	class ALTERHOOK_API hook_chain::hook
	{
	public:
		void enable();
		void disable();

		std::byte* get_target() const { return chain.ptarget; }
		const std::byte* get_detour() const { return pdetour; }
		bool is_enabled() const { return enabled; }
		operator bool() const { return enabled; }
	private:
		friend class hook_chain;
		typedef std::list<hook>::iterator iterator;
		iterator current{};
		iterator other{};
		hook_chain& chain;
		std::byte* pdetour = nullptr;
		std::byte* poriginal = nullptr;
		helpers::orig_buff_t origbuff{};
		helpers::original* origwrap = nullptr;
		bool enabled = false;
		bool has_other = false;

		template <typename orig>
		hook(hook_chain& chain, std::byte* pdetour, std::byte* poriginal, orig& original);
	};

	/*
	* TEMPLATE DEFINITIONS (ignore them)
	*/
	template <__alterhook_must_be_callable_t dtr, __alterhook_must_be_fn_t orig __alterhook_fn_callable_sfinae_nd_templ>
	hook::hook(std::byte* target, dtr&& detour, orig& original, bool enable_hook) : trampoline(target)
	{
		helpers::assert_valid_detour_original_pair<dtr, orig>();
		__alterhook_def_thumb_var(target);
		new (&original_buffer) helpers::original_wrapper(original);
		original_wrap = std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
		__alterhook_make_backup();
		__alterhook_set_dtr(get_target_address(std::forward<dtr>(detour)));
		original = function_cast<orig>(__alterhook_add_thumb_bit(ptrampoline.get()));
		utils_assert(target != pdetour, "hook::hook: detour & target have the same address");
		if (enable_hook)
			enable();
	}

	template <__alterhook_must_be_callable_t dtr __alterhook_callable_sfinae_nd_templ>
	hook::hook(std::byte* target, dtr&& detour, bool enable_hook) : trampoline(target)
	{
		__alterhook_make_backup();
		__alterhook_set_dtr(get_target_address(std::forward<dtr>(detour)));
		utils_assert(target != pdetour, "hook::hook: detour & target have the same address");
		if (enable_hook)
			enable();
	}

	template <__alterhook_must_be_callable_t trg, __alterhook_must_be_callable_t dtr, __alterhook_must_be_fn_t orig __alterhook_fn_callable2_sfinae_nd_templ>
	hook::hook(trg&& target, dtr&& detour, orig& original, bool enable_hook)
		: hook(get_target_address(std::forward<trg>(target)), std::forward<dtr>(detour), original, enable_hook) {}

	template <__alterhook_must_be_callable_t trg, __alterhook_must_be_callable_t dtr __alterhook_callable2_sfinae_nd_templ>
	hook::hook(trg&& target, dtr&& detour, bool enable_hook)
		: hook(get_target_address(std::forward<trg>(target)), std::forward<dtr>(detour), enable_hook) {}

	template <__alterhook_must_be_callable_t dtr __alterhook_callable_sfinae_nd_templ>
	void hook::set_detour(dtr&& detour) { set_detour(get_target_address(std::forward<dtr>(detour))); }

	template <__alterhook_must_be_fn_t orig __alterhook_fn_sfinae_nd_templ>
	void hook::set_original(orig& original)
	{
		const bool should_enable = enabled;
		__alterhook_def_thumb_var(ptarget);
		if (enabled)
			disable();
		if (original_wrap)
			*original_wrap = nullptr;
		new (&original_buffer) helpers::original_wrapper(original);
		original_wrap = std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
		original = function_cast<orig>(__alterhook_add_thumb_bit(ptrampoline.get()));
		if (should_enable)
			enable();
	}

	template <typename detour_t, typename original_t, size_t... d_indexes, size_t... o_indexes, typename... types>
	void hook_chain::init_chain(
		std::index_sequence<d_indexes...>,
		std::index_sequence<o_indexes...>,
		std::tuple<detour_t, original_t, types...>&& args
	)
	{
		typedef utils::type_sequence<detour_t, original_t, types...> seq;
		typedef utils::clean_type_t<detour_t> cdetour_t;
		typedef utils::clean_type_t<original_t> coriginal_t;
		static_assert(
			((
				std::is_same_v<utils::fn_return_t<cdetour_t>, utils::fn_return_t<utils::clean_type_t<utils::type_at_t<d_indexes, seq>>>> &&
				std::is_same_v<utils::fn_return_t<coriginal_t>, utils::fn_return_t<utils::clean_type_t<utils::type_at_t<o_indexes, seq>>>>
			) && ...) &&
			std::is_same_v<utils::fn_return_t<cdetour_t>, utils::fn_return_t<coriginal_t>>,
			"The return types of the detours and the original function need to be the same"
		);
		#if utils_cc_assertions
		// TODO
		#endif
		static_assert(
			((
				utils::compatible_function_arguments_with<
					utils::clean_type_t<utils::type_at_t<d_indexes, seq>>,
					utils::clean_type_t<utils::type_at_t<o_indexes, seq>>
				> &&
				utils::compatible_function_arguments_with<utils::clean_type_t<utils::type_at_t<d_indexes, seq>>, coriginal_t>
			) && ...) &&
			utils::compatible_function_arguments_with<cdetour_t, coriginal_t>
		);
		__alterhook_def_thumb_var(ptarget);
		__alterhook_make_backup();
		hook& fentry = enabled.emplace_back(
			*this,
			get_target_address(std::forward<detour_t>(std::get<0>(args))),
			__alterhook_add_thumb_bit(ptrampoline.get()),
			std::get<1>(args)
		);
		fentry.enabled = true;
		fentry.current = enabled.begin();
		if constexpr (sizeof...(types))
		{
			hook::iterator iter = enabled.begin();
			hook& entry = fentry;
			(
				(
					entry = enabled.emplace_back(
						*this,
						get_target_address(std::forward<utils::type_at_t<d_indexes, seq>>(std::get<d_indexes>(args))),
						entry.pdetour,
						std::get<o_indexes>(args)
					),
					entry.current = ++iter,
					entry.enabled = true
				), ...
			);
		}
		init_chain();
	}

	template <typename orig>
	hook_chain::hook::hook(hook_chain& chain, std::byte* pdetour, std::byte* poriginal, orig& original)
		: chain(chain), pdetour(pdetour), poriginal(poriginal)
	{
		new (&origbuff) helpers::original_wrapper(original);
		origwrap = std::launder(reinterpret_cast<helpers::original*>(&origbuff));
		original = function_cast<orig>(poriginal);
	}
}
