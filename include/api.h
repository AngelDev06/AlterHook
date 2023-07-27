/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if utils_cpp20
	#define __alterhook_must_be_fn_t utils::function_type
	#define __alterhook_must_be_callable_t utils::callable_type
	#define __alterhook_fn_callable_sfinae_templ
	#define __alterhook_callable_sfinae_templ
	#define __alterhook_fn_callable2_sfinae_templ
	#define __alterhook_callable2_sfinae_templ
#else
	#define __alterhook_must_be_fn_t typename
	#define __alterhook_must_be_callable_t typename
	#define __alterhook_fn_callable_sfinae_templ , std::enable_if_t<utils::callable_type<dtr> && utils::function_type<orig>, size_t> = 0
	#define __alterhook_callable_sfinae_templ , std::enable_if_t<utils::callable_type<dtr>, size_t> = 0
	#define __alterhook_fn_callable2_sfinae_templ \
		, std::enable_if_t<utils::callable_type<trg> && utils::callable_type<dtr> && utils::function_type<orig>, size_t> = 0
	#define __alterhook_callable2_sfinae_templ , std::enable_if_t<utils::callable_type<trg> && utils::callable_type<dtr>, size_t> = 0
#endif
#if !utils_windows64
	#define __alterhook_set_dtr(dtr) pdetour = dtr
	#define __alterhook_get_dtr() pdetour
	#define __alterhook_get_real_dtr() pdetour
	#define __alterhook_copy_dtr(other) pdetour = other.pdetour
	#define __alterhook_exchange_dtr(other) pdetour = std::exchange(other.pdetour, nullptr)
#endif
#if utils_arm
	#define __alterhook_make_backup() \
		do \
		{ \
			const auto target_addr = reinterpret_cast<std::byte*>(reinterpret_cast<uintptr_t>(target) & ~1); \
			size_t copy_size = reinterpret_cast<uintptr_t>(target_addr) % 4 ? sizeof(uint64_t) + 2 : sizeof(uint64_t); \
			if (patch_above) \
				memcpy(backup.data(), target_addr - __patch_above_target_offset, __patch_above_backup_size); \
			else \
				memcpy(backup.data(), target_addr, copy_size); \
		} while (false)
	#define __alterhook_def_thumb_var(address) const bool thumb = reinterpret_cast<uintptr_t>(address) & 1
	#define __alterhook_add_thumb_bit(address) reinterpret_cast<std::byte*>(reinterpret_cast<uintptr_t>(address) | thumb)
#endif

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
		~trampoline() {}

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

	class ALTERHOOK_API hook final : public trampoline
	{
	public:
		template <__alterhook_must_be_callable_t dtr, __alterhook_must_be_fn_t orig __alterhook_fn_callable_sfinae_templ>
		hook(std::byte* target, dtr&& detour, orig& original, bool enable_hook = true) : trampoline(target)
		{
			helpers::assert_valid_detour_original_pair<dtr, orig>();
			__alterhook_def_thumb_var(target);
			new (&original_buffer) helpers::original_wrapper(original);
			original_wrap = std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
			__alterhook_make_backup();
			__alterhook_set_dtr(get_target_address(std::forward<dtr>(detour)));
			original = function_cast<orig>(__alterhook_add_thumb_bit(ptrampoline.get()));
			if (enable_hook)
				enable();
		}
		template <__alterhook_must_be_callable_t dtr __alterhook_callable_sfinae_templ>
		hook(std::byte* target, dtr&& detour, bool enable_hook = true) : trampoline(target)
		{
			__alterhook_make_backup();
			__alterhook_set_dtr(get_target_address(std::forward<dtr>(detour)));
			utils_assert(target != pdetour, "hook::hook: detour & target have the same address");
			if (enable_hook)
				enable();
		}
		template <__alterhook_must_be_callable_t trg, __alterhook_must_be_callable_t dtr, __alterhook_must_be_fn_t orig __alterhook_fn_callable2_sfinae_templ>
		hook(trg&& target, dtr&& detour, orig& original, bool enable_hook = true)
			: hook(static_cast<std::byte*>(get_target_address(std::forward<trg>(target))), std::forward<dtr>(detour), original, enable_hook) {}
		template <__alterhook_must_be_callable_t trg, __alterhook_must_be_callable_t dtr __alterhook_callable2_sfinae_templ>
		hook(trg&& target, dtr&& detour, bool enable_hook = true)
			: hook(static_cast<std::byte*>(get_target_address(std::forward<trg>(target))), std::forward<dtr>(detour), enable_hook) {}

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
	private:
		#if !utils_windows64
		const std::byte* pdetour = nullptr;
		#endif
		bool enabled = false;
		std::array<std::byte, __backup_size> backup{};
		helpers::orig_buff_t original_buffer{};
		helpers::original* original_wrap = nullptr;
	};
}
