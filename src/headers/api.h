/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "tools.h"

namespace alterhook
{
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
	private:
		friend class hook;
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
		#endif
		bool patch_above = false;
		size_t tramp_size = 0;
		utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions{};
	};
}
