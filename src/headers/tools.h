/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
	ALTERHOOK_API bool is_executable_address(const void* address);

	namespace helpers
	{
		template <typename dtr, typename orig>
		utils_consteval void assert_valid_detour_original_pair()
		{
			typedef utils::clean_type_t<dtr> detour_type;
			typedef utils::clean_type_t<fn_storage> storage_type;
			static_assert(
				std::is_same_v<utils::fn_return_t<detour_type>, utils::fn_return_t<storage_type>>,
				"The return type of the detour and the original function need to be the same"
			);
			#if utils_cc_assertions
			static_assert(
				utils::compatible_calling_convention_with<detour_type, storage_type>,
				"The calling conventions of the detour and the original function need to be compatible"
			);
			#endif
			static_assert(
				utils::compatible_function_arguments_with<detour_type, storage_type>,
				"The arguments the detour accepts aren't compatible with the original function"
			);
		}
	}

	#if utils_cpp20
	template <utils::callable_type T> requires(!utils::stl_function_type<T>)
	constexpr void* get_target_address(T&& fn) noexcept
	#else
	template <typename T>
	constexpr std::enable_if_t<utils::callable_type<T> && !utils::stl_function_type<T>, void*> get_target_address(T&& fn) noexcept
	#endif
	{
		typedef utils::remove_cvref_t<T> fn_t;
		if constexpr (utils::member_function_type<fn_t>)
			return reinterpret_cast<void*>(addresser::address_of(fn));
		else if constexpr (utils::fn_object_v<fn_t>)
			return reinterpret_cast<void*>(addresser::address_of(&fn_t::operator()));
		else
			return static_cast<void*>(fn);
	}

	#if utils_cpp20
	template <utils::function_type T>
	auto function_cast(void* address) noexcept
	#else
	template <typename T>
	auto function_cast(std::enable_if_t<utils::function_type<T>, void*> address) noexcept
	#endif
	{
		typedef utils::remove_cvref_t<T> fn_t;
		if constexpr (utils::member_function_type<fn_t>)
		{
			T val{ nullptr };
			reinterpret_cast<void*&>(val) = address;
			return val;
		}
		else if constexpr (std::is_function_v<utils::clean_type_t<T>>)
			return reinterpret_cast<std::add_pointer_t<T>>(address);
		else
			return reinterpret_cast<utils::unwrap_stl_function_t<fn_t>>(address);
	}

	namespace helpers
	{
		#if utils_cc_assertions
		#if utils_cpp20
		template <utils::calling_convention CC, utils::non_capturing_lambda T>
		HG_NODISCARD inline constexpr auto lambda_calling_convention(T&& obj) noexcept
		#else
		template <utils::calling_convention CC, typename T, std::enable_if_t<utils::non_capturing_lambda<T>, size_t> = 0>
		HG_NODISCARD inline constexpr auto lambda_calling_convention(T&& obj) noexcept
		#endif
		{
			typedef utils::helpers::lambda_to_fn_t<utils::helpers::call_overload_t<utils::remove_cvref_t<T>>> fn_type;
			typedef std::add_pointer_t<utils::add_calling_convention_t<CC, fn_type>> final_fn_type;
			return static_cast<final_fn_type>(obj);
		}
		#endif
	}
}