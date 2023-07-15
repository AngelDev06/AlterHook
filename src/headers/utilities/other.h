/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <utility>
#include <cassert>
#include "utils_macros.h"
#define utils_assert(expr, msg) assert(((void)msg, expr))

namespace utils
{
	template <typename T>
	inline constexpr bool is_cv_v = false;
	template <typename T>
	inline constexpr bool is_cv_v<const volatile T> = true;
	template <typename T>
	struct is_cv
	{
		static constexpr bool value = is_cv_v<T>;
	};

	template <typename T>
	utils_concept cv_qualified = std::is_const_v<T> || std::is_volatile_v<T> || is_cv_v<T>;

	template <typename T1, typename T2>
	inline constexpr bool same_cv_qualification_v = !cv_qualified<T1> && !cv_qualified<T2>;
	template <typename T1, typename T2>
	inline constexpr bool same_cv_qualification_v<const T1, const T2> = true;
	template <typename T1, typename T2>
	inline constexpr bool same_cv_qualification_v<volatile T1, volatile T2> = true;
	template <typename T1, typename T2>
	inline constexpr bool same_cv_qualification_v<const volatile T1, const volatile T2> = true;

	template <typename T1, typename T2>
	struct same_cv_qualification
	{
		static constexpr bool value = same_cv_qualification_v<T1, T2>;
	};

	namespace helpers
	{
		// I remade std::make_index_sequence because I wanted a specific range of indexes 
		template <size_t start, typename seq, size_t end>
		struct make_index_sequence_impl;
		template <size_t start, size_t... indexes, size_t end>
		struct make_index_sequence_impl<start, std::index_sequence<indexes...>, end>
			: make_index_sequence_impl<start + 1, std::index_sequence<indexes..., start>, end> {};
		template <size_t end, size_t... indexes>
		struct make_index_sequence_impl<end, std::index_sequence<indexes...>, end>
		{
			typedef std::index_sequence<indexes...> type;
		};
	}

	template <size_t end, size_t start = 0>
	struct make_index_sequence : helpers::make_index_sequence_impl<start, std::index_sequence<>, end>
	{
		static_assert(start <= end, "utils::make_index_sequence<end, start>: invalid parameters");
	};
	template <size_t end, size_t start = 0>
	using make_index_sequence_t = typename make_index_sequence<end, start>::type;

	namespace helpers
	{
		template <typename seq, size_t begin, size_t end, size_t step>
		struct index_seq_step_impl;
		template <size_t... indexes, size_t begin, size_t end, size_t step>
		struct index_seq_step_impl<std::index_sequence<indexes...>, begin, end, step> : index_seq_step_impl<std::index_sequence<indexes..., begin>, begin + step, end, step> {};
		template <size_t... indexes, size_t end, size_t step>
		struct index_seq_step_impl<std::index_sequence<indexes...>, end, end, step>
		{
			typedef std::index_sequence<indexes...> type;
		};
	}

	template <size_t end, size_t begin = 0, size_t step = 2>
	using make_index_sequence_with_step = typename helpers::index_seq_step_impl<std::index_sequence<>, begin, end + (begin % step), step>::type;

	#if !utils_cpp20
	template <typename T>
	using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;
	#else
	template <typename T>
	using remove_cvref_t = std::remove_cvref_t<T>;
	#endif

	template <typename... types>
	utils_concept always_false = false;

	template <typename... types>
	struct undefined_struct;

	template <typename... types>
	struct overloaded : types... { using types::operator()...; };
	template <typename... types>
	overloaded(types...) -> overloaded<types...>;
}
