/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

#if utils_cpp20
namespace utils
{
	template <char... chars>
	struct template_string
	{
		static constexpr const char data[sizeof...(chars)]{ chars... };
		static constexpr size_t size = sizeof...(chars);
		static constexpr size_t count = size - 1;

		static consteval const char* c_str()
		{
			if constexpr (size == 0)
				return "";
			else if constexpr (data[count] != '\0')
				return template_string<chars..., '\0'>::data;
			else
				return data;
		}
	};

	template <typename T>
	inline constexpr bool is_template_string_v = false;
	template <char... chars>
	inline constexpr bool is_template_string_v<template_string<chars...>> = true;
	template <typename T>
	struct is_template_string
	{
		static constexpr bool value = is_template_string_v<T>;
	};
	template <typename T>
	concept template_string_type = is_template_string_v<T>;

	namespace helpers
	{
		template <size_t startpos, typename tstr, typename seq>
		struct make_substring;
		template <size_t startpos, char... chars, size_t... indexes>
		struct make_substring<startpos, template_string<chars...>, std::index_sequence<indexes...>>
		{
			static_assert(
				sizeof...(indexes) < sizeof...(chars) - startpos,
				"substr_t: range specified is out of bounds"
				);
			typedef template_string<template_string<chars...>::data[startpos + indexes]..., '\0'> type;
		};

		template <typename tstr1, typename tstr2, typename seq>
		struct tstr_concater;
		template <template_string_type tstr1, char... chars, size_t... indexes>
		struct tstr_concater<tstr1, template_string<chars...>, std::index_sequence<indexes...>>
		{
			typedef template_string<tstr1::data[indexes]..., chars...> type;
		};

		template <template_string_type tstr, template_string_type cmptstr>
		consteval size_t find_impl()
		{
			constexpr std::string_view base{ tstr::data };
			constexpr std::string_view locate{ cmptstr::data };
			return base.find(locate);
		}

		template <template_string_type tstr>
		inline constexpr bool nullterminated = tstr::data[tstr::count] == '\0';

		template <template_string_type tstr, typename seq, bool has_terminator>
		struct cast_away_terminator
		{
			typedef tstr type;
		};
		template <template_string_type tstr, size_t... indexes>
		struct cast_away_terminator<tstr, std::index_sequence<indexes...>, true>
		{
			typedef template_string<tstr::data[indexes]...> type;
		};

		template <template_string_type tstr, bool has_terminator>
		struct nullterminate
		{
			typedef tstr type;
		};
		template <char... chars>
		struct nullterminate<template_string<chars...>, false>
		{
			typedef template_string<chars..., '\0'> type;
		};

		template <template_string_type tstr>
		inline constexpr bool tstr_empty_impl = false;
		template <>
		inline constexpr bool tstr_empty_impl<template_string<>> = true;
		template <>
		inline constexpr bool tstr_empty_impl<template_string<'\0'>> = true;
	}

	template <typename tstr, size_t startpos, size_t count>
	using subtstr_t = typename helpers::make_substring<startpos, tstr, std::make_index_sequence<count>>::type;

	namespace helpers
	{
		template <template_string_type tstr, template_string_type cmptstr, bool fits>
		inline constexpr bool begins_with_impl = std::same_as<subtstr_t<tstr, 0, cmptstr::count>, cmptstr>;
		template <template_string_type tstr, template_string_type cmptstr>
		inline constexpr bool begins_with_impl<tstr, cmptstr, false> = false;
	}

	template <typename tstr, typename cmptstr>
	concept tstr_begins_with = helpers::begins_with_impl < tstr, cmptstr, cmptstr::size < tstr::size>;
	template <typename tstr1, typename tstr2>
	using tstr_concat_t = typename helpers::tstr_concater<tstr1, tstr2, std::make_index_sequence<tstr1::count>>::type;
	template <typename tstr, typename locatetstr>
	inline constexpr size_t tstr_find_v = helpers::find_impl<tstr, locatetstr>();
	template <typename tstr>
	concept tstr_terminated = helpers::nullterminated<tstr>;
	template <typename tstr>
	using tstr_remove_terminator_t = typename helpers::cast_away_terminator<tstr, std::make_index_sequence<tstr::count>, tstr_terminated<tstr>>::type;
	template <typename tstr>
	using tstr_add_terminator_t = typename helpers::nullterminate<tstr, tstr_terminated<tstr>>::type;
	template <typename tstr>
	concept empty_tstr = helpers::tstr_empty_impl<tstr>;

	namespace helpers
	{
		template <size_t N>
		struct cstr_wrapper
		{
			char data[N];
			static constexpr size_t size = N;

			consteval cstr_wrapper(const char(&cstr)[N]) { std::copy_n(cstr, N, data); }
		};

		template <cstr_wrapper str, size_t... indexes>
		consteval auto make_template_string(std::index_sequence<indexes...>)
		{
			return template_string<str.data[indexes]...>{};
		}

		template <cstr_wrapper str, auto result = make_template_string<str>(std::make_index_sequence<str.size>())>
		using tstr_t = decltype(result);

		#define tstr_cast(STRLITERAL) ::utils::helpers::tstr_t<STRLITERAL>
	}
}
#endif
