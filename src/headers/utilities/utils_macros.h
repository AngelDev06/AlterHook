/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

#if defined(__WIN32__) || defined(_WIN32) || defined(_MSC_VER)
	#define utils_windows true
	#if defined(_M_X64) || defined(__x86_x64__)
		#define utils_windows64 true
	#else
		#define utils_windows64 false
	#endif
#else
	#define utils_windows false
	#define utils_windows64 false
#endif

#ifdef __ANDROID__
	#define utils_android true
#else
	#define utils_android false
#endif

// determines which compiler is used
// the order matters since some compilers may
// define the flags of other compilers
// for example clang may define _MSC_VER
// and icc may define __GNUC__
#ifdef __clang__
	#define utils_clang true
	#define utils_icc false
	#define utils_gcc false
	#define utils_msvc false
	#define utils_other false
#else
	#define utils_clang false
	#ifdef __INTEL_COMPILER
		#define utils_icc true
		#define utils_gcc false
		#define utils_msvc false
		#define utils_other false
	#else
		#define utils_icc false
		#ifdef __GNUC__
			#define utils_gcc true
			#define utils_msvc false
			#define utils_other false
		#else
			#define has_gcc false
			#if defined(_MSC_VER) || defined(_MSVC_LANG)
				#define utils_msvc true
				#define utils_other false
			#else
				#define utils_msvc false
				#define utils_other true
			#endif
		#endif
	#endif
#endif

#if utils_msvc
	#define utils_pack_begin() __pragma(pack(push, 1))
	#define utils_pack_end() __pragma(pack(pop))
#else
	#define utils_pack_begin()
	#define utils_pack_end()
#endif

#if utils_gcc || utils_clang
	#define utils_packed __attribute__((packed))
#else
	#define utils_packed
#endif

#if utils_msvc
	#ifdef _MSVC_LANG
		#define utils_cpp_version _MSVC_LANG
	#else
		#define utils_cpp_version __cplusplus
	#endif
#else
	#define utils_cpp_version __cplusplus
#endif

// determines whether we have access to c++17 or even c++20 features
#if utils_cpp_version >= 202002L
	#define utils_cpp20 true
	#define utils_cpp17 true
#else
	#define utils_cpp20 false
	#if utils_cpp_version >= 201703L
		#define utils_cpp17 true
	#else
		#define utils_cpp17 false
	#endif
#endif

#if utils_cpp20
	#define utils_concept concept
	#define utils_consteval consteval
#else
	#define utils_concept inline constexpr bool
	#define utils_consteval constexpr
#endif

// clang & msvc x86 windows support our trick to determine calling convention
#if (utils_msvc || utils_clang) && utils_windows && !utils_windows64
	#define utils_cc_assertions true
#else
	#define utils_cc_assertions false
#endif

#if (utils_msvc || utils_clang) && utils_windows
	#define __utils_emit_cdecl(fn, cv, ref, exception) \
		fn(__cdecl, cv, ref, exception)

	#ifdef _M_CEE
		#define __utils_emit_clrcall(fn, cv, ref, exception) \
			fn(__clrcall, cv, ref, exception)
	#else
		#define __utils_emit_clrcall(fn, cv, ref, exception)
	#endif

	#if !utils_windows64 && !defined(_M_CEE)
		#define __utils_emit_fastcall(fn, cv, ref, exception) \
			fn(__fastcall, cv, ref, exception)
	#else
		#define __utils_emit_fastcall(fn, cv, ref, exception)
	#endif

	#if !utils_windows64
		#define __utils_emit_stdcall(fn, cv, ref, exception) \
			fn(__stdcall, cv, ref, exception)
		#define __utils_emit_thiscall(fn, cv, ref, exception) \
			fn(__thiscall, cv, ref, exception)
	#else
		#define __utils_emit_stdcall(fn, cv, ref, exception)
		#define __utils_emit_thiscall(fn, cv, ref, exception)
	#endif

	#if ((!utils_windows64 && _M_IX86_FP >= 2) || utils_windows64) && !defined(_M_CEE)
		#define __utils_emit_vectorcall(fn, cv, ref, exception) \
			fn(__vectorcall, cv, ref, exception)
	#else
		#define __utils_emit_vectorcall(fn, cv, ref, exception)
	#endif
#else
	#define __utils_emit_cdecl(fn, cv, ref, exception)
	#define __utils_emit_clrcall(fn, cv, ref, exception)
	#define __utils_emit_fastcall(fn, cv, ref, exception)
	#define __utils_emit_stdcall(fn, cv, ref, exception)
	#define __utils_emit_thiscall(fn, cv, ref, exception)
	#define __utils_emit_vectorcall(fn, cv, ref, exception)
#endif

// These are used for code generation purposes
#define __utils_non_member_call(fn, cv, ref, exception) \
	__utils_emit_cdecl(fn, cv, ref, exception) \
	__utils_emit_clrcall(fn, cv, ref, exception) \
	__utils_emit_fastcall(fn, cv, ref, exception) \
	__utils_emit_stdcall(fn, cv, ref, exception) \
	__utils_emit_vectorcall(fn, cv, ref, exception)

#define __utils_non_member_call_cv(fn, ref, exception) \
	__utils_non_member_call(fn, , ref, exception) \
	__utils_non_member_call(fn, const, ref, exception) \
	__utils_non_member_call(fn, volatile, ref, exception) \
	__utils_non_member_call(fn, const volatile, ref, exception)

#define __utils_non_member_call_cv_ref(fn, exception) \
	__utils_non_member_call_cv(fn, , exception) \
	__utils_non_member_call_cv(fn, &, exception) \
	__utils_non_member_call_cv(fn, &&, exception)

#define __utils_non_member_call_cv_ref_noexcept(fn) \
	__utils_non_member_call_cv_ref(fn, ) \
	__utils_non_member_call_cv_ref(fn, noexcept)

#define __utils_member_call(fn, cv, ref, exception) \
	__utils_emit_cdecl(fn, cv, ref, exception) \
	__utils_emit_clrcall(fn, cv, ref, exception) \
	__utils_emit_fastcall(fn, cv, ref, exception) \
	__utils_emit_stdcall(fn, cv, ref, exception) \
	__utils_emit_thiscall(fn, cv, ref, exception) \
	__utils_emit_vectorcall(fn, cv, ref, exception)

#define __utils_member_call_cv(fn, ref, exception) \
	__utils_member_call(fn, , ref, exception) \
	__utils_member_call(fn, const, ref, exception) \
	__utils_member_call(fn, volatile, ref, exception) \
	__utils_member_call(fn, const volatile, ref, exception)

#define __utils_member_call_cv_ref(fn, exception) \
	__utils_member_call_cv(fn, , exception) \
	__utils_member_call_cv(fn, &, exception) \
	__utils_member_call_cv(fn, &&, exception)

#define __utils_member_call_cv_ref_noexcept(fn) \
	__utils_member_call_cv_ref(fn, ) \
	__utils_member_call_cv_ref(fn, noexcept)

// Needed for some reason
#define __utils_concat(x, y) x##y
#define utils_concat(x, y) __utils_concat(x, y)

// All of the following come from: https://github.com/swansontec/map-macro
// Which is an implementation of a "recursive" macro allowing a macro
// to be "invoked" with each argument of __VA_ARGS__ at a time
#define __utils_map_out
#define __utils_map_end(...)
#define __utils_empty()
// This is needed for msvc
#define __utils_defer(id) id __utils_empty()

#define __utils_eval0(...) __VA_ARGS__
#define __utils_eval1(...) __utils_eval0(__utils_eval0(__utils_eval0(__VA_ARGS__)))
#define __utils_eval2(...) __utils_eval1(__utils_eval1(__utils_eval1(__VA_ARGS__)))
#define __utils_eval3(...) __utils_eval2(__utils_eval2(__utils_eval2(__VA_ARGS__)))
#define __utils_eval4(...) __utils_eval3(__utils_eval3(__utils_eval3(__VA_ARGS__)))
#define __utils_eval5(...) __utils_eval4(__utils_eval4(__utils_eval4(__VA_ARGS__)))

#if utils_msvc
	#define __utils_eval6(...) __utils_eval5(__utils_eval5(__utils_eval5(__VA_ARGS__)))
	#define __utils_eval(...) __utils_eval6(__utils_eval6(__VA_ARGS__))
#else
	#define __utils_eval(...) __utils_eval5(__VA_ARGS__)
#endif

#define __utils_map_get_end2() 0, __utils_map_end
#define __utils_map_get_end1(...) __utils_map_get_end2
#define __utils_map_get_end(...) __utils_map_get_end1

#define __utils_map_next0(item, next, ...) next __utils_map_out
#define __utils_map_next1(item, next) __utils_defer(__utils_map_next0)(item, next, 0)
#define __utils_map_next(item, next) __utils_map_next1(__utils_map_get_end item, next)

#define __utils_map0(fn, x, peek, ...) fn(x) __utils_defer(__utils_map_next(peek, __utils_map1))(fn, peek, __VA_ARGS__)
#define __utils_map1(fn, x, peek, ...) fn(x) __utils_defer(__utils_map_next(peek, __utils_map0))(fn, peek, __VA_ARGS__)

#define __utils_map0_ud(fn, userdata, x, peek, ...) \
	fn(x, userdata) __utils_defer(__utils_map_next(peek, __utils_map1_ud))(fn, userdata, peek, __VA_ARGS__)
#define __utils_map1_ud(fn, userdata, x, peek, ...) \
	fn(x, userdata) __utils_defer(__utils_map_next(peek, __utils_map0_ud))(fn, userdata, peek, __VA_ARGS__)

#define __utils_map_seperated0(fn, seperator, x, peek, ...) \
	seperator fn(x) __utils_defer(__utils_map_next(peek, __utils_map_seperated1))(fn, seperator, peek, __VA_ARGS__)
#define __utils_map_seperated1(fn, seperator, x, peek, ...) \
	seperator fn(x) __utils_defer(__utils_map_next(peek, __utils_map_seperated0))(fn, seperator, peek, __VA_ARGS__)
#define __utils_map_seperated2(fn, seperator, x, peek, ...) \
	fn(x) __utils_defer(__utils_map_next(peek, __utils_map_seperated1))(fn, seperator, peek, __VA_ARGS__)

#define __utils_map_seperated0_ud(fn, seperator, userdata, x, peek, ...) \
	seperator fn(x, userdata) __utils_defer(__utils_map_next(peek, __utils_map_seperated1_ud))(fn, seperator, userdata, peek, __VA_ARGS__)
#define __utils_map_seperated1_ud(fn, seperator, userdata, x, peek, ...) \
	seperator fn(x, userdata) __utils_defer(__utils_map_next(peek, __utils_map_seperated0_ud))(fn, seperator, userdata, peek, __VA_ARGS__)
#define __utils_map_seperated2_ud(fn, seperator, userdata, x, peek, ...) \
	fn(x, userdata) __utils_defer(__utils_map_next(peek, __utils_map_seperated1_ud))(fn, seperator, userdata, peek, __VA_ARGS__)

#define __utils_map_list0(fn, x, peek, ...) , fn(x) __utils_defer(__utils_map_next(peek, __utils_map_list1))(fn, peek, __VA_ARGS__)
#define __utils_map_list1(fn, x, peek, ...) , fn(x) __utils_defer(__utils_map_next(peek, __utils_map_list0))(fn, peek, __VA_ARGS__)
#define __utils_map_list2(fn, x, peek, ...) fn(x) __utils_defer(__utils_map_next(peek, __utils_map_list1))(fn, peek, __VA_ARGS__)

#define __utils_map_list0_ud(fn, userdata, x, peek, ...) \
	, fn(x, userdata) __utils_defer(__utils_map_next(peek, __utils_map_list1_ud))(fn, userdata, peek, __VA_ARGS__)
#define __utils_map_list1_ud(fn, userdata, x, peek, ...) \
	, fn(x, userdata) __utils_defer(__utils_map_next(peek, __utils_map_list0_ud))(fn, userdata, peek, __VA_ARGS__)
#define __utils_map_list2_ud(fn, userdata, x, peek, ...) \
	fn(x, userdata) __utils_defer(__utils_map_next(peek, __utils_map_list1_ud))(fn, userdata, peek, __VA_ARGS__)

// Applies the function macro `macro` to each of the remaining parameters
#define utils_map(macro, ...) __utils_eval(__utils_map1(macro, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function macro `macro` to each of the remaining parameters
// and seperates the results with `seperator`
#define utils_map_seperated(macro, seperator, ...) \
	__utils_eval(__utils_map_seperated2(macro, seperator, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function macro `macro` to each of the remaining parameters
// and seperates the results with comma
#define utils_map_list(macro, ...) \
	__utils_eval(__utils_map_list2(macro, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function macro `macro` to each of the remaining parameters
// and passes the `userdata` as a second parameter to each invocation,
// e.g. utils_map_ud(f, x, a, b, c) evaluates to f(a, x) f(b, x) f(c, x)
#define utils_map_ud(macro, userdata, ...) \
	__utils_eval(__utils_map1_ud(macro, userdata, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function macro `macro` to each of the remaining parameters,
// passes the `userdata` as a second parameter to each invocation
// and seperates the results with `seperator`
// e.g. utils_map_seperated_ud(f, <<, x, a, b, c) evaluates to f(a, x) << f(b, x) << f(c, x)
#define utils_map_seperated_ud(macro, seperator, userdata, ...) \
	__utils_eval(__utils_map_seperated2_ud(macro, seperator, userdata, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function macro `macro` to each of the remaining parameters,
// passes the `userdata` as a second parameter to each invocation
// and seperates the results with comma,
// e.g. utils_map_list_ud(f, x, a, b, c) evaluates to f(a, x), f(b, x), f(c, x)
#define utils_map_list_ud(macro, userdata, ...) \
	__utils_eval(__utils_map_list2_ud(macro, userdata, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

#define __utils_print_helper(x) ' ' << x

// Print each argument to stdout seperated by space
#define utils_print(...) std::cout << utils_map_seperated(__utils_print_helper, <<, __VA_ARGS__)

#define __utils_define_fields0(type, identifier) type utils_concat(m_, identifier);
#define __utils_define_fields1(pair) __utils_define_fields0 pair
#define __utils_define_fields(...) utils_map(__utils_define_fields1, __VA_ARGS__)

#define __utils_define_arguments0(type, identifier) type identifier
#define __utils_define_arguments1(pair) __utils_define_arguments0 pair
#define __utils_define_arguments(...) utils_map_list(__utils_define_arguments1, __VA_ARGS__)

#define __utils_pass_parameters0(type, identifier) identifier
#define __utils_pass_parameters1(pair) __utils_pass_parameters0 pair
#define __utils_pass_parameters(...) utils_map_list(__utils_pass_parameters1, __VA_ARGS__)

#define __utils_init_fields0(type, identifier) utils_concat(m_, identifier)(identifier)
#define __utils_init_fields1(pair) __utils_init_fields0 pair
#define __utils_init_fields(...) utils_map_list(__utils_init_fields1, __VA_ARGS__)

#define __utils_copy_fields0(type, identifier) utils_concat(m_, identifier)(other.utils_concat(m_, identifier))
#define __utils_copy_fields1(pair) __utils_copy_fields0 pair
#define __utils_copy_fields(...) utils_map_list(__utils_copy_fields1, __VA_ARGS__)

#define __utils_copy_assign_fields0(type, identifier) utils_concat(m_, identifier) = other.utils_concat(m_, identifier);
#define __utils_copy_assign_fields1(pair) __utils_copy_assign_fields0 pair
#define __utils_copy_assign_fields(...) utils_map(__utils_copy_assign_fields1, __VA_ARGS__)

#define __utils_define_getters0(type, identifier) type utils_concat(get_, identifier)() { return utils_concat(m_, identifier); }
#define __utils_define_getters1(pair) __utils_define_getters0 pair
#define __utils_define_getters(...) utils_map(__utils_define_getters1, __VA_ARGS__)

/* This generates an exception class using the following properties
* `exception_name`: 
* | The name of the exception, it will be used in the class definition like
* | `class exception_name` etc.
* 
* `base`:
* | The base class to inherit from. This is not an optional parameter.
* 
* `fields`:
* | A list of pairs that specify a field's identifier and type, which
* | will automatically be defined inside the class. This is passed like
* | `((int, member1), (long, member2), (double, member3))`
* 
* `base_args`:
* | This is again a list of pairs which specifies the arguments the base
* | constructor will accept and they are also passed the same way fields do
* 
* `__VA_ARGS__`:
* | Any extra content that the class will include. For example a function declaration.
*/
#define utils_generate_exception(exception_name, base, fields, base_args, ...) \
	class exception_name : public base \
	{ \
	private: \
		__utils_define_fields fields \
	public: \
		exception_name(__utils_define_arguments base_args, __utils_define_arguments fields) \
			: base(__utils_pass_parameters base_args), __utils_init_fields fields {} \
		exception_name(const exception_name& other) \
			: base(other), __utils_copy_fields fields {} \
		exception_name& operator=(const exception_name& other) \
		{ \
			base::operator=(other); \
			__utils_copy_assign_fields fields \
			return *this; \
		} \
		__utils_define_getters fields \
	};
