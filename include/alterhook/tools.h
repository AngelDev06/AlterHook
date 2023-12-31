/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "detail/macros.h"
#include "utilities/utils.h"
#include "addresser.h"

namespace alterhook
{
  ALTERHOOK_API bool is_executable_address(const void* address);

  namespace helpers
  {
#if utils_cpp20
    template <typename T>
    concept callable_but_stl_fn =
        utils::callable_type<T> && !utils::stl_function_type<T>;
#endif

    template <typename dtr, typename orig>
    utils_consteval void assert_valid_detour_original_pair()
    {
      typedef utils::clean_type_t<dtr>  detour_type;
      typedef utils::clean_type_t<orig> storage_type;
      static_assert(std::is_same_v<utils::fn_return_t<detour_type>,
                                   utils::fn_return_t<storage_type>>,
                    "The return type of the detour and the original function "
                    "need to be the same");
#if utils_cc_assertions
      static_assert(
          utils::compatible_calling_convention_with<detour_type, storage_type>,
          "The calling conventions of the detour and the original function "
          "need to be compatible");
#endif
      static_assert(
          utils::compatible_function_arguments_with<detour_type, storage_type>,
          "The arguments the detour accepts aren't compatible with the "
          "original function");
    }

    template <typename trg, typename dtr>
    utils_consteval void assert_valid_target_and_detour_pair()
    {
      typedef utils::clean_type_t<trg> ctrg;
      typedef utils::clean_type_t<dtr> cdtr;
      static_assert(
          std::is_same_v<utils::fn_return_t<ctrg>, utils::fn_return_t<cdtr>>,
          "The return type of the target and the detour function need to be "
          "the same");
#if utils_cc_assertions
      static_assert(utils::compatible_calling_convention_with<ctrg, cdtr>,
                    "The calling conventions of the target and the detour "
                    "function need to be compatible");
#endif
      static_assert(utils::compatible_function_arguments_with<cdtr, ctrg>,
                    "The arguments the detour accepts aren't compatible with "
                    "the target function");
    }

    template <typename detour, typename... detours, typename original,
              typename... originals>
    utils_consteval void assert_valid_detour_and_original_pairs(
        utils::type_sequence<detour, detours...>,
        utils::type_sequence<original, originals...>)
    {
      typedef utils::clean_type_t<detour>   cdetour;
      typedef utils::clean_type_t<original> coriginal;
      static_assert(
          ((std::is_same_v<utils::fn_return_t<cdetour>,
                           utils::fn_return_t<utils::clean_type_t<detours>>> &&
            std::is_same_v<
                utils::fn_return_t<coriginal>,
                utils::fn_return_t<utils::clean_type_t<originals>>>)&&...) &&
              std::is_same_v<utils::fn_return_t<cdetour>,
                             utils::fn_return_t<coriginal>>,
          "The return types of the detours and the original function need to "
          "be the same");
#if utils_cc_assertions
      static_assert(
          ((utils::compatible_calling_convention_with<
                utils::clean_type_t<detours>, utils::clean_type_t<originals>> &&
            utils::compatible_calling_convention_with<
                cdetour, utils::clean_type_t<originals>> &&
            utils::compatible_calling_convention_with<
                utils::clean_type_t<detours>, coriginal>)&&...) &&
              utils::compatible_calling_convention_with<cdetour, coriginal>,
          "The calling conventions of the detours and the original function "
          "aren't compatible");
#endif
      static_assert(
          ((utils::compatible_function_arguments_with<
                utils::clean_type_t<detours>, utils::clean_type_t<originals>> &&
            utils::compatible_function_arguments_with<
                utils::clean_type_t<detours>, coriginal>)&&...) &&
              utils::compatible_function_arguments_with<cdetour, coriginal>,
          "The arguments of the detours and the original function aren't "
          "compatible");
    }

    template <typename trg, typename... detours>
    utils_consteval void
        assert_valid_target_and_detours(utils::type_sequence<detours...>)
    {
      typedef utils::clean_type_t<trg> ctrg;
      static_assert(
          (std::is_same_v<utils::fn_return_t<ctrg>,
                          utils::fn_return_t<utils::clean_type_t<detours>>> &&
           ...),
          "The return types of the target and the detour need to be the same");
#if utils_cc_assertions
      static_assert((utils::compatible_calling_convention_with<
                         ctrg, utils::clean_type_t<detours>> &&
                     ...),
                    "The calling conventions of the detours and the target "
                    "function aren't compatible");
#endif
      static_assert((utils::compatible_function_arguments_with<
                         utils::clean_type_t<detours>, ctrg> &&
                     ...),
                    "The arguments of the detours and the target function "
                    "aren't compatible");
    }

    template <typename iseq, typename tseq>
    struct extract_detour_sequence_impl;

    template <size_t... indexes, typename tseq>
    struct extract_detour_sequence_impl<std::index_sequence<indexes...>, tseq>
    {
      typedef utils::type_sequence<utils::type_at_t<indexes, tseq>...> type;
    };

    template <typename... types>
    struct extract_detour_sequence
        : extract_detour_sequence_impl<
              utils::make_index_sequence_with_step<sizeof...(types)>,
              utils::type_sequence<types...>>
    {
    };

    template <typename... types>
    using extract_detour_sequence_t =
        typename extract_detour_sequence<types...>::type;

    template <typename... tuples>
    struct extract_detour_sequence_from_tuples
    {
      typedef utils::type_sequence<std::tuple_element_t<0, tuples>...> type;
    };

    template <typename... tuples>
    using extract_detour_sequence_from_tuples_t =
        typename extract_detour_sequence_from_tuples<tuples...>::type;
  } // namespace helpers

  template <__alterhook_is_callable_but_stl_fn(T)>
  constexpr std::byte* get_target_address(T&& fn) noexcept
  {
    typedef utils::remove_cvref_t<T> fn_t;
    if constexpr (utils::captureless_lambda<fn_t>)
      return reinterpret_cast<std::byte*>(
          static_cast<utils::captureless_lambda_actual_func_ptr_type_t<fn_t>>(
              fn));
#if utils_clang && utils_windows
    else if constexpr (utils::member_function_type<fn_t>)
      return reinterpret_cast<std::byte*>(addresser::address_of_regular(fn));
    else if constexpr (utils::fn_object_v<std::remove_pointer_t<fn_t>>)
      return reinterpret_cast<std::byte*>(
          addresser::address_of_regular(&fn_t::operator()));
#else
    else if constexpr (utils::member_function_type<fn_t>)
      return reinterpret_cast<std::byte*>(addresser::address_of(fn));
    else if constexpr (utils::fn_object_v<std::remove_pointer_t<fn_t>>)
      return reinterpret_cast<std::byte*>(
          addresser::address_of(&fn_t::operator()));
#endif
    else
      return reinterpret_cast<std::byte*>(fn);
  }

  template <__alterhook_is_original(T)>
  auto function_cast(void* address) noexcept
  {
    typedef utils::remove_cvref_t<T> fn_t;
    if constexpr (utils::member_function_type<fn_t>)
    {
      T val{ nullptr };
      reinterpret_cast<void*&>(val) = address;
      return val;
    }
    else if constexpr (std::is_function_v<utils::clean_type_t<T>>)
      return reinterpret_cast<std::add_pointer_t<utils::clean_type_t<T>>>(
          address);
    else
      return fn_t(
          reinterpret_cast<utils::unwrap_stl_function_t<fn_t>>(address));
  }

  template <__alterhook_is_original(T)>
  auto function_cast(const void* address) noexcept
  {
    typedef utils::remove_cvref_t<T> fn_t;
    if constexpr (utils::member_function_type<fn_t>)
    {
      T val{ nullptr };
      reinterpret_cast<void*&>(val) = const_cast<void*>(address);
      return val;
    }
    else if constexpr (std::is_function_v<utils::clean_type_t<T>>)
      return reinterpret_cast<std::add_pointer_t<utils::clean_type_t<T>>>(
          const_cast<void*>(address));
    else
      return reinterpret_cast<utils::unwrap_stl_function_t<fn_t>>(
          const_cast<void*>(address));
  }

  template <typename T>
  [[noreturn]] void nested_throw(T&& exception)
  {
    struct nested : std::nested_exception,
                    utils::remove_cvref_t<T>
    {
      typedef utils::remove_cvref_t<T> base;

      nested(const std::nested_exception& other, T&& current)
          : std::nested_exception(other), base(std::forward<T>(current))
      {
      }
    };

    std::nested_exception other{};
    if (other.nested_ptr())
      throw(nested(other, std::forward<T>(exception)));
    else
      throw(std::forward<T>(exception));
  }

  namespace helpers
  {
    struct original
    {
      virtual original& operator=(std::nullptr_t null)      = 0;
      virtual original& operator=(const std::byte* address) = 0;

      template <typename T>
      bool contains_ref(T& orig);
    };

    template <typename T>
    struct original_wrapper : original
    {
      T& val;

      original_wrapper(T& orig) : val(orig) {}

      original_wrapper& operator=(std::nullptr_t null) override
      {
        val = null;
        return *this;
      }

      original_wrapper& operator=(const std::byte* address) override
      {
        val = function_cast<T>(address);
        return *this;
      }
    };

    typedef std::aligned_storage_t<
        sizeof(original_wrapper<std::function<void()>>),
        alignof(original_wrapper<std::function<void()>>)>
        orig_buff_t;

    template <typename T>
    bool original::contains_ref(T& orig)
    {
      if (auto* wrapper = dynamic_cast<original_wrapper<T>*>(this))
        return &wrapper->val == &orig;
      return false;
    }
  } // namespace helpers
} // namespace alterhook
