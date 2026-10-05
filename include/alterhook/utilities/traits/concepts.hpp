/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <algorithm>
#include <concepts>
#include <cstddef>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>
#include <initializer_list>
#include "../macros.hpp"
#include "type_sequence.hpp"
#include "function_traits.hpp"
#include "../other.hpp"
#include "../data_processing.hpp"
#include "../tuple_tools.hpp"
#include "iterator_traits.hpp"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4996)
#endif

namespace alterhook::utils::traits
{
#if defined(__cpp_lib_concepts) && __cpp_lib_concepts >= 201'907L
  namespace helpers
  {
    template <typename T>
    concept allocator_type_impl =
        requires { typename T::value_type; } &&
        requires(T& a, typename std::allocator_traits<T>::size_type n,
                 typename std::allocator_traits<T>::pointer p) {
          {
            a.allocate(n)
          } -> std::same_as<typename std::allocator_traits<T>::pointer>;
          a.deallocate(p, n);
        };

    template <typename T>
    concept allocator_type_stripped = allocator_type_impl<remove_cvref_t<T>>;

    template <typename T>
    concept is_allocator_aware_impl = requires(const T& m) {
      { m.get_allocator() } -> allocator_type_stripped;
    };

    template <typename detour, typename original>
    concept is_detour_and_original_pair_impl =
        function_type<original> && std::is_lvalue_reference_v<original> &&
        (callable_type<detour> || disambiguatable_with<detour, original>);
  } // namespace helpers
#else
  namespace helpers
  {
    /*
     * IMPLEMENTATION
     */
    template <typename T, typename = void>
    constexpr bool allocator_type_impl2 = false;
    template <typename T>
    constexpr bool allocator_type_impl2<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().allocate(
                                  std::declval<typename std::allocator_traits<
                                      T>::size_type>())),
                              typename std::allocator_traits<T>::pointer>,
               std::void_t<decltype(std::declval<T&>().deallocate(
                   std::declval<typename std::allocator_traits<T>::pointer>(),
                   std::declval<
                       typename std::allocator_traits<T>::size_type>()))>>> =
        true;

    template <typename T, typename = void>
    constexpr bool allocator_type_impl = false;
    template <typename T>
    constexpr bool allocator_type_impl<T, std::void_t<typename T::value_type>> =
        allocator_type_impl2<T>;

    template <typename T, typename = void>
    constexpr bool is_allocator_aware_impl = false;
    template <typename T>
    constexpr bool is_allocator_aware_impl<
        T, std::enable_if_t<allocator_type_impl<remove_cvref_t<
               decltype(std::declval<const T&>().get_allocator())>>>> = true;

    template <typename T>
    struct callable_type_s : std::bool_constant<callable_type<T>>
    {
    };

    template <typename T, typename From>
    struct disambiguatable_with_s
        : std::bool_constant<disambiguatable_with<T, From>>
    {
    };

    template <typename Detour, typename Original>
    constexpr bool is_detour_and_original_pair_impl = std::conjunction_v<
        std::bool_constant<function_type<Original>>,
        std::is_lvalue_reference<Original>,
        std::disjunction<callable_type_s<Detour>,
                         disambiguatable_with_s<Detour, Original>>>;
  } // namespace helpers
#endif

  template <typename T>
  utils_concept allocator_type =
      helpers::allocator_type_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept allocator_aware =
      helpers::is_allocator_aware_impl<remove_cvref_t<T>>;

  template <typename Detour, typename Original>
  utils_concept is_detour_and_original_pair =
      helpers::is_detour_and_original_pair_impl<Detour, Original>;
} // namespace alterhook::utils::traits

#if utils_msvc
  #pragma warning(pop)
#endif
