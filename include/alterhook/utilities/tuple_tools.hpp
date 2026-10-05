/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "macros.hpp"
#include "traits/type_sequence.hpp"
#include <concepts>
#include <cstddef>
#include <tuple>
#include <type_traits>
#include <utility>

namespace alterhook::utils
{
  namespace helpers
  {
    namespace adl
    {
      template <size_t I>
      struct adl_get_fn;
    } // namespace adl

    template <typename F, typename Tuple, size_t... Indexes>
    constexpr decltype(auto) apply_impl(F&& f, Tuple&& tuple,
                                        std::index_sequence<Indexes...>);
    template <typename T, typename Tuple, size_t... indexes>
    constexpr T make_from_tuple_impl(Tuple&& tuple,
                                     std::index_sequence<indexes...>);
    template <size_t... indexes, typename Tuple>
    constexpr auto tuple_slice_impl(std::index_sequence<indexes...>,
                                    Tuple&& tuple)
        -> std::tuple<
            std::tuple_element_t<indexes, std::remove_reference_t<Tuple>>...>;

    template <typename T,
              typename = std::make_index_sequence<std::tuple_size_v<T>>>
    struct tuple_fully_accessible;

    template <typename T, typename type_seq,
              typename = std::make_index_sequence<type_seq::size>,
              typename = void>
    constexpr bool tuple_unpacks_to_impl = false;

#if defined(__cpp_lib_concepts) && __cpp_lib_concepts >= 201'907L
    template <typename T>
    concept tuple_like_impl = requires {
      std::tuple_size<std::remove_reference_t<T>>::value;
    } && tuple_fully_accessible<T>::value;

    template <typename T, size_t N>
    concept fixed_tuple_like_impl =
        requires { std::tuple_size<std::remove_reference_t<T>>::value; } &&
        std::tuple_size_v<std::remove_reference_t<T>> == N &&
        tuple_fully_accessible<T>::value;
#else
    template <typename T, typename = void>
    constexpr bool tuple_like_impl = false;
    template <typename T, size_t N, typename = void>
    constexpr bool fixed_tuple_like_impl = false;
#endif

#if !(defined(__cpp_lib_to_array) && __cpp_lib_to_array >= 201'907L)
    template <typename T, size_t N, size_t... indexes>
    constexpr std::array<std::remove_cv_t<T>, N>
        to_array_impl(T (&a)[N], std::index_sequence<indexes...>);
    template <typename T, size_t N, size_t... indexes>
    constexpr std::array<std::remove_cv_t<T>, N>
        to_array_impl(T (&&a)[N], std::index_sequence<indexes...>);
#endif
  } // namespace helpers

  template <typename T>
  utils_concept tuple_like = helpers::tuple_like_impl<T>;
  template <typename T, size_t N>
  utils_concept fixed_tuple_like = helpers::fixed_tuple_like_impl<T, N>;
  template <typename T>
  utils_concept pair_like = fixed_tuple_like<T, 2>;
  template <typename T, typename... Types>
  utils_concept tuple_unpacks_to =
      helpers::tuple_unpacks_to_impl<T, type_sequence<Types...>>;

  template <size_t I>
  constexpr helpers::adl::adl_get_fn<I> get{};

  template <typename F, typename Tuple>
  constexpr decltype(auto) apply(F&& f, Tuple&& tuple)
  {
    return helpers::apply_impl(
        std::forward<F>(f), std::forward<Tuple>(tuple),
        std::make_index_sequence<std::tuple_size_v<remove_cvref_t<Tuple>>>{});
  }

  template <typename T, typename Tuple>
  constexpr T make_from_tuple(Tuple&& tuple)
  {
    return helpers::make_from_tuple_impl<T>(
        std::forward<Tuple>(tuple),
        std::make_index_sequence<std::tuple_size_v<remove_cvref_t<Tuple>>>{});
  }

  template <size_t begin, size_t end, size_t step = 1, typename Tuple>
  constexpr auto tuple_slice(Tuple&& tuple)
  {
    return helpers::tuple_slice_impl(
        make_index_sequence_with_step<end, begin, step>{},
        std::forward<Tuple>(tuple));
  }

#if defined(__cpp_lib_to_array) && __cpp_lib_to_array >= 201'907L
  using std::to_array;
#else
  template <typename T, size_t N>
  constexpr std::array<std::remove_cv_t<T>, N> to_array(T (&a)[N])
  {
    return helpers::to_array_impl(a, std::make_index_sequence<N>());
  }

  template <typename T, size_t N>
  constexpr std::array<std::remove_cv_t<T>, N> to_array(T (&&a)[N])
  {
    return helpers::to_array_impl(std::move(a), std::make_index_sequence<N>());
  }
#endif

  template <size_t N, typename iter>
  auto to_array(iter first, iter last)
  {
    typedef typename std::iterator_traits<iter>::value_type iter_value;

    std::array<iter_value, N> result{};
    std::copy(first, last, result.begin());
    return result;
  }

  namespace helpers
  {
    template <typename Tuple, size_t I, typename = void>
    constexpr bool has_get_method = false;
    template <typename Tuple, size_t I>
    constexpr bool has_get_method<
        Tuple, I,
        std::void_t<decltype(std::declval<Tuple>().template get<I>())>> = true;

    namespace adl
    {
      using std::get;

      template <typename Tuple, size_t I, typename = void>
      constexpr bool has_adl_get = false;
      template <typename Tuple, size_t I>
      constexpr bool has_adl_get<
          Tuple, I, std::void_t<decltype(get<I>(std::declval<Tuple>()))>> =
          true;

      template <typename Tuple, size_t I>
      struct has_adl_get_s : std::bool_constant<has_adl_get<Tuple, I>>
      {
      };

      template <size_t I>
      struct adl_get_fn
      {
        template <
            typename Tuple,
            std::enable_if_t<
                std::disjunction_v<std::bool_constant<has_get_method<Tuple, I>>,
                                   has_adl_get_s<Tuple, I>>,
                size_t> = 0>
        constexpr decltype(auto) operator()(Tuple&& tuple) const
        {
          if constexpr (has_get_method<Tuple, I>)
            return std::forward<Tuple>(tuple).template get<I>();
          else
            return get<I>(std::forward<Tuple>(tuple));
        }
      };
    } // namespace adl

    template <typename F, typename Tuple, size_t... Indexes>
    constexpr decltype(auto) apply_impl(F&& f, Tuple&& tuple,
                                        std::index_sequence<Indexes...>)
    {
      return std::invoke(std::forward<F>(f),
                         get<Indexes>(std::forward<Tuple>(tuple))...);
    }

    template <typename T, typename Tuple, size_t... indexes>
    constexpr T make_from_tuple_impl(Tuple&& tuple,
                                     std::index_sequence<indexes...>)
    {
      return T(get<indexes>(std::forward<Tuple>(tuple))...);
    }

    template <size_t... indexes, typename Tuple>
    constexpr auto tuple_slice_impl(std::index_sequence<indexes...>,
                                    Tuple&& tuple)
        -> std::tuple<
            std::tuple_element_t<indexes, std::remove_reference_t<Tuple>>...>
    {
      return { get<indexes>(std::forward<Tuple>(tuple))... };
    }

    template <typename GetResult, typename Ti>
    utils_concept valid_get_result = std::is_constructible_v<
        std::conditional_t<std::is_lvalue_reference_v<GetResult>, Ti&, Ti&&>,
        GetResult>;

#if defined(__cpp_lib_concepts) && __cpp_lib_concepts >= 201'907L
    template <typename T, size_t I>
    concept tuple_accessible_at = requires(T tuple) {
      typename std::tuple_element_t<I, std::remove_reference_t<T>>;
      {
        get<I>(std::forward<T>(tuple))
      }
      -> valid_get_result<std::tuple_element_t<I, std::remove_reference_t<T>>>;
    };

    template <typename T, size_t I, typename Expected>
    concept tuple_elem_converts_to = requires(T tuple) {
      { get<I>(std::forward<T>(tuple)) } -> std::convertible_to<Expected>;
    };
#else
    template <typename T, size_t I, typename = void>
    constexpr bool tuple_accessible_at = false;
    template <typename T, size_t I>
    constexpr bool tuple_accessible_at<
        T, I,
        std::enable_if_t<valid_get_result<
            decltype(get<I>(std::declval<T>())),
            std::tuple_element_t<I, std::remove_reference_t<T>>>>> = true;

    template <typename T, size_t I, typename Expected>
    constexpr bool tuple_elem_converts_to =
        std::is_convertible_v<decltype(get<I>(std::declval<T>())), Expected>;
#endif

    template <typename T, size_t I>
    struct tuple_accessible_at_s : std::bool_constant<tuple_accessible_at<T, I>>
    {
    };

    template <typename T, size_t... Indexes>
    struct tuple_fully_accessible<T, std::index_sequence<Indexes...>>
        : std::conjunction<tuple_accessible_at_s<T, Indexes>...>
    {
    };

    template <typename T, size_t I, typename Expected>
    struct tuple_elem_converts_to_s
        : std::bool_constant<tuple_elem_converts_to<T, I, Expected>>
    {
    };

    template <typename T, typename... Types, size_t... Indexes>
    constexpr bool tuple_unpacks_to_impl<
        T, type_sequence<Types...>, std::index_sequence<Indexes...>,
        std::enable_if_t<fixed_tuple_like<T, sizeof...(Indexes)>>> =
        std::conjunction_v<tuple_elem_converts_to_s<T, Indexes, Types>...>;

#if !(defined(__cpp_lib_concepts) && __cpp_lib_concepts >= 201'907L)
    template <typename T>
    constexpr bool tuple_like_impl<
        T, std::void_t<
               decltype(std::tuple_size<std::remove_reference_t<T>>::value)>> =
        tuple_fully_accessible<T>::value;

    template <typename T, size_t N>
    constexpr bool fixed_tuple_like_impl<
        T, N,
        std::enable_if_t<std::tuple_size<std::remove_reference_t<T>>::value ==
                         N>> = tuple_fully_accessible<T>::value;
#endif

#if !(defined(__cpp_lib_to_array) && __cpp_lib_to_array >= 201'907L)
    template <typename T, size_t N, size_t... indexes>
    constexpr std::array<std::remove_cv_t<T>, N>
        to_array_impl(T (&a)[N], std::index_sequence<indexes...>)
    {
      return { { a[indexes]... } };
    }

    template <typename T, size_t N, size_t... indexes>
    constexpr std::array<std::remove_cv_t<T>, N>
        to_array_impl(T (&&a)[N], std::index_sequence<indexes...>)
    {
      return { { std::move(a[indexes])... } };
    }
#endif
  } // namespace helpers
} // namespace alterhook::utils
