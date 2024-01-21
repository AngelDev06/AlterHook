/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <utility>

namespace alterhook::utils
{
  namespace helpers
  {
    template <size_t i, typename... types>
    struct type_at_impl
    {
    };

    template <size_t i, typename first, typename... rest>
    struct type_at_impl<i, first, rest...> : type_at_impl<i - 1, rest...>
    {
    };

    template <typename first, typename... rest>
    struct type_at_impl<0, first, rest...>
    {
      typedef first type;
    };

    template <size_t i, typename T, typename... types>
    inline constexpr size_t find_impl = ~size_t{};
    template <size_t i, typename T, typename next, typename... types>
    inline constexpr size_t find_impl<i, T, next, types...> =
        find_impl<i + 1, T, types...>;
    template <size_t i, typename T, typename... types>
    inline constexpr size_t find_impl<i, T, T, types...> = i;
  } // namespace helpers

  template <typename... types>
  struct type_sequence
  {
    template <template <typename...> typename trg>
    using to = trg<types...>;

    template <template <typename> typename cls>
    using apply = type_sequence<cls<types>...>;

    template <typename T>
    using push_front = type_sequence<T, types...>;

    template <typename T>
    using push_back = type_sequence<types..., T>;

    template <size_t i>
    using at = typename helpers::type_at_impl<i, types...>::type;

    template <typename T>
    static constexpr bool has = (std::is_same_v<T, types> || ...);

    template <typename T>
    static constexpr size_t find = helpers::find_impl<0, T, types...>;
  };

  template <size_t i, typename... types>
  struct type_at : helpers::type_at_impl<i, types...>
  {
  };

  template <size_t i, typename first, typename... rest>
  struct type_at<i, type_sequence<first, rest...>>
      : helpers::type_at_impl<i, first, rest...>
  {
  };

  template <size_t i, typename... types>
  using type_at_t = typename type_at<i, types...>::type;

  template <typename T, typename... types>
  inline constexpr size_t find_type = helpers::find_impl<0, T, types...>;
  template <typename T, typename... types>
  inline constexpr size_t find_type<T, type_sequence<types...>> =
      helpers::find_impl<0, T, types...>;

  template <typename T>
  struct pack_to_type_sequence;

  template <template <typename...> typename T, typename... types>
  struct pack_to_type_sequence<T<types...>>
  {
    typedef type_sequence<types...> type;
  };

  template <typename T>
  using pack_to_type_sequence_t = typename pack_to_type_sequence<T>::type;

  namespace helpers
  {
    template <typename seq, typename... types>
    struct make_type_pairs_impl
    {
      typedef void type;
    };

    template <typename... current_pairs, typename first, typename second,
              typename... rest>
    struct make_type_pairs_impl<type_sequence<current_pairs...>, first, second,
                                rest...>
        : make_type_pairs_impl<
              type_sequence<current_pairs..., std::pair<first, second>>,
              rest...>
    {
    };

    template <typename... current_pairs>
    struct make_type_pairs_impl<type_sequence<current_pairs...>>
    {
      typedef type_sequence<current_pairs...> type;
    };

    template <typename seq, typename... types>
    struct make_type_triplets_impl
    {
      typedef void type;
    };

    template <typename... current_triplets, typename first, typename second,
              typename third, typename... rest>
    struct make_type_triplets_impl<type_sequence<current_triplets...>, first,
                                   second, third, rest...>
        : make_type_triplets_impl<
              type_sequence<current_triplets...,
                            std::tuple<first, second, third>>,
              rest...>
    {
    };

    template <typename... current_triplets>
    struct make_type_triplets_impl<type_sequence<current_triplets...>>
    {
      typedef type_sequence<current_triplets...> type;
    };
  } // namespace helpers

  template <typename... types>
  struct make_type_pairs
      : helpers::make_type_pairs_impl<type_sequence<>, types...>
  {
    // static_assert(!(sizeof...(types) % 2), "can't make pairs with given
    // types");
  };

  template <typename... types>
  using make_type_pairs_t = typename make_type_pairs<types...>::type;

  template <typename... types>
  struct make_type_triplets
      : helpers::make_type_triplets_impl<type_sequence<>, types...>
  {
    // static_assert(!(sizeof...(types) % 3),
    //"can't make triplets with given types");
  };

  template <typename... types>
  using make_type_triplets_t = typename make_type_triplets<types...>::type;
} // namespace alterhook::utils
