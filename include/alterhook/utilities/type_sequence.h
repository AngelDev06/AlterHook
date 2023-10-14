/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <utility>

namespace utils
{
  template <typename... types>
  struct type_sequence
  {
  };

  template <size_t i, typename... types>
  struct type_at;

  template <size_t i, typename first, typename... rest>
  struct type_at<i, first, rest...> : type_at<i - 1, rest...>
  {
  };

  template <typename first, typename... rest>
  struct type_at<0, first, rest...>
  {
    typedef first type;
  };

  template <size_t i>
  struct type_at<i>
  {
  };

  template <size_t i, typename first, typename... rest>
  struct type_at<i, type_sequence<first, rest...>>
      : type_at<i - 1, type_sequence<rest...>>
  {
  };

  template <typename first, typename... rest>
  struct type_at<0, type_sequence<first, rest...>>
  {
    typedef first type;
  };

  template <size_t i>
  struct type_at<i, type_sequence<>>
  {
  };

  template <size_t i, typename... types>
  using type_at_t = typename type_at<i, types...>::type;

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
} // namespace utils
