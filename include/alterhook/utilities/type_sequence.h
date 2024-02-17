/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <limits>
#include <utility>

namespace alterhook::utils
{
  namespace helpers
  {
    template <size_t i, typename... types>
    struct type_at_impl;
    template <size_t begin, size_t end, typename... types>
    struct reverse_types_impl;
    template <size_t begin, size_t end, typename... types>
    struct pop_range_impl;
    template <size_t i, typename T, typename... types>
    inline constexpr size_t find_impl = (std::numeric_limits<size_t>::max)();
    template <typename first, typename... rest>
    struct merge_impl;
    template <typename seq, typename... types>
    struct make_type_pairs_impl;
    template <typename seq, typename... types>
    struct make_type_triplets_impl;
  } // namespace helpers

  template <typename... types>
  struct type_sequence
  {
    template <template <typename...> typename trg>
    using to = trg<types...>;

    template <size_t begin, size_t end = sizeof...(types)>
    using range =
        typename helpers::pop_range_impl<begin, end, types...>::popped;

    template <size_t begin, size_t end = sizeof...(types)>
    using pop = typename helpers::pop_range_impl<begin, end, types...>::type;

    template <size_t begin = 0, size_t end = sizeof...(types)>
    using reverse =
        typename helpers::reverse_types_impl<begin, end, types...>::type;

    template <template <typename> typename cls>
    using apply = type_sequence<cls<types>...>;

    template <typename T>
    using push_front = type_sequence<T, types...>;

    template <typename T>
    using push_back = type_sequence<types..., T>;

    template <typename... sequences>
    using merge = typename helpers::merge_impl<type_sequence<types...>,
                                               sequences...>::type;

    template <size_t i>
    using at = typename helpers::type_at_impl<i, types...>::type;

    template <typename T>
    static constexpr bool has = (std::is_same_v<T, types> || ...);

    template <typename T>
    static constexpr size_t find = helpers::find_impl<0, T, types...>;

    static constexpr size_t size = sizeof...(types);
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

  template <size_t begin, size_t end, typename... types>
  struct range_from
  {
    typedef typename helpers::pop_range_impl<begin, end, types...>::popped type;
  };

  template <size_t begin, size_t end, typename... types>
  struct range_from<begin, end, type_sequence<types...>>
  {
    typedef typename helpers::pop_range_impl<begin, end, types...>::popped type;
  };

  template <size_t begin, size_t end, typename... types>
  using range_from_t = typename range_from<begin, end, types...>::type;

  template <size_t begin, size_t end, typename... types>
  struct pop_range_from
  {
    typedef typename helpers::pop_range_impl<begin, end, types...>::type type;
  };

  template <size_t begin, size_t end, typename... types>
  struct pop_range_from<begin, end, type_sequence<types...>>
  {
    typedef typename helpers::pop_range_impl<begin, end, types...>::type type;
  };

  template <size_t begin, size_t end, typename... types>
  using pop_range_from_t = typename pop_range_from<begin, end, types...>::type;

  template <typename... types>
  struct reverse_types
      : helpers::reverse_types_impl<0, sizeof...(types), types...>
  {
  };

  template <typename... types>
  struct reverse_types<type_sequence<types...>>
      : helpers::reverse_types_impl<0, sizeof...(types), types...>
  {
  };

  template <typename... types>
  using reverse_types_t = typename reverse_types<types...>::type;

  template <typename T, typename... types>
  inline constexpr size_t find_type = helpers::find_impl<0, T, types...>;
  template <typename T, typename... types>
  inline constexpr size_t find_type<T, type_sequence<types...>> =
      helpers::find_impl<0, T, types...>;

  template <typename first, typename... rest>
  using merge_type_sequences =
      typename helpers::merge_impl<first, rest...>::type;

  template <typename T>
  struct pack_to_type_sequence;

  template <template <typename...> typename T, typename... types>
  struct pack_to_type_sequence<T<types...>>
  {
    typedef type_sequence<types...> type;
  };

  template <typename T>
  using pack_to_type_sequence_t = typename pack_to_type_sequence<T>::type;

  template <typename... types>
  struct make_type_pairs
      : helpers::make_type_pairs_impl<type_sequence<>, types...>
  {
  };

  template <typename... types>
  using make_type_pairs_t = typename make_type_pairs<types...>::type;

  template <typename... types>
  struct make_type_triplets
      : helpers::make_type_triplets_impl<type_sequence<>, types...>
  {
  };

  template <typename... types>
  using make_type_triplets_t = typename make_type_triplets<types...>::type;

  namespace helpers
  {
    template <size_t i, typename first, typename... rest>
    struct type_at_impl<i, first, rest...> : type_at_impl<i - 1, rest...>
    {
    };

    template <typename first, typename... rest>
    struct type_at_impl<0, first, rest...>
    {
      typedef first type;
    };

    template <typename seq, size_t begin, size_t end, size_t i = 0,
              typename frontseq    = type_sequence<>,
              typename backseq     = type_sequence<>,
              typename reversedseq = type_sequence<>,
              bool before_begin = (i < begin), bool after_end = (i >= end)>
    struct reverse_types_impl2;

    template <typename current, typename... rest, typename... frontseq_types,
              typename... backseq_types, typename... reversedseq_types,
              size_t begin, size_t end, size_t i>
    struct reverse_types_impl2<type_sequence<current, rest...>, begin, end, i,
                               type_sequence<frontseq_types...>,
                               type_sequence<backseq_types...>,
                               type_sequence<reversedseq_types...>, true, false>
        : reverse_types_impl2<type_sequence<rest...>, begin, end, i + 1,
                              type_sequence<frontseq_types..., current>,
                              type_sequence<backseq_types...>,
                              type_sequence<reversedseq_types...>>
    {
    };

    template <typename current, typename... rest, typename... frontseq_types,
              typename... backseq_types, typename... reversedseq_types,
              size_t begin, size_t end, size_t i>
    struct reverse_types_impl2<type_sequence<current, rest...>, begin, end, i,
                               type_sequence<frontseq_types...>,
                               type_sequence<backseq_types...>,
                               type_sequence<reversedseq_types...>, false, true>
        : reverse_types_impl2<type_sequence<rest...>, begin, end, i + 1,
                              type_sequence<frontseq_types...>,
                              type_sequence<backseq_types..., current>,
                              type_sequence<reversedseq_types...>>
    {
    };

    template <typename current, typename... rest, typename... frontseq_types,
              typename... backseq_types, typename... reversedseq_types,
              size_t begin, size_t end, size_t i>
    struct reverse_types_impl2<
        type_sequence<current, rest...>, begin, end, i,
        type_sequence<frontseq_types...>, type_sequence<backseq_types...>,
        type_sequence<reversedseq_types...>, false, false>
        : reverse_types_impl2<type_sequence<rest...>, begin, end, i + 1,
                              type_sequence<frontseq_types...>,
                              type_sequence<backseq_types...>,
                              type_sequence<current, reversedseq_types...>>
    {
    };

    template <typename... frontseq_types, typename... backseq_types,
              typename... reversedseq_types, size_t begin, size_t end, size_t i>
    struct reverse_types_impl2<type_sequence<>, begin, end, i,
                               type_sequence<frontseq_types...>,
                               type_sequence<backseq_types...>,
                               type_sequence<reversedseq_types...>, false, true>
    {
      typedef type_sequence<frontseq_types..., reversedseq_types...,
                            backseq_types...>
                                                  type;
      typedef type_sequence<reversedseq_types...> reversed_range;
    };

    template <size_t begin, size_t end, typename... types>
    struct reverse_types_impl
        : reverse_types_impl2<type_sequence<types...>, begin, end>
    {
    };

    template <typename seq, size_t begin, size_t end, size_t i = 0,
              typename newseq    = type_sequence<>,
              typename poppedseq = type_sequence<>,
              bool in_range      = (begin <= i && i < end)>
    struct pop_range_impl2;

    template <typename current, typename... rest, typename... newseq_types,
              typename... poppedseq_types, size_t begin, size_t end, size_t i>
    struct pop_range_impl2<type_sequence<current, rest...>, begin, end, i,
                           type_sequence<newseq_types...>,
                           type_sequence<poppedseq_types...>, false>
        : pop_range_impl2<type_sequence<rest...>, begin, end, i + 1,
                          type_sequence<newseq_types..., current>,
                          type_sequence<poppedseq_types...>>
    {
    };

    template <typename current, typename... rest, typename... newseq_types,
              typename... poppedseq_types, size_t begin, size_t end, size_t i>
    struct pop_range_impl2<type_sequence<current, rest...>, begin, end, i,
                           type_sequence<newseq_types...>,
                           type_sequence<poppedseq_types...>, true>
        : pop_range_impl2<type_sequence<rest...>, begin, end, i + 1,
                          type_sequence<newseq_types...>,
                          type_sequence<poppedseq_types..., current>>
    {
    };

    template <typename... newseq_types, typename... poppedseq_types,
              size_t begin, size_t end, size_t i>
    struct pop_range_impl2<type_sequence<>, begin, end, i,
                           type_sequence<newseq_types...>,
                           type_sequence<poppedseq_types...>, false>
    {
      typedef type_sequence<newseq_types...>    type;
      typedef type_sequence<poppedseq_types...> popped;
    };

    template <size_t begin, size_t end, typename... types>
    struct pop_range_impl : pop_range_impl2<type_sequence<types...>, begin, end>
    {
    };

    template <size_t i, typename T, typename next, typename... types>
    inline constexpr size_t find_impl<i, T, next, types...> =
        find_impl<i + 1, T, types...>;
    template <size_t i, typename T, typename... types>
    inline constexpr size_t find_impl<i, T, T, types...> = i;

    template <typename... left_types, typename... right_types, typename... rest>
    struct merge_impl<type_sequence<left_types...>,
                      type_sequence<right_types...>, rest...>
        : merge_impl<type_sequence<left_types..., right_types...>, rest...>
    {
    };

    template <typename... types>
    struct merge_impl<type_sequence<types...>>
    {
      typedef type_sequence<types...> type;
    };

    template <typename... current_pairs, typename first, typename second,
              typename... rest>
    struct make_type_pairs_impl<type_sequence<current_pairs...>, first, second,
                                rest...>
        : make_type_pairs_impl<
              type_sequence<current_pairs..., type_sequence<first, second>>,
              rest...>
    {
    };

    template <typename... current_pairs>
    struct make_type_pairs_impl<type_sequence<current_pairs...>>
    {
      typedef type_sequence<current_pairs...> type;
    };

    template <typename... current_triplets, typename first, typename second,
              typename third, typename... rest>
    struct make_type_triplets_impl<type_sequence<current_triplets...>, first,
                                   second, third, rest...>
        : make_type_triplets_impl<
              type_sequence<current_triplets...,
                            type_sequence<first, second, third>>,
              rest...>
    {
    };

    template <typename... current_triplets>
    struct make_type_triplets_impl<type_sequence<current_triplets...>>
    {
      typedef type_sequence<current_triplets...> type;
    };
  } // namespace helpers
} // namespace alterhook::utils
