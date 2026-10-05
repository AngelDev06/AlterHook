/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <cstddef>
#include <limits>
#include <type_traits>
#include <utility>
#include "index_sequence.hpp"

namespace alterhook::utils
{
  namespace helpers
  {
    template <size_t i, typename... types>
    struct type_at_impl
    {
    };
    template <typename... types>
    struct type_reversed_impl;
    template <typename ignored>
    struct type_reversed_enclosing;
    template <typename type_seq, template <size_t, typename> typename pred,
              typename result_seq, size_t i = 0, typename = void>
    struct type_take_while_impl;
    template <typename type_seq, template <size_t, typename> typename pred,
              typename result_seq, size_t i = 0, typename = void>
    struct type_filter_impl;
    template <typename type_seq, size_t begin, size_t end, ptrdiff_t step,
              typename = void>
    struct type_slice_impl;
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
    template <size_t total_args, size_t arity, typename seq>
    struct make_unzipped_index_sequences_impl;
    template <typename seqs, typename params_seq>
    struct make_unzipped_type_sequences_impl;
  } // namespace helpers

  template <typename... types>
  struct type_sequence
  {
    template <template <typename...> typename trg>
    using apply = trg<types...>;

    template <typename ignored = void>
    using reversed = typename helpers::type_reversed_enclosing<
        ignored>::template reversed<types...>;

    template <template <size_t, typename> typename pred>
    using take_while =
        typename helpers::type_take_while_impl<type_sequence, pred,
                                               type_sequence<>>::type;

    template <template <size_t, typename> typename pred>
    using drop_while =
        typename helpers::type_take_while_impl<type_sequence, pred,
                                               type_sequence<>>::remaining;

    template <template <size_t, typename> typename pred>
    using filter = typename helpers::type_filter_impl<type_sequence, pred,
                                                      type_sequence<>>::type;

    template <size_t begin, size_t end = sizeof...(types), ptrdiff_t step = 1>
    using slice = typename helpers::type_slice_impl<type_sequence, begin, end,
                                                    step>::type;

    template <template <typename> typename cls>
    using map = type_sequence<cls<types>...>;

    template <typename T>
    using push_front = type_sequence<T, types...>;

    template <typename T>
    using push_back = type_sequence<types..., T>;

    template <typename... other_types>
    using append = type_sequence<types..., other_types...>;

    template <typename... sequences>
    using merge = typename helpers::merge_impl<type_sequence<types...>,
                                               sequences...>::type;

    template <size_t i>
    using at = typename helpers::type_at_impl<i, types...>::type;

    template <typename T>
    static constexpr bool has = std::disjunction_v<std::is_same<T, types>...>;

    template <typename T>
    static constexpr size_t find = helpers::find_impl<0, T, types...>;

    static constexpr size_t size = sizeof...(types);
  };

  template <template <typename...> typename... Fs>
  struct template_sequence
  {
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

  template <typename... types>
  using reverse_types = typename helpers::type_reversed_impl<types...>::type;

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

  template <size_t total_args, size_t arity>
  using make_unzipped_index_sequences =
      typename helpers::make_unzipped_index_sequences_impl<
          total_args, arity, std::make_index_sequence<arity>>::type;

  template <size_t arity, typename... types>
  using make_unzipped_type_sequences =
      typename helpers::make_unzipped_type_sequences_impl<
          make_unzipped_index_sequences<sizeof...(types), arity>,
          type_sequence<types...>>::type;

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

    template <typename old_sequence, typename new_seq = type_sequence<>>
    struct type_reversed_impl2
    {
      using type = new_seq;
    };

    template <typename Head, typename... Tail, typename... Added>
    struct type_reversed_impl2<type_sequence<Head, Tail...>,
                               type_sequence<Added...>>
        : type_reversed_impl2<type_sequence<Tail...>,
                              type_sequence<Head, Added...>>
    {
    };

    template <typename... types>
    struct type_reversed_impl : type_reversed_impl2<type_sequence<types...>>
    {
    };

    template <typename ignored>
    struct type_reversed_enclosing
    {
      template <typename... types>
      using reversed = reverse_types<types...>;
    };

    template <typename type_seq, template <size_t, typename> typename pred,
              typename result_seq, size_t i, typename>
    struct type_take_while_impl
    {
      using type      = result_seq;
      using remaining = type_seq;
    };

    template <typename head, typename... tail,
              template <size_t, typename> typename pred, typename... added,
              size_t i>
    struct type_take_while_impl<type_sequence<head, tail...>, pred,
                                type_sequence<added...>, i,
                                std::enable_if_t<pred<i, head>::value>>
        : type_take_while_impl<type_sequence<tail...>, pred,
                               type_sequence<added..., head>, i + 1>
    {
    };

    template <typename type_seq, template <size_t, typename> typename pred,
              typename result_seq, size_t i, typename>
    struct type_filter_impl
    {
      using type = result_seq;
    };

    template <typename head, typename... tail,
              template <size_t, typename> typename pred, typename... added,
              size_t i>
    struct type_filter_impl<type_sequence<head, tail...>, pred,
                            type_sequence<added...>, i,
                            std::enable_if_t<pred<i, head>::value>>
        : type_filter_impl<type_sequence<tail...>, pred,
                           type_sequence<added..., head>, i + 1>
    {
    };

    template <typename head, typename... tail,
              template <size_t, typename> typename pred, typename... added,
              size_t i>
    struct type_filter_impl<type_sequence<head, tail...>, pred,
                            type_sequence<added...>, i,
                            std::enable_if_t<!pred<i, head>::value>>
        : type_filter_impl<type_sequence<tail...>, pred,
                           type_sequence<added...>, i + 1>
    {
    };

    template <size_t begin, size_t end, ptrdiff_t step>
    struct in_range_check_enclosing
    {
      template <size_t i, typename>
      struct check : std::bool_constant<(i >= begin) && (i < end) &&
                                        ((i - begin) % step) == 0>
      {
      };
    };

    template <typename type_seq, size_t begin, size_t end, ptrdiff_t step,
              typename>
    struct type_slice_impl
        : type_filter_impl<
              type_seq,
              in_range_check_enclosing<begin, end, step>::template check,
              type_sequence<>>
    {
    };

    template <typename type_seq, size_t begin, size_t end, ptrdiff_t step>
    struct type_slice_impl<type_seq, begin, end, step,
                           std::enable_if_t<(step < 0)>>
    {
      using type = typename type_filter_impl<
          type_seq, in_range_check_enclosing<end, begin, -step>::template check,
          type_sequence<>>::type::template reversed<>;
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

    template <size_t total_args, size_t arity, size_t... indexes>
    struct make_unzipped_index_sequences_impl<total_args, arity,
                                              std::index_sequence<indexes...>>
    {
      using type = type_sequence<
          make_index_sequence_with_step<total_args, indexes, arity>...>;
    };

    template <typename iseq, typename params_seq>
    struct make_unzipped_type_sequences_impl2;

    template <size_t... indexes, typename params_seq>
    struct make_unzipped_type_sequences_impl2<std::index_sequence<indexes...>,
                                              params_seq>
    {
      using type = type_sequence<type_at_t<indexes, params_seq>...>;
    };

    template <typename iseq, typename params_seq>
    using make_unzipped_type_sequences_impl2_t =
        typename make_unzipped_type_sequences_impl2<iseq, params_seq>::type;

    template <typename... sequences, typename params_seq>
    struct make_unzipped_type_sequences_impl<type_sequence<sequences...>,
                                             params_seq>
    {
      using type = type_sequence<
          make_unzipped_type_sequences_impl2_t<sequences, params_seq>...>;
    };
  } // namespace helpers
} // namespace alterhook::utils
