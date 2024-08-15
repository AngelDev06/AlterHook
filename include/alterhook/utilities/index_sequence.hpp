#pragma once
#include <utility>

namespace alterhook::utils
{
  namespace helpers
  {
    template <size_t start, size_t end, typename seq = std::index_sequence<>>
    struct make_index_sequence_impl;
    template <size_t start, size_t end, typename seq = std::index_sequence<>>
    struct make_reversed_index_sequence_impl;
    template <size_t start, size_t end, size_t step,
              typename seq = std::index_sequence<>>
    struct make_index_sequence_with_step_impl;
  } // namespace helpers

  template <size_t end, size_t start = 0>
  using make_index_sequence =
      typename helpers::make_index_sequence_impl<start, end>::type;
  template <size_t start, size_t end = 0>
  using make_reversed_index_sequence =
      typename helpers::make_reversed_index_sequence_impl<start, end>::type;
  template <size_t end, size_t start = 0, size_t step = 2>
  using make_index_sequence_with_step =
      typename helpers::make_index_sequence_with_step_impl<
          start, end + (start % step), step>::type;

  namespace helpers
  {
    template <size_t i, size_t end, size_t... indexes>
    struct make_index_sequence_impl<i, end, std::index_sequence<indexes...>>
        : make_index_sequence_impl<i + 1, end,
                                   std::index_sequence<indexes..., i>>
    {
    };

    template <size_t end, size_t... indexes>
    struct make_index_sequence_impl<end, end, std::index_sequence<indexes...>>
    {
      typedef std::index_sequence<indexes...> type;
    };

    template <size_t i, size_t end, size_t... indexes>
    struct make_reversed_index_sequence_impl<i, end,
                                             std::index_sequence<indexes...>>
        : make_reversed_index_sequence_impl<
              i - 1, end, std::index_sequence<indexes..., i - 1>>
    {
    };

    template <size_t end, size_t... indexes>
    struct make_reversed_index_sequence_impl<end, end,
                                             std::index_sequence<indexes...>>
    {
      typedef std::index_sequence<indexes...> type;
    };

    template <size_t i, size_t end, size_t step, size_t... indexes>
    struct make_index_sequence_with_step_impl<i, end, step,
                                              std::index_sequence<indexes...>>
        : make_index_sequence_with_step_impl<i + step, end, step,
                                             std::index_sequence<indexes..., i>>
    {
    };

    template <size_t end, size_t step, size_t... indexes>
    struct make_index_sequence_with_step_impl<end, end, step,
                                              std::index_sequence<indexes...>>
    {
      typedef std::index_sequence<indexes...> type;
    };
  } // namespace helpers
} // namespace alterhook::utils
