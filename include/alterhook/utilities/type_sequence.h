/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

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
} // namespace utils
