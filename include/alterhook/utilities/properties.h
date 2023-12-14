/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "type_sequence.h"

namespace alterhook::utils
{
  template <auto arg>
  struct val
  {
    static constexpr auto value = arg;
  };

  template <template <typename...> typename propcls, typename... args>
  struct property
  {
  };

  namespace helpers
  {
    template <typename base, typename... types>
    struct unwrap_properties_impl;

    template <typename base, template <typename...> typename propcls,
              typename... args, typename... rest>
    struct unwrap_properties_impl<base, property<propcls, args...>, rest...>
        : unwrap_properties_impl<propcls<args..., base>, rest...>
    {
    };

    template <typename base>
    struct unwrap_properties_impl<base>
    {
      typedef base type;
    };

    template <typename... types>
    struct unwrap_properties;

    template <template <typename...> typename propcls, typename... args,
              typename... rest>
    struct unwrap_properties<property<propcls, args...>, rest...>
        : unwrap_properties_impl<propcls<args...>, rest...>
    {
    };

    template <typename first, typename... types>
    using unwrap_properties_t =
        typename unwrap_properties<first, types...>::type;
  } // namespace helpers

  template <typename first, typename... types>
  struct properties : helpers::unwrap_properties_t<first, types...>
  {
    typedef helpers::unwrap_properties_t<first, types...> propbase;
    typedef properties                                    base;

    using propbase::propbase;
  };
} // namespace alterhook::utils