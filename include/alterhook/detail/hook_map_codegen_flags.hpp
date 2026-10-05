/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "../utilities/traits/map_traits.hpp"

namespace alterhook::detail
{
  template <typename Adapted>
  struct hook_map_basic_flags
  {
    static utils_consteval bool is_hasher_aware()
    {
      return utils::traits::is_hasher_aware<Adapted>;
    }

    static utils_consteval bool provides_equality_comparator()
    {
      return utils::traits::provides_equality_comparator<Adapted>;
    }

    static utils_consteval bool has_ordered_map_key_comparison()
    {
      return utils::traits::has_ordered_map_key_comparison<Adapted>;
    }

    static utils_consteval bool is_core_map()
    {
      return utils::traits::is_core_map<Adapted>;
    }

    static utils_consteval bool has_hash_map_hash_policy_api()
    {
      return utils::traits::has_hash_map_hash_policy_api<Adapted>;
    }

    static utils_consteval bool has_hash_map_capacity_modification_api()
    {
      return utils::traits::has_hash_map_capacity_modification_api<Adapted>;
    }

    static utils_consteval bool has_map_basic_bucket_api()
    {
      return utils::traits::has_map_basic_bucket_api<Adapted>;
    }

    static utils_consteval bool has_map_count_method()
    {
      return utils::traits::has_map_count_method<Adapted>;
    }

    static utils_consteval bool has_map_contains_method()
    {
      return utils::traits::has_map_contains_method<Adapted>;
    }

    static utils_consteval bool has_map_standard_find_method()
    {
      return utils::traits::has_map_standard_find_method<Adapted>;
    }

    static utils_consteval bool has_map_basic_find_method()
    {
      return utils::traits::has_map_basic_find_method<Adapted>;
    }

    static utils_consteval bool has_map_standard_equal_range_method()
    {
      return utils::traits::has_map_standard_equal_range_method<Adapted>;
    }

    static utils_consteval bool has_map_basic_equal_range_method()
    {
      return utils::traits::has_map_basic_equal_range_method<Adapted>;
    }

    static utils_consteval bool has_map_at_method()
    {
      return utils::traits::has_map_at_method<Adapted>;
    }

    static utils_consteval bool has_map_access_operator()
    {
      return utils::traits::has_map_access_operator<Adapted>;
    }

    static utils_consteval bool has_map_basic_visit_method()
    {
      return utils::traits::has_map_basic_visit_method<Adapted>;
    }

    template <typename Itr>
    static utils_consteval bool has_map_range_visit_method()
    {
      return utils::traits::has_map_range_visit_method<Adapted, Itr>;
    }

    static utils_consteval bool has_map_visit_all_method()
    {
      return utils::traits::has_map_visit_all_method<Adapted>;
    }

    static utils_consteval bool has_map_visit_while_method()
    {
      return utils::traits::has_map_visit_while_method<Adapted>;
    }

    static utils_consteval bool has_map_clear_method()
    {
      return utils::traits::has_map_clear_method<Adapted>;
    }

    static utils_consteval bool has_map_key_erase_method()
    {
      return utils::traits::has_map_key_erase_method<Adapted>;
    }

    template <bool const_iterator = false>
    static utils_consteval bool has_map_iterator_erase_method()
    {
      return utils::traits::has_map_iterator_erase_method<Adapted,
                                                          const_iterator>;
    }

    template <bool const_range = false>
    static utils_consteval bool has_map_range_erase_method()
    {
      return utils::traits::has_map_range_erase_method<Adapted, const_range>;
    }

    static utils_consteval bool has_map_key_erase_if_method()
    {
      return utils::traits::has_map_key_erase_if_method<Adapted>;
    }

    static utils_consteval bool has_map_full_erase_if_method()
    {
      return utils::traits::has_map_full_erase_if_method<Adapted>;
    }

    static utils_consteval bool has_map_try_emplace_method()
    {
      return utils::traits::has_map_try_emplace_method<Adapted>;
    }

    static utils_consteval bool has_map_emplace_method()
    {
      return utils::traits::has_map_emplace_method<Adapted>;
    }

    static utils_consteval bool has_map_insert_method()
    {
      return utils::traits::has_map_insert_method<Adapted>;
    }

    static utils_consteval bool has_map_standard_try_emplace_method()
    {
      return utils::traits::has_map_standard_try_emplace_method<Adapted>;
    }

    static utils_consteval bool has_map_standard_emplace_method()
    {
      return utils::traits::has_map_standard_emplace_method<Adapted>;
    }

    static utils_consteval bool has_map_standard_insert_method()
    {
      return utils::traits::has_map_standard_insert_method<Adapted>;
    }

    template <typename Itr>
    static utils_consteval bool has_map_range_insert_method()
    {
      return utils::traits::has_map_range_insert_method<Adapted, Itr>;
    }

    template <bool const_hint = false>
    static utils_consteval bool has_map_hint_try_emplace_method()
    {
      return utils::traits::has_map_hint_try_emplace_method<Adapted,
                                                            const_hint>;
    }

    template <bool const_hint = false>
    static utils_consteval bool has_map_hint_emplace_method()
    {
      return utils::traits::has_map_hint_emplace_method<Adapted, const_hint>;
    }

    template <bool const_hint = false>
    static utils_consteval bool has_map_hint_insert_method()
    {
      return utils::traits::has_map_hint_insert_method<Adapted, const_hint>;
    }

    template <bool const_visit = false>
    static utils_consteval bool has_map_try_emplace_or_visit_method()
    {
      return utils::traits::has_map_try_emplace_or_visit_method<Adapted,
                                                                const_visit>;
    }

    template <bool const_visit = false>
    static utils_consteval bool has_map_emplace_or_visit_method()
    {
      return utils::traits::has_map_emplace_or_visit_method<Adapted,
                                                            const_visit>;
    }

    template <bool const_visit = false>
    static utils_consteval bool has_map_insert_or_visit_method()
    {
      return utils::traits::has_map_insert_or_visit_method<Adapted,
                                                           const_visit>;
    }

    template <bool const_visit = false>
    static utils_consteval bool has_map_try_emplace_and_visit_method()
    {
      return utils::traits::has_map_try_emplace_and_visit_method<Adapted,
                                                                 const_visit>;
    }

    template <bool const_visit = false>
    static utils_consteval bool has_map_emplace_and_visit_method()
    {
      return utils::traits::has_map_emplace_and_visit_method<Adapted,
                                                             const_visit>;
    }

    template <bool const_visit = false>
    static utils_consteval bool has_map_insert_and_visit_method()
    {
      return utils::traits::has_map_insert_and_visit_method<Adapted,
                                                            const_visit>;
    }

    template <bool const_iterator = false>
    static utils_consteval bool has_map_node_relocation()
    {
      return utils::traits::has_map_node_relocation<Adapted, const_iterator>;
    }
  };
} // namespace alterhook::detail
