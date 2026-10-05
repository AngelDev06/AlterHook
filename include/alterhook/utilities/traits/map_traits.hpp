/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "concepts.hpp"
#include "../other.hpp"
#include "iterator_traits.hpp"
#include "../tuple_tools.hpp"
#include <concepts>
#include <type_traits>
#include <utility>

namespace alterhook::utils::traits
{
  namespace helpers
  {
    template <typename T>
    struct dummy_visitor;

    template <typename Ret, typename... Args>
    struct dummy_visitor<Ret(Args...)>
    {
      constexpr Ret operator()(Args...) const noexcept;
    };

    template <typename MapType, bool = std::is_const_v<MapType>>
    struct map_get_ref;

    template <typename MapType>
    using map_get_ref_t = typename map_get_ref<MapType>::type;
    template <typename MapType>
    using map_get_mapped_ref_t =
        std::conditional_t<std::is_const_v<MapType>,
                           const typename MapType::mapped_type&,
                           typename MapType::mapped_type&>;
    template <typename MapType,
              bool use_const =
                  std::is_copy_constructible_v<typename MapType::key_type>>
    using map_get_key_type_t =
        std::conditional_t<use_const, const typename MapType::key_type&,
                           typename MapType::key_type>;
    template <typename MapType,
              bool use_const =
                  std::is_copy_constructible_v<typename MapType::mapped_type>>
    using map_get_mapped_type_t =
        std::conditional_t<use_const, const typename MapType::mapped_type&,
                           typename MapType::mapped_type>;
    template <typename MapType,
              bool use_const =
                  std::is_copy_constructible_v<typename MapType::value_type>>
    using map_get_value_type_t =
        std::conditional_t<use_const, const typename MapType::value_type&,
                           typename MapType::value_type>;
    template <typename MapType, bool const_visit>
    using map_get_visitor_t =
        dummy_visitor<void(map_get_ref_t<typename std::conditional_t<
                               const_visit, std::add_const<MapType>,
                               std::remove_cv<MapType>>::type>)>;
    template <typename T, bool use_const>
    using map_iterator_t =
        iter::range_iterator_t<std::conditional_t<use_const, const T, T>>;
    template <typename T>
    using size_type_t = decltype(std::declval<const T&>().size());
  } // namespace helpers

#if defined(__cpp_lib_concepts) && __cpp_lib_concepts >= 201'907L
  namespace helpers
  {
    /*
     * Map Special Objects
     */
    template <typename T>
    concept is_hasher_aware_impl =
        requires(T& map, const typename T::key_type key) {
          { map.hash_function()(key) } -> std::unsigned_integral;
        };

    template <typename T>
    concept provides_equality_comparator_impl =
        requires(T& map, const typename T::key_type key) {
          { map.key_eq()(key, key) } -> std::convertible_to<bool>;
        };

    template <typename T>
    concept has_ordered_map_key_comparison_impl =
        requires(T& map, const typename T::key_type key) {
          { map.key_comp()(key, key) } -> std::convertible_to<bool>;
        };

    template <typename Ret, typename Map>
    concept size_type_of = (!requires { typename Map::size_type; } ||
                            std::same_as<Ret, typename Map::size_type>) &&
                           std::unsigned_integral<Ret>;

    /*
     * Core Map Requirements
     */

    template <typename T>
    concept is_core_map_impl = std::destructible<T> && requires(const T& cm) {
      typename T::key_type;
      typename T::mapped_type;
      typename T::value_type;
      { cm.empty() } -> std::same_as<bool>;
      { cm.size() } -> size_type_of<T>;
    };

    /*
     * Hash Policy
     */

    template <typename T>
    concept has_hash_map_hash_policy_api_impl =
        requires(T& map, const T& cmap, float f, size_type_t<T> count) {
          { cmap.load_factor() } -> std::same_as<float>;
          { cmap.max_load_factor() } -> std::same_as<float>;
          map.max_load_factor(f);
        };

    /*
     * Capacity Update
     */

    template <typename T>
    concept has_hash_map_capacity_modification_api_impl =
        requires(T& map, size_type_t<T> count) {
          map.rehash(count);
          map.reserve(count);
        };

    /*
     * Bucket Lookup and Counting
     */

    template <typename T>
    concept has_map_basic_bucket_api_impl =
        requires(T& map, size_type_t<T> n, const typename T::key_type key) {
          { map.bucket_count() } -> std::unsigned_integral;
          { map.max_bucket_count() } -> std::unsigned_integral;
          { map.bucket_size(n) } -> std::unsigned_integral;
          { map.bucket(key) } -> std::unsigned_integral;
        };

    /*
     * Lookup API
     */

    template <typename T>
    concept has_map_count_method_impl =
        requires(T& map, const typename T::key_type key) {
          { map.count(key) } -> std::unsigned_integral;
        };

    template <typename T>
    concept has_map_contains_method_impl =
        requires(T& map, const typename T::key_type key) {
          { map.contains(key) } -> std::same_as<bool>;
        };

    template <typename T>
    concept has_map_standard_find_method_impl =
        requires(T& map, const typename T::key_type key) {
          { map.find(key) } -> iter::is_iterator_of<T>;
        };

    template <typename T>
    concept has_map_basic_find_method_impl =
        requires(T& map, const typename T::key_type key) {
          { map.find(key) } -> iter::is_any_iterator_of<T>;
        };

    template <typename T>
    concept has_map_standard_equal_range_method_impl =
        requires(T& map, const typename T::key_type key) {
          { map.equal_range(key) } -> iter::is_iterator_pair_of<T>;
        };

    template <typename T>
    concept has_map_basic_equal_range_method_impl =
        requires(T& map, const typename T::key_type key) {
          { map.equal_range(key) } -> iter::is_any_iterator_pair_of<T>;
        };

    template <typename T>
    concept has_map_at_method_impl =
        requires(T& map, const typename T::key_type key) {
          { map.at(key) } -> std::same_as<map_get_mapped_ref_t<T>>;
        };

    template <typename T>
    concept has_map_access_operator_impl =
        requires(T& m, const typename T::key_type& k) {
          { m[k] } -> std::convertible_to<map_get_mapped_ref_t<T>>;
        };

    template <typename T>
    concept has_map_basic_visit_method_impl =
        requires(T& map, const typename T::key_type key,
                 dummy_visitor<void(map_get_ref_t<T>)> visitor) {
          map.visit(key, visitor);
        };

    template <typename T, typename Itr>
    concept has_map_range_visit_method_impl = requires(
        T& map, Itr itr, dummy_visitor<void(map_get_ref_t<T>)> visitor) {
      map.visit(itr, itr, visitor);
    };

    template <typename T>
    concept has_map_visit_all_method_impl =
        requires(T& map, dummy_visitor<void(map_get_ref_t<T>)> visitor) {
          map.visit_all(visitor);
        };

    template <typename T>
    concept has_map_visit_while_method_impl =
        requires(T& map, dummy_visitor<bool(map_get_ref_t<T>)> visitor) {
          map.visit_while(visitor);
        };

    /*
     * Erasure
     */

    template <typename T>
    concept has_map_clear_method_impl = requires(T& map) { map.clear(); };

    template <typename T>
    concept has_map_key_erase_method_impl =
        requires(T& map, const typename T::key_type key) {
          { map.erase(key) } -> std::convertible_to<size_type_t<T>>;
        };

    template <typename T, bool const_iterator = false>
    concept has_map_iterator_erase_method_impl =
        requires(T& map, map_iterator_t<T, const_iterator> itr) {
          {
            map.erase(itr)
          } -> std::convertible_to<map_iterator_t<T, const_iterator>>;
        };

    template <typename T, bool const_range = false>
    concept has_map_range_erase_method_impl =
        requires(T& map, map_iterator_t<T, const_range> itr) {
          {
            map.erase(itr, itr)
          } -> std::convertible_to<map_iterator_t<T, const_range>>;
        };

    template <typename T>
    concept has_map_key_erase_if_method_impl =
        requires(T& map, const typename T::key_type key,
                 dummy_visitor<bool(map_get_ref_t<T>)> pred) {
          map.erase_if(key, pred);
        };

    template <typename T>
    concept has_map_full_erase_if_method_impl =
        requires(T& map, dummy_visitor<bool(map_get_ref_t<T>)> pred) {
          map.erase_if(pred);
        };

    /*
     * Insertion
     */

    template <typename T>
    concept has_map_try_emplace_method_impl = requires(
        T& map, map_get_key_type_t<T> key, map_get_mapped_type_t<T> val) {
      map.try_emplace(std::forward<decltype(key)>(key),
                      std::forward<decltype(val)>(val));
    };

    template <typename T>
    concept has_map_emplace_method_impl = requires(
        T& map, map_get_key_type_t<T> key, map_get_mapped_type_t<T> val) {
      map.emplace(std::forward<decltype(key)>(key),
                  std::forward<decltype(val)>(val));
    };

    template <typename T>
    concept has_map_insert_method_impl =
        requires(T& map, map_get_value_type_t<T> item) {
          map.insert(std::forward<decltype(item)>(item));
        };

    template <typename Ret, typename T>
    concept standard_multimap_insert_ret_of = iter::is_iterator_of<Ret, T>;

    template <typename Ret, typename T>
    concept standard_singlemap_insert_ret_of = requires {
      typename iter::range_iterator_t<T>;
    } && tuple_unpacks_to<Ret, iter::range_iterator_t<T>, bool>;

    template <typename Ret, typename T>
    concept standard_map_insert_ret_of =
        standard_singlemap_insert_ret_of<Ret, T> ||
        standard_multimap_insert_ret_of<Ret, T>;

    template <typename T>
    concept has_map_standard_try_emplace_method_impl = requires(
        T& map, map_get_key_type_t<T> key, map_get_mapped_type_t<T> val) {
      {
        map.try_emplace(std::forward<decltype(key)>(key),
                        std::forward<decltype(val)>(val))
      } -> standard_map_insert_ret_of<T>;
    };

    template <typename T>
    concept has_map_standard_emplace_method_impl = requires(
        T& map, map_get_key_type_t<T> key, map_get_mapped_type_t<T> val) {
      {
        map.emplace(std::forward<decltype(key)>(key),
                    std::forward<decltype(val)>(val))
      } -> standard_map_insert_ret_of<T>;
    };

    template <typename T>
    concept has_map_standard_insert_method_impl =
        requires(T& map, map_get_value_type_t<T> item) {
          {
            map.insert(std::forward<decltype(item)>(item))
          } -> standard_map_insert_ret_of<T>;
        };

    template <typename T, typename Itr>
    concept has_map_range_insert_method_impl =
        requires(T& map, Itr itr) { map.insert(itr, itr); };

    template <typename T, bool const_hint = false>
    concept has_map_hint_try_emplace_method_impl =
        requires(T& map, map_iterator_t<T, const_hint> hint,
                 map_get_key_type_t<T> key, map_get_mapped_type_t<T> val) {
          {
            map.try_emplace(hint, std::forward<decltype(key)>(key),
                            std::forward<decltype(val)>(val))
          } -> iter::is_any_iterator_of<T>;
        };

    template <typename T, bool const_hint = false>
    concept has_map_hint_emplace_method_impl =
        requires(T& map, map_iterator_t<T, const_hint> hint,
                 map_get_key_type_t<T> key, map_get_mapped_type_t<T> val) {
          {
            map.emplace_hint(hint, std::forward<decltype(key)>(key),
                             std::forward<decltype(val)>(val))
          } -> iter::is_any_iterator_of<T>;
        };

    template <typename T, bool const_hint = false>
    concept has_map_hint_insert_method_impl =
        requires(T& map, map_iterator_t<T, const_hint> hint,
                 map_get_value_type_t<T> item) {
          {
            map.insert(hint, std::forward<decltype(item)>(item))
          } -> iter::is_any_iterator_of<T>;
        };

    template <typename T, bool const_visit = false>
    concept has_map_try_emplace_or_visit_method_impl =
        (!const_visit &&
         requires(T& map, map_get_key_type_t<T> key,
                  map_get_mapped_type_t<T>          val,
                  map_get_visitor_t<T, const_visit> visitor) {
           map.try_emplace_or_visit(std::forward<decltype(key)>(key),
                                    std::forward<decltype(val)>(val), visitor);
         }) ||
        (const_visit && requires(T& map, map_get_key_type_t<T> key,
                                 map_get_mapped_type_t<T>          val,
                                 map_get_visitor_t<T, const_visit> visitor) {
          map.try_emplace_or_cvisit(std::forward<decltype(key)>(key),
                                    std::forward<decltype(val)>(val), visitor);
        });

    template <typename T, bool const_visit = false>
    concept has_map_emplace_or_visit_method_impl =
        (!const_visit &&
         requires(T& map, map_get_key_type_t<T> key,
                  map_get_mapped_type_t<T>          val,
                  map_get_visitor_t<T, const_visit> visitor) {
           map.emplace_or_visit(std::forward<decltype(key)>(key),
                                std::forward<decltype(val)>(val), visitor);
         }) ||
        (const_visit && requires(T& map, map_get_key_type_t<T> key,
                                 map_get_mapped_type_t<T>          val,
                                 map_get_visitor_t<T, const_visit> visitor) {
          map.emplace_or_cvisit(std::forward<decltype(key)>(key),
                                std::forward<decltype(val)>(val), visitor);
        });

    template <typename T, bool const_visit = false>
    concept has_map_insert_or_visit_method_impl =
        (!const_visit &&
         requires(T& map, map_get_value_type_t<T> item,
                  map_get_visitor_t<T, const_visit> visitor) {
           map.insert_or_visit(std::forward<decltype(item)>(item), visitor);
         }) ||
        (const_visit && requires(T& map, map_get_value_type_t<T> item,
                                 map_get_visitor_t<T, const_visit> visitor) {
          map.insert_or_cvisit(std::forward<decltype(item)>(item), visitor);
        });

    template <typename T, bool const_visit = false>
    concept has_map_try_emplace_and_visit_method_impl =
        (!const_visit &&
         requires(T& map, map_get_key_type_t<T> key,
                  map_get_mapped_type_t<T>    val,
                  map_get_visitor_t<T, false> visitor) {
           map.try_emplace_and_visit(std::forward<decltype(key)>(key),
                                     std::forward<decltype(val)>(val), visitor,
                                     visitor);
         }) ||
        (const_visit && requires(T& map, map_get_key_type_t<T> key,
                                 map_get_mapped_type_t<T>    val,
                                 map_get_visitor_t<T, false> and_visitor,
                                 map_get_visitor_t<T, true>  or_visitor) {
          map.try_emplace_and_cvisit(std::forward<decltype(key)>(key),
                                     std::forward<decltype(val)>(val),
                                     and_visitor, or_visitor);
        });

    template <typename T, bool const_visit = false>
    concept has_map_emplace_and_visit_method_impl =
        (!const_visit &&
         requires(T& map, map_get_key_type_t<T> key,
                  map_get_mapped_type_t<T>    val,
                  map_get_visitor_t<T, false> visitor) {
           map.emplace_and_visit(std::forward<decltype(key)>(key),
                                 std::forward<decltype(val)>(val), visitor,
                                 visitor);
         }) ||
        (const_visit && requires(T& map, map_get_key_type_t<T> key,
                                 map_get_mapped_type_t<T>    val,
                                 map_get_visitor_t<T, false> and_visitor,
                                 map_get_visitor_t<T, true>  or_visitor) {
          map.emplace_and_cvisit(std::forward<decltype(key)>(key),
                                 std::forward<decltype(val)>(val), and_visitor,
                                 or_visitor);
        });

    template <typename T, bool const_visit = false>
    concept has_map_insert_and_visit_method_impl =
        (!const_visit &&
         requires(T& map, map_get_value_type_t<T> item,
                  map_get_visitor_t<T, false> visitor) {
           map.insert_and_visit(std::forward<decltype(item)>(item), visitor,
                                visitor);
         }) ||
        (const_visit && requires(T& map, map_get_value_type_t<T> item,
                                 map_get_visitor_t<T, false> and_visitor,
                                 map_get_visitor_t<T, true>  or_visitor) {
          map.insert_and_cvisit(std::forward<decltype(item)>(item), and_visitor,
                                or_visitor);
        });

    /*
     * Node Relocation
     */
    template <typename Node, typename T>
    concept basic_map_node_of = requires(Node node, T& map) {
      { node.key() } -> std::same_as<typename T::key_type&>;
      { node.mapped() } -> std::same_as<typename T::mapped_type&>;
      map.insert(std::move(node));
    };

    template <typename Node, typename T>
    concept basic_nullable_map_node_of =
        basic_map_node_of<Node, T> && requires(Node node) {
          { node.empty() } -> std::same_as<bool>;
        };

    template <typename NodeInsertRet, typename Map>
    concept map_node_insert_ret_of =
        iter::is_any_iterator_of<NodeInsertRet, Map> ||
        requires(NodeInsertRet ret) {
          { ret.position } -> iter::converts_to_any_iterator_of<Map>;
          { ret.inserted } -> std::same_as<bool&>;
          { ret.node } -> basic_map_node_of<Map>;
        };

    template <typename Node, typename T>
    concept map_node_insertable_to = requires(T& map, Node node) {
      { map.insert(std::move(node)) } -> map_node_insert_ret_of<T>;
    };

    template <typename Node, typename T>
    concept map_node_of =
        basic_map_node_of<Node, T> && map_node_insertable_to<Node, T>;

    template <typename Node, typename T>
    concept nullable_map_node_of =
        basic_nullable_map_node_of<Node, T> && map_node_insertable_to<Node, T>;

    template <typename T, bool const_iterator = false>
    concept has_map_node_relocation_impl =
        requires(T& map, const typename T::key_type key,
                 map_iterator_t<T, const_iterator> itr) {
          { map.extract(itr) } -> map_node_of<T>;
          { map.extract(key) } -> nullable_map_node_of<T>;
        };
  } // namespace helpers
#else
  namespace helpers
  {
    template <typename T, typename = void>
    constexpr bool is_hasher_aware_impl = false;

    template <typename T, typename = void>
    constexpr bool provides_equality_comparator_impl = false;

    template <typename T, typename = void>
    constexpr bool has_ordered_map_key_comparison_impl = false;

    template <typename T, typename = void>
    constexpr bool is_core_map_impl = false;

    template <typename T, typename = void>
    constexpr bool has_hash_map_hash_policy_api_impl = false;

    template <typename T, typename = void>
    constexpr bool has_hash_map_capacity_modification_api_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_basic_bucket_api_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_count_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_contains_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_standard_find_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_basic_find_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_standard_equal_range_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_basic_equal_range_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_at_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_access_operator_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_basic_visit_method_impl = false;

    template <typename T, typename Itr, typename = void>
    constexpr bool has_map_range_visit_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_visit_all_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_visit_while_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_clear_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_key_erase_method_impl = false;

    template <typename T, bool const_iterator = false, typename = void>
    constexpr bool has_map_iterator_erase_method_impl = false;

    template <typename T, bool const_range = false, typename = void>
    constexpr bool has_map_range_erase_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_key_erase_if_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_full_erase_if_method_impl = false;

    template <typename T>
    using map_try_emplace_t = decltype(std::declval<T&>().try_emplace(
        std::declval<map_get_key_type_t<T>>(),
        std::declval<map_get_mapped_type_t<T>>()));
    template <typename T>
    using map_emplace_t = decltype(std::declval<T&>().emplace(
        std::declval<map_get_key_type_t<T>>(),
        std::declval<map_get_mapped_type_t<T>>()));
    template <typename T>
    using map_insert_t = decltype(std::declval<T&>().insert(
        std::declval<map_get_value_type_t<T>>()));

    template <typename T>
    constexpr bool has_map_try_emplace_method_impl =
        can_substitute<map_try_emplace_t, T>;
    template <typename T>
    constexpr bool has_map_emplace_method_impl =
        can_substitute<map_emplace_t, T>;
    template <typename T>
    constexpr bool has_map_insert_method_impl = can_substitute<map_insert_t, T>;

    template <typename T, typename = void>
    constexpr bool has_map_standard_try_emplace_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_standard_emplace_method_impl = false;

    template <typename T, typename = void>
    constexpr bool has_map_standard_insert_method_impl = false;

    template <typename T, typename Itr, typename = void>
    constexpr bool has_map_range_insert_method_impl = false;

    template <typename T, bool const_hint = false, typename = void>
    constexpr bool has_map_hint_try_emplace_method_impl = false;

    template <typename T, bool const_hint = false, typename = void>
    constexpr bool has_map_hint_emplace_method_impl = false;

    template <typename T, bool const_hint = false, typename = void>
    constexpr bool has_map_hint_insert_method_impl = false;

    template <typename T, bool const_visit = false, typename = void>
    constexpr bool has_map_try_emplace_or_visit_method_impl = false;

    template <typename T, bool const_visit = false, typename = void>
    constexpr bool has_map_emplace_or_visit_method_impl = false;

    template <typename T, bool const_visit = false, typename = void>
    constexpr bool has_map_insert_or_visit_method_impl = false;

    template <typename T, bool const_visit = false, typename = void>
    constexpr bool has_map_try_emplace_and_visit_method_impl = false;

    template <typename T, bool const_visit = false, typename = void>
    constexpr bool has_map_emplace_and_visit_method_impl = false;

    template <typename T, bool const_visit = false, typename = void>
    constexpr bool has_map_insert_and_visit_method_impl = false;

    template <typename Node, typename T, typename = void>
    constexpr bool basic_map_node_of = false;

    template <typename Node, typename T, typename = void>
    constexpr bool basic_nullable_map_node_of = false;

    template <typename NodeInsertRet, typename Map, typename = void>
    constexpr bool map_node_insert_ret_of = false;

    template <typename Node, typename T, typename = void>
    constexpr bool map_node_insertable_to = false;

    template <typename Node, typename T, typename = void>
    constexpr bool map_node_of = false;

    template <typename Node, typename T, typename = void>
    constexpr bool nullable_map_node_of = false;

    template <typename T, bool const_iterator = false, typename = void>
    constexpr bool has_map_node_relocation_impl = false;
  } // namespace helpers
#endif

  template <typename T>
  utils_concept is_hasher_aware =
      helpers::is_hasher_aware_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept provides_equality_comparator =
      helpers::provides_equality_comparator_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_ordered_map_key_comparison =
      helpers::has_ordered_map_key_comparison_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept is_core_map = helpers::is_core_map_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_hash_map_hash_policy_api =
      helpers::has_hash_map_hash_policy_api_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_hash_map_capacity_modification_api =
      helpers::has_hash_map_capacity_modification_api_impl<
          std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_basic_bucket_api =
      helpers::has_map_basic_bucket_api_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_count_method =
      helpers::has_map_count_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_contains_method =
      helpers::has_map_contains_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_standard_find_method =
      helpers::has_map_standard_find_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_basic_find_method =
      helpers::has_map_basic_find_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_standard_equal_range_method =
      helpers::has_map_standard_equal_range_method_impl<
          std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_basic_equal_range_method =
      helpers::has_map_basic_equal_range_method_impl<
          std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_at_method =
      helpers::has_map_at_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_access_operator =
      helpers::has_map_access_operator_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_basic_visit_method =
      helpers::has_map_basic_visit_method_impl<std::remove_reference_t<T>>;

  template <typename T, typename Itr>
  utils_concept has_map_range_visit_method =
      helpers::has_map_range_visit_method_impl<std::remove_reference_t<T>, Itr>;

  template <typename T>
  utils_concept has_map_visit_all_method =
      helpers::has_map_visit_all_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_visit_while_method =
      helpers::has_map_visit_while_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_clear_method =
      helpers::has_map_clear_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_key_erase_method =
      helpers::has_map_key_erase_method_impl<std::remove_reference_t<T>>;

  template <typename T, bool const_iterator = false>
  utils_concept has_map_iterator_erase_method =
      helpers::has_map_iterator_erase_method_impl<std::remove_reference_t<T>,
                                                  const_iterator>;

  template <typename T, bool const_range = false>
  utils_concept has_map_range_erase_method =
      helpers::has_map_range_erase_method_impl<std::remove_reference_t<T>,
                                               const_range>;

  template <typename T>
  utils_concept has_map_key_erase_if_method =
      helpers::has_map_key_erase_if_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_full_erase_if_method =
      helpers::has_map_full_erase_if_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_try_emplace_method =
      helpers::has_map_try_emplace_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_emplace_method =
      helpers::has_map_emplace_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_insert_method =
      helpers::has_map_insert_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_standard_try_emplace_method =
      helpers::has_map_standard_try_emplace_method_impl<
          std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_standard_emplace_method =
      helpers::has_map_standard_emplace_method_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_map_standard_insert_method =
      helpers::has_map_standard_insert_method_impl<std::remove_reference_t<T>>;

  template <typename T, typename Itr>
  utils_concept has_map_range_insert_method =
      helpers::has_map_range_insert_method_impl<std::remove_reference_t<T>,
                                                Itr>;

  template <typename T, bool const_hint = false>
  utils_concept has_map_hint_try_emplace_method =
      helpers::has_map_hint_try_emplace_method_impl<std::remove_reference_t<T>,
                                                    const_hint>;

  template <typename T, bool const_hint = false>
  utils_concept has_map_hint_emplace_method =
      helpers::has_map_hint_emplace_method_impl<std::remove_reference_t<T>,
                                                const_hint>;

  template <typename T, bool const_hint = false>
  utils_concept has_map_hint_insert_method =
      helpers::has_map_hint_insert_method_impl<std::remove_reference_t<T>,
                                               const_hint>;

  template <typename T, bool const_visit = false>
  utils_concept has_map_try_emplace_or_visit_method =
      helpers::has_map_try_emplace_or_visit_method_impl<
          std::remove_reference_t<T>, const_visit>;

  template <typename T, bool const_visit = false>
  utils_concept has_map_emplace_or_visit_method =
      helpers::has_map_emplace_or_visit_method_impl<std::remove_reference_t<T>,
                                                    const_visit>;

  template <typename T, bool const_visit = false>
  utils_concept has_map_insert_or_visit_method =
      helpers::has_map_insert_or_visit_method_impl<std::remove_reference_t<T>,
                                                   const_visit>;

  template <typename T, bool const_visit = false>
  utils_concept has_map_try_emplace_and_visit_method =
      helpers::has_map_try_emplace_and_visit_method_impl<
          std::remove_reference_t<T>, const_visit>;

  template <typename T, bool const_visit = false>
  utils_concept has_map_emplace_and_visit_method =
      helpers::has_map_emplace_and_visit_method_impl<std::remove_reference_t<T>,
                                                     const_visit>;

  template <typename T, bool const_visit = false>
  utils_concept has_map_insert_and_visit_method =
      helpers::has_map_insert_and_visit_method_impl<std::remove_reference_t<T>,
                                                    const_visit>;

  template <typename T, bool const_iterator = false>
  utils_concept has_map_node_relocation =
      helpers::has_map_node_relocation_impl<std::remove_reference_t<T>,
                                            const_iterator>;

  namespace helpers
  {
    template <typename MapType, bool>
    struct map_get_ref
    {
      using type =
          reference_optional_type_member_of<MapType,
                                            typename MapType::value_type&>;
    };

    template <typename MapType>
    struct map_get_ref<MapType, true>
    {
      using type = const_reference_optional_type_member_of<
          MapType, const typename MapType::value_type&>;
    };

#if !(defined(__cpp_lib_concepts) && __cpp_lib_concepts >= 201'907L)
    template <typename T>
    constexpr bool unsigned_integral =
        std::conjunction_v<std::is_integral<T>, std::is_unsigned<T>>;

    template <typename T>
    struct unsigned_integral_s : std::bool_constant<unsigned_integral<T>>
    {
    };

    template <typename T>
    constexpr bool is_hasher_aware_impl<
        T, std::enable_if_t<
               unsigned_integral<decltype(std::declval<T&>().hash_function()(
                   std::declval<const typename T::key_type&>()))>>> = true;

    template <typename T>
    constexpr bool provides_equality_comparator_impl<
        T, std::enable_if_t<std::is_convertible_v<
               decltype(std::declval<T&>().key_eq()(
                   std::declval<const typename T::key_type&>(),
                   std::declval<const typename T::key_type&>())),
               bool>>> = true;

    template <typename T>
    constexpr bool has_ordered_map_key_comparison_impl<
        T, std::enable_if_t<std::is_convertible_v<
               decltype(std::declval<T&>().key_comp()(
                   std::declval<const typename T::key_type&>(),
                   std::declval<const typename T::key_type&>())),
               bool>>> = true;

    template <typename Ret, typename Map, typename = void>
    constexpr bool size_type_of = unsigned_integral<Ret>;
    template <typename Ret, typename Map>
    constexpr bool
        size_type_of<Ret, Map, std::void_t<typename Map::size_type>> =
            std::conjunction_v<std::is_same<Ret, typename Map::size_type>,
                               unsigned_integral_s<Ret>>;

    template <typename Ret, typename Map>
    struct size_type_of_s : std::bool_constant<size_type_of<Ret, Map>>
    {
    };

    template <typename T>
    constexpr bool is_core_map_impl<
        T,
        std::enable_if_t<
            std::conjunction_v<
                std::is_same<decltype(std::declval<const T&>().empty()), bool>,
                size_type_of_s<decltype(std::declval<const T&>().size()), T>>,
            std::void_t<typename T::key_type, typename T::mapped_type,
                        typename T::value_type>>> = true;

    template <typename T>
    constexpr bool has_hash_map_hash_policy_api_impl<
        T, std::enable_if_t<
               std::conjunction_v<
                   std::is_same<
                       decltype(std::declval<const T&>().load_factor()), float>,
                   std::is_same<
                       decltype(std::declval<const T&>().max_load_factor()),
                       float>>,
               std::void_t<decltype(std::declval<T&>().max_load_factor(
                   float{}))>>> = true;

    template <typename T>
    constexpr bool has_hash_map_capacity_modification_api_impl<
        T, std::void_t<decltype(std::declval<T&>().rehash(
                           std::declval<size_type_t<T>>())),
                       decltype(std::declval<T&>().reserve(
                           std::declval<size_type_t<T>>()))>> = true;

    template <typename T>
    constexpr bool has_map_basic_bucket_api_impl<
        T, std::enable_if_t<std::conjunction_v<
               unsigned_integral_s<decltype(std::declval<T&>().bucket_count())>,
               unsigned_integral_s<
                   decltype(std::declval<T&>().max_bucket_count())>,
               unsigned_integral_s<decltype(std::declval<T&>().bucket_size(
                   std::declval<size_type_t<T>>()))>,
               unsigned_integral_s<decltype(std::declval<T&>().bucket(
                   std::declval<const typename T::key_type&>()))>>>> = true;

    template <typename T>
    constexpr bool has_map_count_method_impl<
        T, std::enable_if_t<unsigned_integral<decltype(std::declval<T&>().count(
               std::declval<const typename T::key_type&>()))>>> = true;

    template <typename T>
    constexpr bool has_map_contains_method_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().contains(
                                  std::declval<const typename T::key_type&>())),
                              bool>>> = true;

    template <typename T>
    constexpr bool has_map_basic_find_method_impl<
        T, std::enable_if_t<iter::is_any_iterator_of<
               decltype(std::declval<T&>().find(
                   std::declval<const typename T::key_type&>())),
               T>>> = true;

    template <typename T>
    constexpr bool has_map_standard_find_method_impl<
        T, std::enable_if_t<iter::is_iterator_of<
               decltype(std::declval<T&>().find(
                   std::declval<const typename T::key_type&>())),
               T>>> = true;

    template <typename T>
    constexpr bool has_map_basic_equal_range_method_impl<
        T, std::enable_if_t<iter::is_any_iterator_pair_of<
               decltype(std::declval<T&>().equal_range(
                   std::declval<const typename T::key_type&>())),
               T>>> = true;

    template <typename T>
    constexpr bool has_map_standard_equal_range_method_impl<
        T, std::enable_if_t<iter::is_iterator_pair_of<
               decltype(std::declval<T&>().equal_range(
                   std::declval<const typename T::key_type&>())),
               T>>> = true;

    template <typename T>
    constexpr bool has_map_at_method_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().at(
                                  std::declval<const typename T::key_type&>())),
                              map_get_mapped_ref_t<T>>>> = true;

    template <typename T>
    constexpr bool has_map_access_operator_impl<
        T, std::enable_if_t<
               std::is_convertible_v<decltype(std::declval<T&>()[std::declval<
                                         const typename T::key_type&>()]),
                                     map_get_mapped_ref_t<T>>>> = true;

    template <typename T>
    constexpr bool has_map_basic_visit_method_impl<
        T, std::void_t<decltype(std::declval<T&>().visit(
               std::declval<const typename T::key_type&>(),
               dummy_visitor<void(map_get_ref_t<T>)>{}))>> = true;

    template <typename T, typename Itr>
    constexpr bool has_map_range_visit_method_impl<
        T, Itr,
        std::void_t<decltype(std::declval<T&>().visit(
            std::declval<Itr>(), std::declval<Itr>(),
            dummy_visitor<void(map_get_ref_t<T>)>{}))>> = true;

    template <typename T>
    constexpr bool has_map_visit_all_method_impl<
        T, std::void_t<decltype(std::declval<T&>().visit_all(
               dummy_visitor<void(map_get_ref_t<T>)>{}))>> = true;

    template <typename T>
    constexpr bool has_map_visit_while_method_impl<
        T, std::void_t<decltype(std::declval<T&>().visit_while(
               dummy_visitor<bool(map_get_ref_t<T>)>{}))>> = true;

    template <typename T>
    constexpr bool has_map_clear_method_impl<
        T, std::void_t<decltype(std::declval<T&>().clear())>> = true;

    template <typename T>
    constexpr bool has_map_key_erase_method_impl<
        T, std::enable_if_t<std::is_convertible_v<
               decltype(std::declval<T&>().erase(
                   std::declval<const typename T::key_type&>())),
               size_type_t<T>>>> = true;

    template <typename T, bool const_iterator>
    constexpr bool has_map_iterator_erase_method_impl<
        T, const_iterator,
        std::enable_if_t<std::is_convertible_v<
            decltype(std::declval<T&>().erase(
                std::declval<map_iterator_t<T, const_iterator>>())),
            map_iterator_t<T, const_iterator>>>> = true;

    template <typename T, bool const_range>
    constexpr bool has_map_range_erase_method_impl<
        T, const_range,
        std::enable_if_t<std::is_convertible_v<
            decltype(std::declval<T&>().erase(
                std::declval<map_iterator_t<T, const_range>>(),
                std::declval<map_iterator_t<T, const_range>>())),
            map_iterator_t<T, const_range>>>> = true;

    template <typename T>
    constexpr bool has_map_key_erase_if_method_impl<
        T, std::void_t<decltype(std::declval<T&>().erase_if(
               std::declval<const typename T::key_type&>(),
               dummy_visitor<bool(map_get_ref_t<T>)>{}))>> = true;

    template <typename T>
    constexpr bool has_map_full_erase_if_method_impl<
        T, std::void_t<decltype(std::declval<T&>().erase_if(
               dummy_visitor<bool(map_get_ref_t<T>)>{}))>> = true;

    template <typename Ret, typename T, typename = void>
    constexpr bool standard_multimap_insert_ret_of = false;

    template <typename Ret, typename T>
    constexpr bool standard_multimap_insert_ret_of<
        Ret, T,
        std::enable_if_t<std::is_same_v<Ret, iter::range_iterator_t<T>>>> =
        true;

    template <typename Ret, typename T>
    struct standard_multimap_insert_ret_of_s
        : std::bool_constant<standard_multimap_insert_ret_of<Ret, T>>
    {
    };

    template <typename Ret, typename T, typename = void>
    constexpr bool standard_singlemap_insert_ret_of = false;

    template <typename Ret, typename T>
    constexpr bool standard_singlemap_insert_ret_of<
        Ret, T,
        std::enable_if_t<
            tuple_unpacks_to<Ret, iter::range_iterator_t<T>, bool>>> = true;

    template <typename Ret, typename T>
    struct standard_singlemap_insert_ret_of_s
        : std::bool_constant<standard_singlemap_insert_ret_of<Ret, T>>
    {
    };

    template <typename Ret, typename T>
    constexpr bool standard_map_insert_ret_of = std::disjunction_v<
        std::bool_constant<standard_singlemap_insert_ret_of<Ret, T>>,
        standard_multimap_insert_ret_of_s<Ret, T>>;

    template <typename T>
    constexpr bool has_map_standard_try_emplace_method_impl<
        T,
        std::enable_if_t<standard_map_insert_ret_of<map_try_emplace_t<T>, T>>> =
        true;

    template <typename T>
    constexpr bool has_map_standard_emplace_method_impl<
        T, std::enable_if_t<standard_map_insert_ret_of<map_emplace_t<T>, T>>> =
        true;

    template <typename T>
    constexpr bool has_map_standard_insert_method_impl<
        T, std::enable_if_t<standard_map_insert_ret_of<map_insert_t<T>, T>>> =
        true;

    template <typename T, typename Itr>
    constexpr bool has_map_range_insert_method_impl<
        T, Itr,
        std::void_t<decltype(std::declval<T&>().insert(
            std::declval<Itr&>(), std::declval<Itr&>()))>> = true;

    template <typename T, bool const_hint>
    constexpr bool has_map_hint_try_emplace_method_impl<
        T, const_hint,
        std::enable_if_t<iter::is_any_iterator_of<
            decltype(std::declval<T&>().try_emplace(
                std::declval<map_iterator_t<T, const_hint>>(),
                std::declval<map_get_key_type_t<T>>(),
                std::declval<map_get_mapped_type_t<T>>())),
            T>>> = true;

    template <typename T, bool const_hint>
    constexpr bool has_map_hint_emplace_method_impl<
        T, const_hint,
        std::enable_if_t<iter::is_any_iterator_of<
            decltype(std::declval<T&>().emplace_hint(
                std::declval<map_iterator_t<T, const_hint>>(),
                std::declval<map_get_key_type_t<T>>(),
                std::declval<map_get_mapped_type_t<T>>())),
            T>>> = true;

    template <typename T, bool const_hint>
    constexpr bool has_map_hint_insert_method_impl<
        T, const_hint,
        std::enable_if_t<iter::is_any_iterator_of<
            decltype(std::declval<T&>().insert(
                std::declval<map_iterator_t<T, const_hint>>(),
                std::declval<map_get_key_type_t<T>>(),
                std::declval<map_get_mapped_type_t<T>>())),
            T>>> = true;

    template <typename T, typename... Types>
    using map_try_emplace_or_visit_t =
        decltype(std::declval<T&>().try_emplace_or_visit(
            std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_try_emplace_or_cvisit_t =
        decltype(std::declval<T&>().try_emplace_or_cvisit(
            std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_emplace_or_visit_t =
        decltype(std::declval<T&>().emplace_or_visit(std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_emplace_or_cvisit_t =
        decltype(std::declval<T&>().emplace_or_cvisit(
            std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_insert_or_visit_t =
        decltype(std::declval<T&>().insert_or_visit(std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_insert_or_cvisit_t =
        decltype(std::declval<T&>().insert_or_cvisit(std::declval<Types>()...));

    template <typename T, typename... Types>
    using map_try_emplace_and_visit_t =
        decltype(std::declval<T&>().try_emplace_and_visit(
            std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_try_emplace_and_cvisit_t =
        decltype(std ::declval<T&>().try_emplace_and_cvisit(
            std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_emplace_and_visit_t =
        decltype(std::declval<T&>().emplace_and_visit(
            std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_emplace_and_cvisit_t =
        decltype(std::declval<T&>().emplace_and_cvisit(
            std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_insert_and_visit_t =
        decltype(std::declval<T&>().insert_and_visit(std::declval<Types>()...));
    template <typename T, typename... Types>
    using map_insert_and_cvisit_t =
        decltype(std::declval<T&>().insert_and_cvisit(
            std::declval<Types>()...));

    template <template <template <typename, typename...> typename, typename,
                        bool> typename ArgsPropagator,
              template <typename, typename...> typename VisitTmpl,
              template <typename, typename...> typename CVisitTmpl, typename T,
              bool const_visit>
    using insertion_and_visitation_selector = ArgsPropagator<
        std::conditional_t<const_visit, template_wrapper<CVisitTmpl>,
                           template_wrapper<VisitTmpl>>::template apply,
        T, const_visit>;

    template <template <typename, typename...> typename Tmpl, typename T,
              bool const_visit>
    using emplace_or_visit_dispatch =
        Tmpl<T, map_get_key_type_t<T>, map_get_mapped_type_t<T>,
             map_get_visitor_t<T, const_visit>>;
    template <template <typename, typename...> typename Tmpl, typename T,
              bool const_visit>
    using insert_or_visit_dispatch =
        Tmpl<T, map_get_value_type_t<T>, map_get_visitor_t<T, const_visit>>;
    template <template <typename, typename...> typename Tmpl, typename T,
              bool const_visit>
    using emplace_and_visit_dispatch =
        Tmpl<T, map_get_key_type_t<T>, map_get_mapped_type_t<T>,
             map_get_visitor_t<T, false>, map_get_visitor_t<T, const_visit>>;
    template <template <typename, typename...> typename Tmpl, typename T,
              bool const_visit>
    using insert_and_visit_dispatch =
        Tmpl<T, map_get_value_type_t<T>, map_get_visitor_t<T, false>,
             map_get_visitor_t<T, const_visit>>;

    template <typename T, bool const_visit>
    constexpr bool has_map_try_emplace_or_visit_method_impl<
        T, const_visit,
        std::void_t<insertion_and_visitation_selector<
            emplace_or_visit_dispatch, map_try_emplace_or_visit_t,
            map_try_emplace_or_cvisit_t, T, const_visit>>> = true;

    template <typename T, bool const_visit>
    constexpr bool has_map_emplace_or_visit_method_impl<
        T, const_visit,
        std::void_t<insertion_and_visitation_selector<
            emplace_or_visit_dispatch, map_emplace_or_visit_t,
            map_emplace_or_cvisit_t, T, const_visit>>> = true;

    template <typename T, bool const_visit>
    constexpr bool has_map_insert_or_visit_method_impl<
        T, const_visit,
        std::void_t<insertion_and_visitation_selector<
            insert_or_visit_dispatch, map_insert_or_visit_t,
            map_insert_or_cvisit_t, T, const_visit>>> = true;

    template <typename T, bool const_visit>
    constexpr bool has_map_try_emplace_and_visit_method_impl<
        T, const_visit,
        std::void_t<insertion_and_visitation_selector<
            emplace_and_visit_dispatch, map_try_emplace_and_visit_t,
            map_try_emplace_and_cvisit_t, T, const_visit>>> = true;

    template <typename T, bool const_visit>
    constexpr bool has_map_emplace_and_visit_method_impl<
        T, const_visit,
        std::void_t<insertion_and_visitation_selector<
            emplace_and_visit_dispatch, map_emplace_and_visit_t,
            map_emplace_and_cvisit_t, T, const_visit>>> = true;

    template <typename T, bool const_visit>
    constexpr bool has_map_insert_and_visit_method_impl<
        T, const_visit,
        std::void_t<insertion_and_visitation_selector<
            insert_and_visit_dispatch, map_insert_and_visit_t,
            map_insert_and_cvisit_t, T, const_visit>>> = true;

    template <typename Node, typename T>
    constexpr bool basic_map_node_of<
        Node, T,
        std::enable_if_t<
            std::conjunction_v<
                std::is_same<decltype(std::declval<Node&>().key()),
                             typename T::key_type&>,
                std::is_same<decltype(std::declval<Node&>().mapped()),
                             typename T::mapped_type&>>,
            std::void_t<decltype(std::declval<T&>().insert(
                std::declval<Node>()))>>> = true;

    template <typename Node, typename T>
    struct basic_map_node_of_s : std::bool_constant<basic_map_node_of<Node, T>>
    {
    };

    template <typename Node, typename T>
    constexpr bool basic_nullable_map_node_of<
        Node, T,
        std::enable_if_t<std::conjunction_v<
            basic_map_node_of_s<Node, T>,
            std::is_same<decltype(std::declval<Node&>().empty()), bool>>>> =
        true;

    template <typename NodeInsertRet, typename Map, typename = void>
    constexpr bool map_node_insert_ret_of_impl = false;
    template <typename NodeInsertRet, typename Map>
    constexpr bool map_node_insert_ret_of_impl<
        NodeInsertRet, Map,
        std::enable_if_t<std::conjunction_v<
            std::bool_constant<iter::converts_to_any_iterator_of<
                decltype(std::declval<NodeInsertRet&>().position), Map>>,
            std::is_same<decltype(std::declval<NodeInsertRet&>().inserted),
                         bool>,
            basic_map_node_of_s<decltype(std::declval<NodeInsertRet&>().node),
                                Map>>>> = true;

    template <typename NodeInsertRet, typename Map>
    struct map_node_insert_ret_of_impl_s
        : std::bool_constant<map_node_insert_ret_of_impl<NodeInsertRet, Map>>
    {
    };

    template <typename NodeInsertRet, typename Map>
    constexpr bool map_node_insert_ret_of<
        NodeInsertRet, Map,
        std::enable_if_t<std::disjunction_v<
            std::bool_constant<iter::is_any_iterator_of<NodeInsertRet, Map>>,
            map_node_insert_ret_of_impl_s<NodeInsertRet, Map>>>> = true;

    template <typename Node, typename T>
    constexpr bool map_node_insertable_to<
        Node, T,
        std::enable_if_t<map_node_insert_ret_of<
            decltype(std::declval<T&>().insert(std::declval<Node>())), T>>> =
        true;

    template <typename Node, typename T>
    struct map_node_insertable_to_s
        : std::bool_constant<map_node_insertable_to<Node, T>>
    {
    };

    template <typename Node, typename T>
    constexpr bool map_node_of<
        Node, T,
        std::enable_if_t<std::conjunction_v<
            basic_map_node_of_s<Node, T>, map_node_insertable_to_s<Node, T>>>> =
        true;

    template <typename Node, typename T>
    constexpr bool nullable_map_node_of<
        Node, T,
        std::enable_if_t<std::conjunction_v<
            std::bool_constant<basic_nullable_map_node_of<Node, T>>,
            map_node_insertable_to_s<Node, T>>>> = true;

    template <typename Node, typename T>
    struct nullable_map_node_of_s
        : std::bool_constant<nullable_map_node_of<Node, T>>
    {
    };

    template <typename T, bool const_iterator>
    constexpr bool has_map_node_relocation_impl<
        T, const_iterator,
        std::enable_if_t<std::conjunction_v<
            std::bool_constant<map_node_of<
                decltype(std::declval<T&>().extract(
                    std::declval<map_iterator_t<T, const_iterator>>())),
                T>>,
            nullable_map_node_of_s<
                decltype(std::declval<T&>().extract(
                    std::declval<const typename T::key_type&>())),
                T>>>> = true;
#endif
  } // namespace helpers
} // namespace alterhook::utils::traits
