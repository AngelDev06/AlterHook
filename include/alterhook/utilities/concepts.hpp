/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>
#include <initializer_list>
#include "macros.hpp"
#include "type_sequence.hpp"
#include "function_traits.hpp"
#include "other.hpp"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4996)
#endif

namespace alterhook::utils
{
  namespace helpers
  {
    template <typename T>
    using size_type_member_of = typename T::size_type;

    template <typename T>
    using size_type_member_or_size_t =
        try_apply<T, size_type_member_of, size_t>;

    template <typename T>
    struct dummy_visitor
    {
      constexpr void operator()(T) const noexcept {}
    };
  } // namespace helpers

#if utils_cpp20
  namespace helpers
  {
    template <typename T>
    concept dereferencable_impl = requires(T& obj) { *obj; };

    template <typename T>
    concept equal_comparable_impl = requires(const T& a, const T& b) {
      { a == b } -> std::same_as<bool>;
    };

    template <typename T>
    concept not_equal_comparable_impl = requires(const T& a, const T& b) {
      { a != b } -> std::same_as<bool>;
    };

    template <typename T>
    concept tuple_like_impl =
        requires { std::tuple_size<T>::value; } &&
        (std::tuple_size_v<T> == 0 || requires(const T& obj) {
          typename std::tuple_element_t<std::tuple_size_v<T> - 1, T>;
          std::get<std::tuple_size_v<T> - 1>(obj);
        });

    template <typename T, size_t N>
    concept fixed_tuple_like_impl =
        tuple_like_impl<T> && std::tuple_size_v<T> == N;

    template <typename T>
    concept forward_iterable_impl = requires(T& m, const T& cm) {
      typename T::iterator;
      typename T::const_iterator;
      { m.begin() } -> std::convertible_to<typename T::iterator>;
      { m.end() } -> std::convertible_to<typename T::iterator>;
      { cm.begin() } -> std::convertible_to<typename T::const_iterator>;
      { cm.end() } -> std::convertible_to<typename T::const_iterator>;
    };

    template <typename T>
    concept allocator_type_impl =
        requires { typename T::value_type; } &&
        requires(T& a, typename std::allocator_traits<T>::size_type n,
                 typename std::allocator_traits<T>::pointer p) {
          {
            a.allocate(n)
          } -> std::same_as<typename std::allocator_traits<T>::pointer>;
          a.deallocate(p, n);
        };

    template <typename T, typename k>
    concept hash_type_impl =
        std::copy_constructible<T> && std::destructible<T> &&
        requires(const T& hasher, const k& key) {
          { hasher(key) } -> std::same_as<size_t>;
        };

    // ---------------------------------------------------------
    // MAP-AWARE BASIC CONCEPTS (INTERNAL)
    // ---------------------------------------------------------

    template <typename T>
    concept is_allocator_aware_impl = requires(T& m) {
      typename T::allocator_type;
      { m.get_allocator() } -> std::same_as<typename T::allocator_type>;
    };

    template <typename T>
    concept is_hasher_aware_impl = requires(T& m) {
      typename T::hasher;
      { m.hash_function() } -> std::same_as<typename T::hasher>;
    };

    template <typename T>
    concept provides_equality_comparator_impl = requires(T& m) {
      typename T::key_equal;
      { m.key_eq() } -> std::same_as<typename T::key_equal>;
    };

    template <typename T>
    concept is_core_hash_map_impl =
        std::destructible<T> && requires(const T& cm) {
          typename T::key_type;
          typename T::mapped_type;
          typename T::value_type;
          typename T::hasher;
          typename T::key_equal;
          cm.empty();
          cm.size();
        };

    // ---------------------------------------------------------
    // MAP STRUCTURAL APIs (INTERNAL)
    // ---------------------------------------------------------

    template <typename T>
    concept has_hash_map_capacity_api_impl =
        requires(T& m, const T& cm, float f, size_type_member_or_size_t<T> s) {
          { cm.load_factor() } -> std::same_as<float>;
          { cm.max_load_factor() } -> std::same_as<float>;
          m.max_load_factor(f);
          m.rehash(s);
          m.reserve(s);
        };

    template <typename T>
    concept has_map_bucket_api_impl =
        requires(const T& cm, const typename T::key_type& k,
                 size_type_member_or_size_t<T> s) {
          { cm.bucket_count() } -> std::same_as<size_type_member_or_size_t<T>>;
          {
            cm.max_bucket_count()
          } -> std::same_as<size_type_member_or_size_t<T>>;
          { cm.bucket_size(s) } -> std::same_as<size_type_member_or_size_t<T>>;
          { cm.bucket(k) } -> std::same_as<size_type_member_or_size_t<T>>;
        };

    template <typename T>
    concept has_map_bucket_iteration_impl =
        requires(T& m, const T& cm, size_type_member_or_size_t<T> s) {
          typename T::local_iterator;
          typename T::const_local_iterator;
          { m.begin(s) } -> std::same_as<typename T::local_iterator>;
          { m.end(s) } -> std::same_as<typename T::local_iterator>;
          { cm.begin(s) } -> std::same_as<typename T::const_local_iterator>;
          { cm.end(s) } -> std::same_as<typename T::const_local_iterator>;
        };

    // ---------------------------------------------------------
    // VISITATION & LOOKUP APIs (INTERNAL)
    // ---------------------------------------------------------

    template <typename T>
    concept has_map_basic_visitation_api_impl =
        requires(T& m, const T& cm, const typename T::key_type& k) {
          m.visit(k, dummy_visitor<typename T::value_type&>{});
          cm.visit(k, dummy_visitor<const typename T::value_type&>{});
        };

    template <typename T>
    concept has_map_range_visitation_api_impl =
        requires(T& m, const T& cm, const typename T::key_type* ptr) {
          m.visit(ptr, ptr, dummy_visitor<typename T::value_type&>{});
          cm.visit(ptr, ptr, dummy_visitor<const typename T::value_type&>{});
        };

    template <typename T>
    concept has_cuckoo_map_visitation_api_impl =
        requires(T& m, const T& cm, const typename T::key_type& k) {
          cm.find_fn(k, dummy_visitor<const typename T::mapped_type&>{});
          m.update_fn(k, dummy_visitor<typename T::mapped_type&>{});
        };

    template <typename T>
    concept has_map_count_method_impl =
        requires(const T& cm, const typename T::key_type& k) {
          { cm.count(k) } -> std::same_as<size_type_member_or_size_t<T>>;
        };

    template <typename T>
    concept has_map_find_method_impl =
        requires(const T& cm, const typename T::key_type& k) { cm.find(k); };

    template <typename T>
    concept has_map_contains_method_impl =
        requires(const T& cm, const typename T::key_type& k) {
          { cm.contains(k) } -> std::same_as<bool>;
        };

    template <typename T>
    concept has_map_standard_lookup_impl =
        has_map_count_method_impl<T> &&
        requires(T& m, const T& cm, const typename T::key_type& k) {
          { m.find(k) } -> std::same_as<typename T::iterator>;
          { cm.find(k) } -> std::same_as<typename T::const_iterator>;
          {
            m.equal_range(k)
          } -> std::same_as<
              std::pair<typename T::iterator, typename T::iterator>>;
          {
            cm.equal_range(k)
          } -> std::same_as<std::pair<typename T::const_iterator,
                                      typename T::const_iterator>>;
        };

    // ---------------------------------------------------------
    // MUTATION APIs (INTERNAL)
    // ---------------------------------------------------------

    template <typename T>
    concept has_map_at_method_impl =
        requires(T& m, const T& cm, const typename T::key_type& k) {
          { m.at(k) } -> std::same_as<typename T::mapped_type&>;
          { cm.at(k) } -> std::same_as<const typename T::mapped_type&>;
        };

    template <typename T>
    concept has_map_access_operator_impl =
        requires(T& m, const typename T::key_type& k) {
          { m[k] } -> std::same_as<typename T::mapped_type&>;
        };

    template <typename T>
    concept has_map_basic_erasure_impl =
        requires(T& m, const typename T::key_type& k) {
          { m.erase(k) } -> std::same_as<size_type_member_or_size_t<T>>;
          m.clear();
        };

    template <typename T>
    concept has_map_iterator_erasure_impl =
        requires(T& m, typename T::const_iterator cit) {
          { m.erase(cit) } -> std::same_as<typename T::iterator>;
          { m.erase(cit, cit) } -> std::same_as<typename T::iterator>;
        };

    template <typename T>
    concept has_map_basic_insertion_impl =
        requires(T& m, const typename T::value_type& v, typename T::key_type k,
                 typename T::mapped_type val) {
          m.insert(v);
          m.emplace(std::move(k), std::move(val));
        };

    template <typename T>
    concept has_map_hint_insertion_impl =
        requires(T& m, typename T::const_iterator cit,
                 const typename T::value_type& v, typename T::key_type k,
                 typename T::mapped_type val) {
          m.insert(cit, v);
          m.emplace_hint(cit, std::move(k), std::move(val));
        };

    template <typename T>
    concept has_map_init_list_insertion_impl =
        requires(T& m, std::initializer_list<typename T::value_type> ilist) {
          m.insert(ilist);
        };

    template <typename T>
    concept has_map_range_insertion_impl = requires(
        T& m, const typename T::value_type* ptr) { m.insert(ptr, ptr); };

    template <typename T>
    concept has_cuckoo_map_insertion_impl =
        requires(T& m, typename T::key_type k, typename T::mapped_type val) {
          m.insert(std::move(k), std::move(val));
        };

    template <typename T>
    concept has_map_try_emplace_impl =
        requires(T& m, typename T::key_type k, typename T::mapped_type val) {
          m.try_emplace(std::move(k), std::move(val));
        };

    template <typename T>
    concept has_map_insert_or_assign_impl = requires(
        T& m, const typename T::key_type& k,
        const typename T::mapped_type& val) { m.insert_or_assign(k, val); };

    template <typename T>
    concept has_map_node_relocation_impl =
        requires(T& m, const typename T::key_type& k,
                 typename T::const_iterator cit, typename T::node_type&& node) {
          typename T::node_type;
          { m.extract(cit) } -> std::same_as<typename T::node_type>;
          { m.extract(k) } -> std::same_as<typename T::node_type>;
          m.insert(std::move(node));
          m.merge(m);
        };

    template <typename T>
    concept has_map_swap_method_impl = requires(T& m) { m.swap(m); };

    template <typename T>
    concept has_map_insertion_and_visitation_impl = requires(
        T& m, const typename T::value_type& v, typename T::key_type k,
        typename T::mapped_type val) {
      m.insert_or_visit(v, dummy_visitor<typename T::value_type&>{});
      m.insert_or_cvisit(v, dummy_visitor<const typename T::value_type&>{});
      m.insert_and_visit(v, dummy_visitor<typename T::value_type&>{},
                         dummy_visitor<typename T::value_type&>{});
      m.insert_and_cvisit(v, dummy_visitor<const typename T::value_type&>{},
                          dummy_visitor<const typename T::value_type&>{});

      m.emplace_or_visit(std::move(k), std::move(val),
                         dummy_visitor<typename T::value_type&>{});
      m.emplace_or_cvisit(std::move(k), std::move(val),
                          dummy_visitor<const typename T::value_type&>{});
      m.emplace_and_visit(std::move(k), std::move(val),
                          dummy_visitor<typename T::value_type&>{},
                          dummy_visitor<typename T::value_type&>{});
      m.emplace_and_cvisit(std::move(k), std::move(val),
                           dummy_visitor<const typename T::value_type&>{},
                           dummy_visitor<const typename T::value_type&>{});

      m.try_emplace_or_visit(std::move(k), std::move(val),
                             dummy_visitor<typename T::value_type&>{});
      m.try_emplace_or_cvisit(std::move(k), std::move(val),
                              dummy_visitor<const typename T::value_type&>{});
      m.try_emplace_and_visit(std::move(k), std::move(val),
                              dummy_visitor<typename T::value_type&>{},
                              dummy_visitor<typename T::value_type&>{});
      m.try_emplace_and_cvisit(std::move(k), std::move(val),
                               dummy_visitor<const typename T::value_type&>{},
                               dummy_visitor<const typename T::value_type&>{});
    }
  } // namespace helpers
#else
  namespace helpers
  {
    template <typename T, typename = void>
    constexpr bool dereferencable_impl = false;
    template <typename T>
    constexpr bool
        dereferencable_impl<T, std::void_t<decltype(*std::declval<T&>())>> =
            true;
    template <typename T>
    using dereferenced_t = decltype(*std::declval<T>());

    template <typename T, typename = void>
    constexpr bool equal_comparable_impl = false;
    template <typename T>
    constexpr bool equal_comparable_impl<
        T, std::enable_if_t<std::is_same_v<decltype(std::declval<const T&>() ==
                                                    std::declval<const T&>()),
                                           bool>>> = true;
    template <typename T, typename = void>
    constexpr bool not_equal_comparable_impl = false;
    template <typename T>
    constexpr bool not_equal_comparable_impl<
        T, std::enable_if_t<std::is_same_v<decltype(std::declval<const T&>() !=
                                                    std::declval<const T&>()),
                                           bool>>> = true;

    template <typename T, size_t size, typename = void>
    constexpr bool tuple_like_impl2 = false;
    template <typename T, size_t size>
    constexpr bool tuple_like_impl2<
        T, size,
        std::void_t<std::tuple_element_t<size - 1, T>,
                    decltype(std::get<size - 1>(std::declval<T>()))>> = true;
    template <typename T>
    constexpr bool tuple_like_impl2<T, 0, void> = true;

    template <typename T, typename = void>
    constexpr bool tuple_like_impl = false;
    template <typename T>
    constexpr bool tuple_like_impl<
        T, std::enable_if_t<std::is_integral_v<
               std::remove_cv_t<decltype(std::tuple_size<T>::value)>>>> =
        tuple_like_impl2<T, std::tuple_size_v<T>>;

    template <typename T, size_t N, typename = void>
    constexpr bool fixed_tuple_like_impl = false;
    template <typename T, size_t N>
    constexpr bool fixed_tuple_like_impl<
        T, N,
        std::enable_if_t<std::is_integral_v<
            std::remove_cv_t<decltype(std::tuple_size<T>::value)>>>> =
        tuple_like_impl2<T, std::tuple_size_v<T>> && std::tuple_size_v<T> == N;

    /*
     * IMPLEMENTATION
     */
    template <typename T, typename = void>
    constexpr bool forward_iterable_impl = false;
    template <typename T>
    constexpr bool forward_iterable_impl<
        T, std::enable_if_t<
               std::is_convertible_v<decltype(std::declval<T&>().begin()),
                                     typename T::iterator> &&
               std::is_convertible_v<decltype(std::declval<T&>().end()),
                                     typename T::iterator> &&
               std::is_convertible_v<decltype(std::declval<const T&>().begin()),
                                     typename T::const_iterator> &&
               std::is_convertible_v<decltype(std::declval<const T&>().end()),
                                     typename T::const_iterator>>> = true;

    template <typename T, typename = void>
    constexpr bool allocator_type_impl2 = false;
    template <typename T>
    constexpr bool allocator_type_impl2<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().allocate(
                                  std::declval<typename std::allocator_traits<
                                      T>::size_type>())),
                              typename std::allocator_traits<T>::pointer>,
               std::void_t<decltype(std::declval<T&>().deallocate(
                   std::declval<typename std::allocator_traits<T>::pointer>(),
                   std::declval<
                       typename std::allocator_traits<T>::size_type>()))>>> =
        true;

    template <typename T, typename = void>
    constexpr bool allocator_type_impl = false;
    template <typename T>
    constexpr bool allocator_type_impl<T, std::void_t<typename T::value_type>> =
        allocator_type_impl2<T>;

    template <typename T, typename k, typename = void>
    constexpr bool hash_type_impl = false;
    template <typename T, typename k>
    constexpr bool hash_type_impl<
        T, k,
        std::enable_if_t<std::is_same_v<decltype(std::declval<const T&>()(
                                            std::declval<const k&>())),
                                        size_t>>> =
        std::is_copy_constructible_v<T> && std::is_destructible_v<T>;

    template <typename T, typename = void>
    constexpr bool is_allocator_aware_impl = false;
    template <typename T>
    constexpr bool is_allocator_aware_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().get_allocator()),
                              typename T::allocator_type>>> = true;

    template <typename T, typename = void>
    constexpr bool is_hasher_aware_impl = false;
    template <typename T>
    constexpr bool is_hasher_aware_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().hash_function()),
                              typename T::hasher>>> = true;

    template <typename T, typename = void>
    constexpr bool provides_equality_comparator_impl = false;
    template <typename T>
    constexpr bool provides_equality_comparator_impl<
        T, std::enable_if_t<std::is_same_v<
               decltype(std::declval<T&>().key_eq()), typename T::key_equal>>> =
        true;

    template <typename T, typename = void>
    constexpr bool is_core_hash_map_impl = false;
    template <typename T>
    constexpr bool is_core_hash_map_impl<
        T, std::enable_if_t<
               std::is_destructible_v<T>,
               std::void_t<typename T::key_type, typename T::mapped_type,
                           typename T::value_type, typename T::hasher,
                           typename T::key_equal,
                           decltype(std::declval<const T&>().empty()),
                           decltype(std::declval<const T&>().size())>>> = true;

    template <typename T, typename = void>
    constexpr bool has_hash_map_capacity_api_impl = false;
    template <typename T>
    constexpr bool has_hash_map_capacity_api_impl<
        T,
        std::enable_if_t<
            std::is_same_v<decltype(std::declval<const T&>().load_factor()),
                           float> &&
                std::is_same_v<
                    decltype(std::declval<const T&>().max_load_factor()),
                    float>,
            std::void_t<decltype(std::declval<T&>().max_load_factor(float{})),
                        decltype(std::declval<T&>().rehash(
                            std::declval<size_type_member_or_size_t<T>>())),
                        decltype(std::declval<T&>().reserve(
                            std::declval<size_type_member_or_size_t<T>>()))>>> =
        true;

    template <typename T, typename = void>
    constexpr bool has_map_bucket_api_impl = false;
    template <typename T>
    constexpr bool has_map_bucket_api_impl<
        T,
        std::enable_if_t<
            std::is_same_v<decltype(std::declval<const T&>().bucket_count()),
                           size_type_member_or_size_t<T>> &&
            std::is_same_v<
                decltype(std::declval<const T&>().max_bucket_count()),
                size_type_member_or_size_t<T>> &&
            std::is_same_v<decltype(std::declval<const T&>().bucket_size(
                               std::declval<size_type_member_or_size_t<T>>())),
                           size_type_member_or_size_t<T>> &&
            std::is_same_v<decltype(std::declval<const T&>().bucket(
                               std::declval<const typename T::key_type&>())),
                           size_type_member_or_size_t<T>>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_bucket_iteration_impl = false;
    template <typename T>
    constexpr bool has_map_bucket_iteration_impl<
        T,
        std::enable_if_t<
            std::is_same_v<decltype(std::declval<T&>().begin(
                               std::declval<size_type_member_or_size_t<T>>())),
                           typename T::local_iterator> &&
            std::is_same_v<decltype(std::declval<const T&>().begin(
                               std::declval<size_type_member_or_size_t<T>>())),
                           typename T::const_local_iterator> &&
            std::is_same_v<decltype(std::declval<T&>().end(
                               std::declval<size_type_member_or_size_t<T>>())),
                           typename T::local_iterator> &&
            std::is_same_v<decltype(std::declval<const T&>().end(
                               std::declval<size_type_member_or_size_t<T>>())),
                           typename T::const_local_iterator>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_basic_visitation_api_impl = false;
    template <typename T>
    constexpr bool has_map_basic_visitation_api_impl<
        T, std::void_t<decltype(std::declval<T&>().visit(
                           std::declval<const typename T::key_type&>(),
                           dummy_visitor<typename T::value_type&>{})),
                       decltype(std::declval<const T&>().visit(
                           std::declval<const typename T::key_type&>(),
                           dummy_visitor<const typename T::value_type&>{}))>> =
        true;

    template <typename T, typename = void>
    constexpr bool has_map_range_visitation_api_impl = false;
    template <typename T>
    constexpr bool has_map_range_visitation_api_impl<
        T, std::void_t<decltype(std::declval<T&>().visit(
                           std::declval<const typename T::key_type*>(),
                           std::declval<const typename T::key_type*>(),
                           dummy_visitor<typename T::value_type&>{})),
                       decltype(std::declval<const T&>().visit(
                           std::declval<const typename T::key_type*>(),
                           std::declval<const typename T::key_type*>(),
                           dummy_visitor<const typename T::value_type&>{}))>> =
        true;

    template <typename T, typename = void>
    constexpr bool has_cuckoo_map_visitation_api_impl = false;
    template <typename T>
    constexpr bool has_cuckoo_map_visitation_api_impl<
        T, std::void_t<decltype(std::declval<const T&>().find_fn(
                           std::declval<const typename T::key_type&>(),
                           dummy_visitor<const typename T::mapped_type&>{})),
                       decltype(std::declval<T&>().update_fn(
                           std::declval<const typename T::key_type&>(),
                           dummy_visitor<typename T::mapped_type&>{}))>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_count_method_impl = false;
    template <typename T>
    constexpr bool has_map_count_method_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<const T&>().count(
                                  std::declval<const typename T::key_type&>())),
                              size_type_member_or_size_t<T>>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_find_method_impl = false;
    template <typename T>
    constexpr bool has_map_find_method_impl<
        T, std::void_t<decltype(std::declval<const T&>().find(
               std::declval<const typename T::key_type&>()))>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_contains_method_impl = false;
    template <typename T>
    constexpr bool has_map_contains_method_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<const T&>().contains(
                                  std::declval<const typename T::key_type&>())),
                              bool>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_standard_lookup_impl = false;
    template <typename T>
    constexpr bool has_map_standard_lookup_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().find(
                                  std::declval<const typename T::key_type&>())),
                              typename T::iterator> &&
               std::is_same_v<decltype(std::declval<const T&>().find(
                                  std::declval<const typename T::key_type&>())),
                              typename T::const_iterator> &&
               std::is_same_v<
                   decltype(std::declval<T&>().equal_range(
                       std::declval<const typename T::key_type&>())),
                   std::pair<typename T::iterator, typename T::iterator>> &&
               std::is_same_v<decltype(std::declval<const T&>().equal_range(
                                  std::declval<const typename T::key_type&>())),
                              std::pair<typename T::const_iterator,
                                        typename T::const_iterator>> &&
               has_map_count_method_impl<T>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_at_method_impl = false;
    template <typename T>
    constexpr bool has_map_at_method_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().at(
                                  std::declval<const typename T::key_type&>())),
                              typename T::mapped_type&> &&
               std::is_same_v<decltype(std::declval<const T&>().at(
                                  std::declval<const typename T::key_type&>())),
                              const typename T::mapped_type&>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_access_operator_impl = false;
    template <typename T>
    constexpr bool has_map_access_operator_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>()[std::declval<
                                  const typename T::key_type&>()]),
                              typename T::mapped_type&>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_basic_erasure_impl = false;
    template <typename T>
    constexpr bool has_map_basic_erasure_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().erase(
                                  std::declval<const typename T::key_type&>())),
                              size_type_member_or_size_t<T>>,
               std::void_t<decltype(std::declval<T&>().clear())>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_iterator_erasure_impl = false;
    template <typename T>
    constexpr bool has_map_iterator_erasure_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().erase(
                                  std::declval<typename T::const_iterator>())),
                              typename T::iterator> &&
               std::is_same_v<decltype(std::declval<T&>().erase(
                                  std::declval<typename T::const_iterator>(),
                                  std::declval<typename T::const_iterator>())),
                              typename T::iterator>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_basic_insertion_impl = false;
    template <typename T>
    constexpr bool has_map_basic_insertion_impl<
        T, std::void_t<decltype(std::declval<T&>().insert(
                           std::declval<const typename T::value_type&>())),
                       decltype(std::declval<T&>().emplace(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>()))>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_hint_insertion_impl = false;
    template <typename T>
    constexpr bool has_map_hint_insertion_impl<
        T, std::void_t<decltype(std::declval<T&>().insert(
                           std::declval<typename T::const_iterator>(),
                           std::declval<const typename T::value_type&>())),
                       decltype(std::declval<T&>().emplace_hint(
                           std::declval<typename T::const_iterator>(),
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>()))>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_init_list_insertion_impl = false;
    template <typename T>
    constexpr bool has_map_init_list_insertion_impl<
        T,
        std::void_t<decltype(std::declval<T&>().insert(
            std::declval<std::initializer_list<typename T::value_type>>()))>> =
        true;

    template <typename T, typename = void>
    constexpr bool has_map_range_insertion_impl = false;
    template <typename T>
    constexpr bool has_map_range_insertion_impl<
        T, std::void_t<decltype(std::declval<T&>().insert(
               std::declval<const typename T::value_type*>(),
               std::declval<const typename T::value_type*>()))>> = true;

    template <typename T, typename = void>
    constexpr bool has_cuckoo_map_insertion_impl = false;
    template <typename T>
    constexpr bool has_cuckoo_map_insertion_impl<
        T, std::void_t<decltype(std::declval<T&>().insert(
               std::declval<typename T::key_type>(),
               std::declval<typename T::mapped_type>()))>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_try_emplace_impl = false;
    template <typename T>
    constexpr bool has_map_try_emplace_impl<
        T, std::void_t<decltype(std::declval<T&>().try_emplace(
               std::declval<typename T::key_type>(),
               std::declval<typename T::mapped_type>()))>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_insert_or_assign_impl = false;
    template <typename T>
    constexpr bool has_map_insert_or_assign_impl<
        T, std::void_t<decltype(std::declval<T&>().insert_or_assign(
               std::declval<const typename T::key_type&>(),
               std::declval<const typename T::mapped_type&>()))>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_node_relocation_impl = false;
    template <typename T>
    constexpr bool has_map_node_relocation_impl<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<T&>().extract(
                                  std::declval<typename T::const_iterator>())),
                              typename T::node_type> &&
                   std::is_same_v<
                       decltype(std::declval<T&>().extract(
                           std::declval<const typename T::key_type&>())),
                       typename T::node_type>,
               std::void_t<decltype(std::declval<T&>().insert(
                               std::declval<typename T::node_type>())),
                           decltype(std::declval<T&>().merge(
                               std::declval<T&>()))>>> = true;

    template <typename T, typename = void>
    constexpr bool has_map_swap_method_impl = false;
    template <typename T>
    constexpr bool has_map_swap_method_impl<
        T, std::void_t<decltype(std::declval<T&>().swap(std::declval<T&>()))>> =
        true;

    template <typename T, typename = void>
    constexpr bool has_map_insertion_and_visitation_impl = false;
    template <typename T>
    constexpr bool has_map_insertion_and_visitation_impl<
        T, std::void_t<decltype(std::declval<T&>().insert_or_visit(
                           std::declval<const typename T::value_type&>(),
                           dummy_visitor<typename T::value_type&>{})),
                       decltype(std::declval<T&>().insert_or_cvisit(
                           std::declval<const typename T::value_type&>(),
                           dummy_visitor<const typename T::value_type&>{})),
                       decltype(std::declval<T&>().insert_and_visit(
                           std::declval<const typename T::value_type&>(),
                           dummy_visitor<typename T::value_type&>{},
                           dummy_visitor<typename T::value_type&>{})),
                       decltype(std::declval<T&>().insert_and_cvisit(
                           std::declval<const typename T::value_type&>(),
                           dummy_visitor<const typename T::value_type&>{},
                           dummy_visitor<const typename T::value_type&>{})),
                       decltype(std::declval<T&>().emplace_or_visit(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>(),
                           dummy_visitor<typename T::value_type&>{})),
                       decltype(std::declval<T&>().emplace_or_cvisit(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>(),
                           dummy_visitor<const typename T::value_type&>{})),
                       decltype(std::declval<T&>().emplace_and_visit(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>(),
                           dummy_visitor<typename T::value_type&>{},
                           dummy_visitor<typename T::value_type&>{})),
                       decltype(std::declval<T&>().emplace_and_cvisit(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>(),
                           dummy_visitor<const typename T::value_type&>{},
                           dummy_visitor<const typename T::value_type&>{})),
                       decltype(std::declval<T&>().try_emplace_or_visit(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>(),
                           dummy_visitor<typename T::value_type&>{})),
                       decltype(std::declval<T&>().try_emplace_or_cvisit(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>(),
                           dummy_visitor<const typename T::value_type&>{})),
                       decltype(std::declval<T&>().try_emplace_and_visit(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>(),
                           dummy_visitor<typename T::value_type&>{},
                           dummy_visitor<typename T::value_type&>{})),
                       decltype(std::declval<T&>().try_emplace_and_cvisit(
                           std::declval<typename T::key_type>(),
                           std::declval<typename T::mapped_type>(),
                           dummy_visitor<const typename T::value_type&>{},
                           dummy_visitor<const typename T::value_type&>{}))>> =
        true;
  } // namespace helpers
#endif

  // ---------------------------------------------------------
  // PUBLIC API WRAPPERS
  // ---------------------------------------------------------

  template <typename T>
  utils_concept dereferencable =
      helpers::dereferencable_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept equal_comparable =
      helpers::equal_comparable_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept not_equal_comparable =
      helpers::not_equal_comparable_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept tuple_like = helpers::tuple_like_impl<remove_cvref_t<T>>;

  template <typename T, size_t N>
  utils_concept fixed_tuple_like =
      helpers::fixed_tuple_like_impl<remove_cvref_t<T>, N>;

  template <typename T>
  utils_concept pair_like = fixed_tuple_like<T, 2>;

  template <typename T>
  utils_concept forward_iterable =
      helpers::forward_iterable_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept allocator_type =
      helpers::allocator_type_impl<remove_cvref_t<T>>;

  template <typename T, typename k>
  utils_concept hash_type =
      helpers::hash_type_impl<remove_cvref_t<T>, remove_cvref_t<k>>;

  template <typename T>
  utils_concept is_allocator_aware =
      helpers::is_allocator_aware_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept is_hasher_aware =
      helpers::is_hasher_aware_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept provides_equality_comparator =
      helpers::provides_equality_comparator_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept is_core_hash_map =
      helpers::is_core_hash_map_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_hash_map_capacity_api =
      helpers::has_hash_map_capacity_api_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_bucket_api =
      helpers::has_map_bucket_api_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_bucket_iteration =
      helpers::has_map_bucket_iteration_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_basic_visitation_api =
      helpers::has_map_basic_visitation_api_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_range_visitation_api =
      helpers::has_map_range_visitation_api_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_cuckoo_map_visitation_api =
      helpers::has_cuckoo_map_visitation_api_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_count_method =
      helpers::has_map_count_method_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_find_method =
      helpers::has_map_find_method_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_contains_method =
      helpers::has_map_contains_method_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_standard_lookup =
      helpers::has_map_standard_lookup_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_at_method =
      helpers::has_map_at_method_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_access_operator =
      helpers::has_map_access_operator_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_basic_erasure =
      helpers::has_map_basic_erasure_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_iterator_erasure =
      helpers::has_map_iterator_erasure_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_basic_insertion =
      helpers::has_map_basic_insertion_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_hint_insertion =
      helpers::has_map_hint_insertion_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_init_list_insertion =
      helpers::has_map_init_list_insertion_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_range_insertion =
      helpers::has_map_range_insertion_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_cuckoo_map_insertion =
      helpers::has_cuckoo_map_insertion_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_try_emplace =
      helpers::has_map_try_emplace_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_insert_or_assign =
      helpers::has_map_insert_or_assign_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_node_relocation =
      helpers::has_map_node_relocation_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_swap_method =
      helpers::has_map_swap_method_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_map_insertion_and_visitation =
      helpers::has_map_insertion_and_visitation_impl<remove_cvref_t<T>>;

  template <typename... types>
  utils_concept tuple_like_types = (tuple_like<types> && ...);

  template <typename... types>
  utils_concept pair_like_types = (pair_like<types> && ...);

  template <size_t N, typename... types>
  utils_concept fixed_tuple_like_types = (fixed_tuple_like<types, N> && ...);

  namespace helpers
  {
    template <typename seq, typename = void>
    struct pack_hook_arguments_as_pairs_impl;
    template <typename seq, typename = void>
    struct repack_hook_argument_pairs_impl;
    template <typename seq, typename = void>
    struct pack_hook_arguments_as_triplets_impl;
    template <typename seq, typename = void>
    struct repack_hook_argument_triplets_impl;

    template <typename... types>
    using pack_hook_arguments_as_pairs =
        typename pack_hook_arguments_as_pairs_impl<
            type_sequence<types...>>::type;

    template <typename... types>
    using repack_hook_argument_pairs =
        typename repack_hook_argument_pairs_impl<type_sequence<types...>>::type;

    template <typename... types>
    using pack_hook_arguments_as_triplets =
        typename pack_hook_arguments_as_triplets_impl<
            type_sequence<types...>>::type;

    template <typename... types>
    using repack_hook_argument_triplets =
        typename repack_hook_argument_triplets_impl<
            type_sequence<types...>>::type;

    template <typename seq>
    constexpr bool detours_and_originals_impl2 = false;
    template <typename seq, typename = void>
    constexpr bool detours_and_originals_impl = false;
    template <typename seq, typename = void>
    constexpr bool detour_and_original_pairs_impl = false;
    template <typename seq>
    constexpr bool keys_detours_and_originals_impl2 = false;
    template <typename seq, typename = void>
    constexpr bool keys_detours_and_originals_impl = false;
    template <typename seq, typename = void>
    constexpr bool key_detour_and_original_triplets_impl = false;
  } // namespace helpers

  template <typename detour, typename original>
  utils_concept detour_and_original_requirements =
      function_type<original> && std::is_lvalue_reference_v<original> &&
      (callable_type<detour> || disambiguatable_with<detour, original>);

  template <typename detour, typename original, typename... rest>
  utils_concept detours_and_originals = helpers::detours_and_originals_impl<
      type_sequence<detour, original, rest...>>;

  template <typename pair, typename... rest>
  utils_concept detour_and_original_pairs =
      helpers::detour_and_original_pairs_impl<type_sequence<pair, rest...>>;

  template <typename key, typename detour, typename original, typename... rest>
  utils_concept keys_detours_and_originals =
      helpers::keys_detours_and_originals_impl<
          type_sequence<key, detour, original, rest...>>;

  template <typename tuple, typename... rest>
  utils_concept key_detour_and_original_triplets =
      helpers::key_detour_and_original_triplets_impl<
          type_sequence<tuple, rest...>>;

  namespace helpers
  {
    template <typename... types>
    struct pack_hook_arguments_as_pairs_impl<
        type_sequence<types...>, std::enable_if_t<(sizeof...(types) % 2) == 0 &&
                                                  !pair_like_types<types...>>>
    {
      using type = make_type_pairs_t<types...>;
    };

    template <typename... types>
    struct repack_hook_argument_pairs_impl<
        type_sequence<types...>, std::enable_if_t<pair_like_types<types...>>>
    {
      using type = type_sequence<
          type_sequence<std::tuple_element_t<0, remove_cvref_t<types>>,
                        std::tuple_element_t<1, remove_cvref_t<types>>>...>;
    };

    template <typename... types>
    struct pack_hook_arguments_as_triplets_impl<
        type_sequence<types...>,
        std::enable_if_t<(sizeof...(types) % 3) == 0 &&
                         !fixed_tuple_like_types<3, types...>>>
    {
      using type = make_type_triplets_t<types...>;
    };

    template <typename... types>
    struct repack_hook_argument_triplets_impl<
        type_sequence<types...>,
        std::enable_if_t<fixed_tuple_like_types<3, types...>>>
    {
      using type = type_sequence<
          type_sequence<std::tuple_element_t<0, remove_cvref_t<types>>,
                        std::tuple_element_t<1, remove_cvref_t<types>>,
                        std::tuple_element_t<2, remove_cvref_t<types>>>...>;
    };

    template <typename... detours, typename... originals>
    constexpr bool detours_and_originals_impl2<
        type_sequence<type_sequence<detours, originals>...>> =
        (detour_and_original_requirements<detours, originals> && ...);

    template <typename... types>
    constexpr bool detours_and_originals_impl<
        type_sequence<types...>, std::enable_if_t<detours_and_originals_impl2<
                                     pack_hook_arguments_as_pairs<types...>>>> =
        true;

    template <typename... types>
    constexpr bool detour_and_original_pairs_impl<
        type_sequence<types...>, std::enable_if_t<detours_and_originals_impl2<
                                     repack_hook_argument_pairs<types...>>>> =
        true;

    /* note: we don't check the keys at all, we avoid them intentionally so that
     * the code hits a proper static assertion instead of failing to compile
     * with douzens of sfinae stripped overload errors */
    template <typename... keys, typename... detours, typename... originals>
    constexpr bool keys_detours_and_originals_impl2<
        type_sequence<type_sequence<keys, detours, originals>...>> =
        (detour_and_original_requirements<detours, originals> && ...);

    template <typename... types>
    constexpr bool keys_detours_and_originals_impl<
        type_sequence<types...>,
        std::enable_if_t<keys_detours_and_originals_impl2<
            pack_hook_arguments_as_triplets<types...>>>> = true;

    template <typename... types>
    constexpr bool key_detour_and_original_triplets_impl<
        type_sequence<types...>,
        std::enable_if_t<keys_detours_and_originals_impl2<
            repack_hook_argument_triplets<types...>>>> = true;
  } // namespace helpers
} // namespace alterhook::utils

#if utils_msvc
  #pragma warning(pop)
#endif
