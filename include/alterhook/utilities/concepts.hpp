/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <utility>
#include <initializer_list>
#include "utils_macros.h"
#include "type_sequence.h"
#include "function_traits.h"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4996)
#endif

namespace alterhook::utils
{
  namespace helpers
  {
    template <typename T>
    inline constexpr bool takes_5_types = false;

    template <template <typename, typename, typename, typename, typename>
              typename cls,
              typename T1, typename T2, typename T3, typename T4, typename T5>
    inline constexpr bool takes_5_types<cls<T1, T2, T3, T4, T5>> = true;

    template <typename T>
    struct alloc_type;

    template <template <typename> typename alloc, typename T>
    struct alloc_type<alloc<T>>
    {
      typedef T type;
    };

    template <typename T>
    using alloc_type_t = typename alloc_type<T>::type;

#define __utils_member_or2(name, member, otherwise)                            \
  template <typename T, typename = void>                                       \
  struct utils_concat(member_or_, name)                                        \
  {                                                                            \
    typedef otherwise type;                                                    \
  };                                                                           \
  template <typename T>                                                        \
  struct utils_concat(member_or_, name)<T, std::void_t<typename T::member>>    \
  {                                                                            \
    typedef typename T::member type;                                           \
  };                                                                           \
  template <typename T>                                                        \
  using utils_concat(utils_concat(member_or_, name), _t) =                     \
      typename utils_concat(member_or_, name)<T>::type;

#define __utils_member_or(args) __utils_member_or2 args

    // clang-format off
    utils_map(__utils_member_or, (size_t, size_type, size_t),
              (void_pointer, void_pointer, void*),
              (const_void_pointer, const_void_pointer, const void*),
              (pointer, pointer, std::add_pointer_t<alloc_type_t<T>>),
              (const_pointer, const_pointer,
               std::add_pointer_t<std::add_const_t<alloc_type_t<T>>>))

    template <typename T, typename alloc>
    utils_concept allocator_value_type = std::is_same_v<T, alloc_type_t<alloc>>;

    // clang-format on

    template <typename T, typename alloc>
    utils_concept allocator_pointer =
        std::is_same_v<T, member_or_pointer_t<alloc>>;

    template <typename T, typename alloc>
    utils_concept allocator_const_pointer =
        std::is_same_v<T, member_or_const_pointer_t<alloc>>;

    struct visit_dummy
    {
      template <typename T>
      void operator()(const T& pair)
      {
        (void)pair.first;
        (void)pair.second;
      }
    };
  } // namespace helpers

#if utils_cpp20
  template <typename T>
  concept tuple_like =
      requires { std::tuple_size<T>::value; } &&
      (std::tuple_size_v<std::remove_cvref_t<T>> == 0 ||
       requires(const T& obj) {
         typename std::tuple_element_t<
             std::tuple_size_v<std::remove_cvref_t<T>> - 1,
             std::remove_cvref_t<T>>;
         std::get<std::tuple_size_v<std::remove_cvref_t<T>> - 1>(obj);
       });

  template <typename T, size_t N>
  concept fixed_tuple_like =
      tuple_like<T> && std::tuple_size_v<std::remove_cvref_t<T>> == N;

  template <typename T>
  concept pair_like = fixed_tuple_like<T, 2>;

  template <typename T>
  concept forward_iterable = requires(T& instance, const T& cinstance) {
    typename T::iterator;
    typename T::const_iterator;
    {
      instance.begin()
    } -> std::convertible_to<typename T::iterator>;
    {
      instance.end()
    } -> std::convertible_to<typename T::iterator>;
    {
      cinstance.begin()
    } -> std::convertible_to<typename T::const_iterator>;
    {
      cinstance.end()
    } -> std::convertible_to<typename T::const_iterator>;
    {
      cinstance.cbegin()
    } -> std::convertible_to<typename T::const_iterator>;
    {
      cinstance.cend()
    } -> std::convertible_to<typename T::const_iterator>;
  };

  template <typename T>
  concept allocator_type =
      requires { typename T::value_type; } &&
      requires(T instance, helpers::member_or_size_t_t<T> n,
               helpers::member_or_pointer_t<T>            p,
               helpers::member_or_const_pointer_t<T>      cp,
               helpers::member_or_void_pointer_t<T>       vp,
               helpers::member_or_const_void_pointer_t<T> cvp) {
        requires helpers::allocator_value_type<
            typename T::value_type, T>; // is T::value_type equivalent to the
                                        // template parameter of the allocator?
        requires std::convertible_to<helpers::member_or_pointer_t<T>,
                                     helpers::member_or_const_pointer_t<T>>;
        {
          instance.allocate(n)
        } -> helpers::allocator_pointer<T>;
        {
          *p
        } -> std::same_as<std::add_lvalue_reference_t<typename T::value_type>>;
        {
          *cp
        } -> std::same_as<std::add_lvalue_reference_t<
            std::add_const_t<typename T::value_type>>>;
        {
          static_cast<helpers::member_or_pointer_t<T>>(vp)
        };
        {
          static_cast<helpers::member_or_const_pointer_t<T>>(cvp)
        };
        {
          instance == instance
        } -> std::same_as<bool>;
        {
          instance != instance
        } -> std::same_as<bool>;
        instance.deallocate(p, n);
        T(instance);
        T(std::move(instance));
      };

  template <typename T, typename k>
  concept hash_type = std::copy_constructible<T> && std::destructible<T> &&
                      requires(T instance, k key) {
                        {
                          instance(key)
                        } -> std::same_as<size_t>;
                      };

  template <typename T>
  concept hash_map =
      hash_type<type_at_t<2, pack_to_type_sequence_t<T>>,
                type_at_t<0, pack_to_type_sequence_t<T>>> &&
      allocator_type<type_at_t<4, pack_to_type_sequence_t<T>>> &&
      std::destructible<T> && std::copyable<T> &&
      requires {
        typename T::key_type;
        typename T::mapped_type;
        typename T::value_type;
        typename T::hasher;
        typename T::key_equal;
        typename T::allocator_type;
        typename T::pointer;
        typename T::const_pointer;
        typename T::reference;
        typename T::const_reference;
        typename T::size_type;
        typename T::difference_type;
      } &&
      requires(T& instance, typename T::size_type n,
               const typename T::hasher& hash, const typename T::key_equal& keq,
               const typename T::allocator_type&             alloc,
               std::initializer_list<typename T::value_type> list,
               const typename T::key_type& key, float z) {
        T();
        T(n, hash, keq, alloc);
        T(instance);
        T(std::move(instance));
        T(alloc);
        T(instance, alloc);
        T(std::move(instance), alloc);
        T(list, n, hash, keq, alloc);
        T(n, alloc);
        T(n, hash, alloc);
        T(list, alloc);
        T(list, n, alloc);
        T(list, n, hash, alloc);
        instance = list;
        {
          instance.get_allocator()
        } -> std::same_as<typename T::allocator_type>;
        {
          instance.empty()
        } -> std::same_as<bool>;
        {
          instance.size()
        } -> std::same_as<typename T::size_type>;
        {
          instance.max_size()
        } -> std::same_as<typename T::size_type>;
        {
          instance.hash_function()
        } -> std::same_as<typename T::hasher>;
        {
          instance.key_eq()
        } -> std::same_as<typename T::key_equal>;
        {
          instance.count(key)
        } -> std::same_as<typename T::size_type>;
        {
          instance.bucket_count()
        } -> std::same_as<typename T::size_type>;
        {
          instance.load_factor()
        } -> std::same_as<float>;
        {
          instance.max_load_factor()
        } -> std::same_as<float>;
        instance.max_load_factor(z);
        instance.rehash(n);
        instance.reserve(n);
        {
          instance == instance
        } -> std::same_as<bool>;
        {
          instance != instance
        } -> std::same_as<bool>;
        instance.swap(instance);
      };

  template <typename T>
  concept concurrent_hash_map =
      hash_map<T> &&
      requires(
          const T& cinstance, T& instance,
          std::add_lvalue_reference_t<std::add_const_t<typename T::key_type>>
                               key,
          helpers::visit_dummy func,
          std::add_lvalue_reference_t<std::add_const_t<typename T::value_type>>
                                                        val,
          std::initializer_list<typename T::value_type> list) {
        {
          cinstance.visit(key, func)
        } -> std::same_as<size_t>;
        {
          cinstance.cvisit(key, func)
        } -> std::same_as<size_t>;
        {
          cinstance.visit_all(func)
        } -> std::same_as<size_t>;
        {
          cinstance.cvisit_all(func)
        } -> std::same_as<size_t>;
        {
          instance.insert(val)
        } -> std::same_as<bool>;
        {
          instance.insert(list)
        };
        {
          instance.insert_or_visit(val, func)
        } -> std::same_as<bool>;
        {
          instance.insert_or_cvisit(val, func)
        } -> std::same_as<bool>;
        {
          cinstance.max_load()
        } -> std::same_as<typename T::size_type>;
      };

  template <typename T>
  concept regular_hash_map =
      hash_map<T> && forward_iterable<T> &&
      requires(
          const T& cinstance, T& instance,
          std::add_lvalue_reference_t<std::add_const_t<typename T::value_type>>
                                                        val,
          typename T::iterator                          itr,
          std::initializer_list<typename T::value_type> list,
          std::add_lvalue_reference_t<std::add_const_t<typename T::mapped_type>>
              obj,
          std::add_lvalue_reference_t<std::add_const_t<typename T::key_type>>
                                     key,
          typename T::const_iterator citr) {
        {
          instance.insert(val)
        } -> std::same_as<std::pair<typename T::iterator, bool>>;
        instance.insert(itr, itr);
        instance.insert(list);
        {
          instance.insert_or_assign(key, obj)
        } -> std::same_as<std::pair<typename T::iterator, bool>>;
        {
          instance.insert_or_assign(citr, key, obj)
        } -> std::convertible_to<typename T::iterator>;
        {
          instance.erase(citr)
        } -> std::convertible_to<typename T::iterator>;
        {
          instance.erase(key)
        } -> std::same_as<typename T::size_type>;
        instance.swap(instance);
        instance.clear();
        instance.merge(instance);
        {
          instance.find(key)
        } -> std::convertible_to<typename T::iterator>;
        {
          cinstance.find(key)
        } -> std::convertible_to<typename T::const_iterator>;
        {
          instance.equal_range(key)
        }
        -> std::same_as<std::pair<typename T::iterator, typename T::iterator>>;
        {
          cinstance.equal_range(key)
        } -> std::same_as<
            std::pair<typename T::const_iterator, typename T::const_iterator>>;
        instance.at(key) = obj;
        instance[key]    = obj;
      };

  template <typename T>
  concept multi_hash_map =
      hash_map<T> && forward_iterable<T> &&
      requires(
          T& instance, const T& cinstance, const typename T::value_type& val,
          std::initializer_list<typename T::value_type> list,
          typename T::iterator itr, typename T::const_iterator citr,
          const typename T::key_type& key, const typename T::mapped_type& obj) {
        {
          instance.insert(val)
        } -> std::same_as<typename T::iterator>;
        instance.insert(itr, itr);
        instance.insert(list);
        {
          instance.erase(citr)
        } -> std::convertible_to<typename T::iterator>;
        {
          instance.erase(key)
        } -> std::same_as<typename T::size_type>;
        instance.swap(instance);
        instance.clear();
        instance.merge(instance);
        instance.merge(instance);
        {
          instance.find(key)
        } -> std::convertible_to<typename T::iterator>;
        {
          cinstance.find(key)
        } -> std::convertible_to<typename T::const_iterator>;
        {
          instance.equal_range(key)
        }
        -> std::same_as<std::pair<typename T::iterator, typename T::iterator>>;
        {
          cinstance.equal_range(key)
        } -> std::same_as<
            std::pair<typename T::const_iterator, typename T::const_iterator>>;
      };

  template <typename T>
  concept closed_addressing =
      (regular_hash_map<T> || multi_hash_map<T>)&&requires(
          T& instance, const T& cinstance, typename T::size_type n,
          const typename T::key_type& key) {
        typename T::local_iterator;
        typename T::const_local_iterator;
        {
          instance.begin(n)
        } -> std::same_as<typename T::local_iterator>;
        {
          instance.end(n)
        } -> std::same_as<typename T::local_iterator>;
        {
          cinstance.begin(n)
        } -> std::same_as<typename T::const_local_iterator>;
        {
          cinstance.end(n)
        } -> std::same_as<typename T::const_local_iterator>;
        {
          cinstance.cbegin(n)
        } -> std::same_as<typename T::const_local_iterator>;
        {
          cinstance.cend(n)
        } -> std::same_as<typename T::const_local_iterator>;
        {
          cinstance.max_bucket_count()
        } -> std::same_as<typename T::size_type>;
        {
          cinstance.bucket_size(n)
        } -> std::same_as<typename T::size_type>;
        {
          cinstance.bucket(key)
        } -> std::same_as<typename T::size_type>;
      };
#else
  namespace helpers
  {
  #define __utils_make_arg(type) std::declval<type>()
  #define __utils_make_args(...) utils_map_list(__utils_make_arg, __VA_ARGS__)

    /*
     * IMPLEMENTATION CODE GENERATORS
     */
  #define __utils_gen_checker(name)                                            \
    template <typename T, typename = void>                                     \
    inline constexpr bool has_##name##_v = false;                              \
    template <typename T>                                                      \
    inline constexpr bool                                                      \
        has_##name##_v<T, std::void_t<decltype(std::declval<T&>().name())>> =  \
            true;                                                              \
    template <typename T, typename = void>                                     \
    inline constexpr bool has_const_##name##_v = false;                        \
    template <typename T>                                                      \
    inline constexpr bool has_const_##name##_v<                                \
        T, std::void_t<decltype(std::declval<const T&>().name())>> = true;     \
    template <typename T>                                                      \
    using name##_ret_t = decltype(std::declval<T&>().name());                  \
    template <typename T>                                                      \
    using const_##name##_ret_t = decltype(std::declval<const T&>().name());

  #define __utils_gen_args_checker2(name, unique_name, ...)                    \
    template <typename T, typename = void>                                     \
    inline constexpr bool has_##unique_name##_v = false;                       \
    template <typename T>                                                      \
    inline constexpr bool has_##unique_name##_v<                               \
        T, std::void_t<decltype(std::declval<T&>().name(__VA_ARGS__))>> =      \
        true;                                                                  \
    template <typename T, typename = void>                                     \
    inline constexpr bool has_const_##unique_name##_v = false;                 \
    template <typename T>                                                      \
    inline constexpr bool has_const_##unique_name##_v<                         \
        T,                                                                     \
        std::void_t<decltype(std::declval<const T&>().name(__VA_ARGS__))>> =   \
        true;                                                                  \
    template <typename T>                                                      \
    using unique_name##_ret_t =                                                \
        decltype(std::declval<T&>().name(__VA_ARGS__));                        \
    template <typename T>                                                      \
    using const_##unique_name##_ret_t =                                        \
        decltype(std::declval<const T&>().name(__VA_ARGS__));

  #define __utils_gen_args_checker(args) __utils_gen_args_checker2 args

  #define __utils_gen_member_type_checker(name)                                \
    template <typename T, typename = void>                                     \
    inline constexpr bool has_##name##_member_type_v = false;                  \
    template <typename T>                                                      \
    inline constexpr bool                                                      \
        has_##name##_member_type_v<T, std::void_t<typename T::name>> = true;

    /*
     * CHECKS GENERATORS
     */
  #define __utils_gen_convertible_checker2(name, type)                         \
    std::is_convertible_v<name##_ret_t<T>, type>
  #define __utils_gen_convertible_checker(args)                                \
    __utils_gen_convertible_checker2 args

  #define __utils_gen_const_convertible_checker2(name, type)                   \
    std::is_convertible_v<const_##name##_ret_t<T>, type>
  #define __utils_gen_const_convertible_checker(args)                          \
    __utils_gen_const_convertible_checker2 args

  #define __utils_gen_same_types_checker2(name, type)                          \
    std::is_same_v<name##_ret_t<T>, type>
  #define __utils_gen_same_types_checker(args)                                 \
    __utils_gen_same_types_checker2 args

  #define __utils_gen_const_same_types_checker2(name, type)                    \
    std::is_same_v<const_##name##_ret_t<T>, type>
  #define __utils_gen_const_same_types_checker(args)                           \
    __utils_gen_const_same_types_checker2 args

  #define __utils_gen_method_checker(name)       has_##name##_v<T>
  #define __utils_gen_const_method_checker(name) has_const_##name##_v<T>

  #define __utils_gen_type_member_checker(name) has_##name##_member_type_v<T>

    /*
     * ABSTRACTED GENERATORS
     */
  #define __utils_convertible_checks(...)                                      \
    utils_map_separated(__utils_gen_convertible_checker, &&, __VA_ARGS__)

  #define __utils_const_convertible_checks(...)                                \
    utils_map_separated(__utils_gen_const_convertible_checker, &&, __VA_ARGS__)

  #define __utils_same_method_return_types(...)                                \
    utils_map_separated(__utils_gen_same_types_checker, &&, __VA_ARGS__)

  #define __utils_same_const_method_return_types(...)                          \
    utils_map_separated(__utils_gen_const_same_types_checker, &&, __VA_ARGS__)

  #define __utils_has_methods(...)                                             \
    utils_map_separated(__utils_gen_method_checker, &&, __VA_ARGS__)
  #define __utils_has_const_methods(...)                                       \
    utils_map_separated(__utils_gen_const_method_checker, &&, __VA_ARGS__)

  #define __utils_has_types(...)                                               \
    utils_map_separated(__utils_gen_type_member_checker, &&, __VA_ARGS__)

    /*
     * IMPLEMENTATION GENERATION
     */
    // clang-format off
    utils_map(__utils_gen_checker, begin, end, cbegin, cend, get_allocator,
              empty, size, max_size, hash_function, key_eq, bucket_count,
              load_factor, max_load_factor, max_load, clear, max_bucket_count)

    utils_map(
        __utils_gen_args_checker,
        (allocate, allocate, __utils_make_args(member_or_size_t_t<T>)),
        (deallocate, deallocate,
         __utils_make_args(member_or_pointer_t<T>, member_or_size_t_t<T>)),
        (count, count, __utils_make_args(const typename T::key_type&)),
        (max_load_factor, max_load_factorf, __utils_make_args(float)),
        (rehash, rehash, __utils_make_args(typename T::size_type)),
        (reserve, reserve, __utils_make_args(typename T::size_type)),
        (swap, swap, __utils_make_args(T&)),
        (visit, visit,
         __utils_make_args(const typename T::key_type&, visit_dummy)),
        (cvisit, cvisit,
         __utils_make_args(const typename T::key_type&, visit_dummy)),
        (visit_all, visit_all, __utils_make_args(visit_dummy)),
        (cvisit_all, cvisit_all, __utils_make_args(visit_dummy)),
        (insert, insert, __utils_make_args(const typename T::value_type&)),
        (insert, inserti,
         __utils_make_args(std::initializer_list<typename T::value_type>)),
        (insert, insertr,
         __utils_make_args(typename T::iterator, typename T::iterator)),
        (insert_or_visit, insert_or_visit,
         __utils_make_args(const typename T::value_type&, visit_dummy)),
        (insert_or_cvisit, insert_or_cvisit,
         __utils_make_args(const typename T::value_type&, visit_dummy)),
        (insert_or_assign, insert_or_assign,
         __utils_make_args(const typename T::key_type&,
                           const typename T::mapped_type&)),
        (insert_or_assign, insert_or_assignr,
         __utils_make_args(typename T::const_iterator,
                           const typename T::key_type&,
                           const typename T::mapped_type&)),
        (erase, erase, __utils_make_args(typename T::const_iterator)),
        (erase, erasek, __utils_make_args(const typename T::key_type&)),
        (merge, merge, __utils_make_args(T&)),
        (find, find, __utils_make_args(const typename T::key_type&)),
        (equal_range, equal_range,
         __utils_make_args(const typename T::key_type&)),
        (at, at, __utils_make_args(const typename T::key_type&)),
        (operator[], access, __utils_make_args(const typename T::key_type&)),
        (begin, bbegin, __utils_make_args(typename T::size_type)),
        (end, bend, __utils_make_args(typename T::size_type)),
        (cbegin, bcbegin, __utils_make_args(typename T::size_type)),
        (cend, bcend, __utils_make_args(typename T::size_type)),
        (bucket_size, bucket_size, __utils_make_args(typename T::size_type)),
        (bucket, bucket, __utils_make_args(const typename T::key_type&)))

    utils_map(__utils_gen_member_type_checker, iterator, const_iterator,
              value_type, key_type, mapped_type, hasher, key_equal,
              allocator_type, pointer, const_pointer, reference,
              const_reference, size_type, difference_type, local_iterator,
              const_local_iterator)

    template <typename T, typename = void>
    inline constexpr bool dummy = false;
    // clang-format on

    /*
     * HAND WRITTEN UTILITIES
     */
    template <typename T, typename = void>
    inline constexpr bool dereferencable = false;
    template <typename T>
    inline constexpr bool
        dereferencable<T, std::void_t<decltype(*std::declval<T>())>> = true;
    template <typename T>
    using dereferenced_t = decltype(*std::declval<T>());

    template <typename T, typename = void>
    inline constexpr bool equal_comparable = false;
    template <typename T>
    inline constexpr bool equal_comparable<
        T, std::void_t<decltype(std::declval<T>() == std::declval<T>())>> =
        std::is_same_v<decltype(std::declval<T>() == std::declval<T>()), bool>;
    template <typename T, typename = void>
    inline constexpr bool not_equal_comparable = false;
    template <typename T>
    inline constexpr bool not_equal_comparable<
        T, std::void_t<decltype(std::declval<T>() != std::declval<T>())>> =
        std::is_same_v<decltype(std::declval<T>() != std::declval<T>()), bool>;

    template <typename T, size_t size, typename = void>
    inline constexpr bool tuple_like_impl2 = false;
    template <typename T, size_t size>
    inline constexpr bool tuple_like_impl2<
        T, size,
        std::void_t<std::tuple_element_t<size - 1, T>,
                    decltype(std::get<size - 1>(std::declval<T>()))>> = true;
    template <typename T>
    inline constexpr bool tuple_like_impl2<T, 0, void> = true;

    template <typename T, typename = void>
    inline constexpr bool tuple_like_impl = false;
    template <typename T>
    inline constexpr bool tuple_like_impl<
        T, std::enable_if_t<std::is_integral_v<
               std::remove_cv_t<decltype(std::tuple_size<T>::value)>>>> =
        tuple_like_impl2<T, std::tuple_size_v<T>>;

    template <typename T, size_t N, typename = void>
    inline constexpr bool fixed_tuple_like_impl = false;
    template <typename T, size_t N>
    inline constexpr bool fixed_tuple_like_impl<
        T, N,
        std::enable_if_t<std::is_integral_v<
            std::remove_cv_t<decltype(std::tuple_size<T>::value)>>>> =
        tuple_like_impl2<T, std::tuple_size_v<T>> && std::tuple_size_v<T> == N;

    /*
     * IMPLEMENTATION
     */
    template <typename T,
              bool = __utils_has_const_methods(begin, end, cbegin, cend) &&
                     __utils_has_types(iterator, const_iterator)>
    inline constexpr bool forward_iterable_impl = false;

    template <typename T>
    inline constexpr bool forward_iterable_impl<T, true> =
        __utils_convertible_checks((begin, typename T::iterator),
                                   (end, typename T::iterator)) &&
        __utils_const_convertible_checks((begin, typename T::const_iterator),
                                         (end, typename T::const_iterator),
                                         (cbegin, typename T::const_iterator),
                                         (cend, typename T::const_iterator));

    template <typename T, bool = __utils_has_types(value_type) &&
                                 __utils_has_methods(allocate, deallocate)>
    inline constexpr bool allocator_type_impl = false;
    template <typename T>
    inline constexpr bool allocator_type_impl<T, true> =
        dereferencable<member_or_pointer_t<T>> &&
        dereferencable<member_or_const_pointer_t<T>> && equal_comparable<T> &&
        not_equal_comparable<T> && std::is_copy_constructible_v<T> &&
        allocator_value_type<typename T::value_type, T> &&
        std::is_convertible_v<member_or_pointer_t<T>,
                              member_or_const_pointer_t<T>> &&
        allocator_pointer<decltype(std::declval<T>().allocate(
                              std::declval<member_or_size_t_t<T>>())),
                          T> &&
        std::is_same_v<dereferenced_t<member_or_pointer_t<T>>,
                       typename T::value_type&> &&
        std::is_same_v<dereferenced_t<member_or_const_pointer_t<T>>,
                       const typename T::value_type&>;

    template <typename T, typename k, typename = void>
    inline constexpr bool hash_type_impl = false;
    template <typename T, typename k>
    inline constexpr bool hash_type_impl<
        T, k, std::void_t<decltype(std::declval<T>()(std::declval<k>()))>> =
        std::is_copy_constructible_v<T> && std::is_destructible_v<T> &&
        std::is_same_v<decltype(std::declval<T>()(std::declval<k>())), size_t>;

    template <typename T>
    inline constexpr bool takes_alloc_param = false;
    template <template <typename, typename, typename, typename, typename>
              typename hash_map,
              typename T1, typename T2, typename T3, typename T4, typename T5>
    inline constexpr bool takes_alloc_param<hash_map<T1, T2, T3, T4, T5>> =
        allocator_type_impl<T5>;

    template <typename T>
    inline constexpr bool takes_hasher_param = false;
    template <template <typename, typename, typename, typename, typename>
              typename hash_map,
              typename T1, typename T2, typename T3, typename T4, typename T5>
    inline constexpr bool takes_hasher_param<hash_map<T1, T2, T3, T4, T5>> =
        hash_type_impl<T3, T1>;

    template <
        typename T,
        bool = takes_alloc_param<T> && takes_hasher_param<T> &&
               __utils_has_types(key_type, mapped_type, value_type, hasher,
                                 key_equal, allocator_type, pointer,
                                 const_pointer, reference, const_reference,
                                 size_type, difference_type) &&
               __utils_has_const_methods(
                   get_allocator, empty, size, max_size, hash_function, key_eq,
                   count, max_load_factor, load_factor, bucket_count) &&
               __utils_has_methods(max_load_factorf, rehash, reserve, swap)>
    inline constexpr bool hash_map_impl = false;
    template <typename T>
    inline constexpr bool hash_map_impl<T, true> =
        std::is_default_constructible_v<T> &&
        std::is_constructible_v<
            T, typename T::size_type, const typename T::hasher&,
            const typename T::key_equal&, const typename T::allocator_type&> &&
        std::is_copy_constructible_v<T> &&
        std::is_constructible_v<T, T&, const typename T::allocator_type&> &&
        std::is_constructible_v<
            T, std::initializer_list<typename T::value_type>,
            typename T::size_type, const typename T::hasher&,
            const typename T::key_equal&, const typename T::allocator_type&> &&
        std::is_constructible_v<T, typename T::size_type,
                                const typename T::allocator_type&> &&
        std::is_constructible_v<T, typename T::size_type,
                                const typename T::hasher&,
                                const typename T::allocator_type&> &&
        std::is_constructible_v<T,
                                std::initializer_list<typename T::value_type>,
                                const typename T::allocator_type&> &&
        std::is_constructible_v<
            T, std::initializer_list<typename T::value_type>,
            typename T::size_type, const typename T::allocator_type&> &&
        std::is_constructible_v<
            T, std::initializer_list<typename T::value_type>,
            typename T::size_type, const typename T::hasher&,
            const typename T::allocator_type&> &&
        std::is_constructible_v<
            T, std::initializer_list<typename T::value_type>> &&
        std::is_copy_assignable_v<T> &&
        std::is_assignable_v<T&,
                             std::initializer_list<typename T::value_type>> &&
        __utils_same_const_method_return_types(
            (get_allocator, typename T::allocator_type), (empty, bool),
            (size, typename T::size_type), (hash_function, typename T::hasher),
            (key_eq, typename T::key_equal), (count, typename T::size_type),
            (bucket_count, typename T::size_type), (load_factor, float),
            (max_load_factor, float)) &&
        equal_comparable<T> && not_equal_comparable<T>;

    template <typename T,
              bool = __utils_has_const_methods(visit, cvisit, visit_all,
                                               cvisit_all, max_load) &&
                     __utils_has_methods(insert, inserti, insert_or_visit,
                                         insert_or_cvisit) &&
                     hash_map_impl<T>>
    inline constexpr bool concurrent_hash_map_impl = false;
    template <typename T>
    inline constexpr bool concurrent_hash_map_impl<T, true> =
        __utils_same_const_method_return_types(
            (visit, size_t), (cvisit, size_t), (visit_all, size_t),
            (cvisit_all, size_t), (max_load, typename T::size_type)) &&
        __utils_same_method_return_types(
            (insert, bool), (insert_or_visit, bool), (insert_or_cvisit, bool));

    template <typename T>
    using itr_bool_pair_t = std::pair<typename T::iterator, bool>;
    template <typename T>
    using itr_itr_pair_t =
        std::pair<typename T::iterator, typename T::iterator>;
    template <typename T>
    using citr_citr_pair_t =
        std::pair<typename T::const_iterator, typename T::const_iterator>;

    template <typename T,
              bool = __utils_has_methods(insert, inserti, insertr,
                                         insert_or_assign, insert_or_assignr,
                                         erase, erasek, merge, access) &&
                     __utils_has_const_methods(equal_range, at) &&
                     hash_map_impl<T> && forward_iterable_impl<T>>
    inline constexpr bool regular_hash_map_impl = false;
    template <typename T>
    inline constexpr bool regular_hash_map_impl<T, true> =
        __utils_same_method_return_types((insert, itr_bool_pair_t<T>),
                                         (insert_or_assign, itr_bool_pair_t<T>),
                                         (erasek, typename T::size_type),
                                         (equal_range, itr_itr_pair_t<T>),
                                         (at, typename T::mapped_type&),
                                         (access, typename T::mapped_type&)) &&
        __utils_same_const_method_return_types(
            (equal_range, citr_citr_pair_t<T>),
            (at, const typename T::mapped_type&)) &&
        __utils_convertible_checks((erase, typename T::iterator),
                                   (insert_or_assignr, typename T::iterator),
                                   (find, typename T::iterator)) &&
        __utils_const_convertible_checks((find, typename T::const_iterator));

    template <typename T, bool = __utils_has_methods(insert, inserti, insertr,
                                                     erase, erasek, merge) &&
                                 __utils_has_const_methods(equal_range) &&
                                 hash_map_impl<T> && forward_iterable_impl<T>>
    inline constexpr bool multi_hash_map_impl = false;
    template <typename T>
    inline constexpr bool multi_hash_map_impl<T, true> =
        __utils_same_method_return_types((insert, typename T::iterator),
                                         (erasek, typename T::size_type),
                                         (equal_range, itr_itr_pair_t<T>)) &&
        __utils_same_const_method_return_types(
            (equal_range, citr_citr_pair_t<T>)) &&
        __utils_convertible_checks((erase, typename T::iterator),
                                   (find, typename T::iterator)) &&
        __utils_const_convertible_checks((find, typename T::const_iterator));

    template <
        typename T,
        bool =
            (regular_hash_map_impl<T> ||
             multi_hash_map_impl<T>)&&__utils_has_types(local_iterator,
                                                        const_local_iterator) &&
            __utils_has_const_methods(bbegin, bend, bcbegin, bcend,
                                      max_bucket_count, bucket_size, bucket)>
    inline constexpr bool closed_addressing_impl = false;
    template <typename T>
    inline constexpr bool closed_addressing_impl<T, true> =
        __utils_same_method_return_types((bbegin, typename T::local_iterator),
                                         (bend, typename T::local_iterator)) &&
        __utils_same_const_method_return_types(
            (bbegin, typename T::const_local_iterator),
            (bend, typename T::const_local_iterator),
            (bcbegin, typename T::const_local_iterator),
            (bcend, typename T::const_local_iterator),
            (max_bucket_count, typename T::size_type),
            (bucket_size, typename T::size_type),
            (bucket, typename T::size_type));
  } // namespace helpers

  template <typename T>
  inline constexpr bool tuple_like =
      helpers::tuple_like_impl<remove_cvref_t<T>>;

  template <typename T, size_t N>
  inline constexpr bool fixed_tuple_like =
      helpers::fixed_tuple_like_impl<remove_cvref_t<T>, N>;

  template <typename T>
  inline constexpr bool pair_like = fixed_tuple_like<T, 2>;

  template <typename T>
  inline constexpr bool allocator_type = helpers::allocator_type_impl<T>;

  template <typename T, typename k>
  inline constexpr bool hash_type = helpers::hash_type_impl<T, k>;

  template <typename T>
  inline constexpr bool hash_map = helpers::hash_map_impl<T>;

  template <typename T>
  inline constexpr bool concurrent_hash_map =
      helpers::concurrent_hash_map_impl<T>;

  template <typename T>
  inline constexpr bool regular_hash_map = helpers::regular_hash_map_impl<T>;

  template <typename T>
  inline constexpr bool multi_hash_map = helpers::multi_hash_map_impl<T>;

  template <typename T>
  inline constexpr bool closed_addressing = helpers::closed_addressing_impl<T>;
#endif

  template <typename... types>
  utils_concept tuple_like_types = (tuple_like<types> && ...);

  template <typename... types>
  utils_concept pair_like_types = (pair_like<types> && ...);

  template <size_t N, typename... types>
  utils_concept fixed_tuple_like_types = (fixed_tuple_like<types, N> && ...);

  namespace helpers
  {
    template <typename detour, typename original>
    utils_concept detour_and_original_requirements =
        function_type<original> && std::is_lvalue_reference_v<original> &&
        (callable_type<detour> || disambiguatable_with<detour, original>);

    template <typename first_key, typename key, typename detour,
              typename original>
    utils_concept key_detour_and_original_requirements =
        std::is_convertible_v<std::decay_t<key>, std::decay_t<first_key>> &&
        detour_and_original_requirements<detour, original>;

    template <typename seq, bool = true>
    inline constexpr bool detours_and_originals_impl = false;

    template <typename tuple, typename... rest>
    inline constexpr bool detours_and_originals_impl<
        type_sequence<tuple, rest...>, true> =
        detours_and_originals_impl<
            type_sequence<rest...>,
            detour_and_original_requirements<std::tuple_element_t<0, tuple>,
                                             std::tuple_element_t<1, tuple>>>;

    template <typename first, typename second, typename... rest>
    inline constexpr bool detours_and_originals_impl<
        type_sequence<type_sequence<first, second>, rest...>, true> =
        detours_and_originals_impl<
            type_sequence<rest...>,
            detour_and_original_requirements<first, second>>;

    template <>
    inline constexpr bool detours_and_originals_impl<type_sequence<>, true> =
        true;

    template <typename key, typename seq, bool = true>
    inline constexpr bool keys_detours_and_originals_impl = false;

    template <typename key, typename tuple, typename... rest>
    inline constexpr bool keys_detours_and_originals_impl<
        key, type_sequence<tuple, rest...>, true> =
        keys_detours_and_originals_impl<key, type_sequence<rest...>,
                                        key_detour_and_original_requirements<
                                            key, std::tuple_element_t<0, tuple>,
                                            std::tuple_element_t<1, tuple>,
                                            std::tuple_element_t<2, tuple>>>;

    template <typename key, typename first, typename second, typename third,
              typename... rest>
    inline constexpr bool keys_detours_and_originals_impl<
        key, type_sequence<type_sequence<first, second, third>, rest...>,
        true> =
        keys_detours_and_originals_impl<
            key, type_sequence<rest...>,
            key_detour_and_original_requirements<key, first, second, third>>;

    template <typename key>
    inline constexpr bool
        keys_detours_and_originals_impl<key, type_sequence<>, true> = true;

#if !utils_cpp20
    template <typename seq, typename = void>
    inline constexpr bool detours_and_originals_impl2 = false;
    template <typename... types>
    inline constexpr bool detours_and_originals_impl2<
        type_sequence<types...>, std::enable_if_t<(sizeof...(types) % 2) == 0 &&
                                                  !pair_like_types<types...>>> =
        detours_and_originals_impl<make_type_pairs_t<types...>>;

    template <typename seq, typename = void>
    inline constexpr bool keys_detours_and_originals_impl2 = false;
    template <typename first, typename... rest>
    inline constexpr bool keys_detours_and_originals_impl2<
        type_sequence<first, rest...>,
        std::enable_if_t<((sizeof...(rest) + 1) % 3) == 0 &&
                         !fixed_tuple_like_types<3, first, rest...>>> =
        keys_detours_and_originals_impl<first,
                                        make_type_triplets_t<first, rest...>>;

    template <typename seq, typename = void>
    inline constexpr bool detour_and_original_pairs_impl = false;
    template <typename... types>
    inline constexpr bool detour_and_original_pairs_impl<
        type_sequence<types...>, std::enable_if_t<pair_like_types<types...>>> =
        detours_and_originals_impl<type_sequence<remove_cvref_t<types>...>>;

    template <typename seq, typename = void>
    inline constexpr bool key_detour_and_original_triplets_impl = false;
    template <typename first, typename... rest>
    inline constexpr bool key_detour_and_original_triplets_impl<
        type_sequence<first, rest...>,
        std::enable_if_t<fixed_tuple_like_types<3, first, rest...>>> =
        keys_detours_and_originals_impl<
            std::tuple_element_t<0, remove_cvref_t<first>>,
            type_sequence<remove_cvref_t<first>, remove_cvref_t<rest>...>>;
#endif
  } // namespace helpers

#if !utils_cpp20
  template <typename detour, typename original, typename... rest>
  inline constexpr bool detours_and_originals =
      helpers::detours_and_originals_impl2<
          type_sequence<detour, original, rest...>>;

  template <typename key, typename detour, typename original, typename... rest>
  inline constexpr bool keys_detours_and_originals =
      helpers::keys_detours_and_originals_impl2<
          type_sequence<key, detour, original, rest...>>;

  template <typename pair, typename... rest>
  inline constexpr bool detour_and_original_pairs =
      helpers::detour_and_original_pairs_impl<type_sequence<pair, rest...>>;
  template <typename tuple, typename... rest>
  inline constexpr bool key_detour_and_original_triplets =
      helpers::key_detour_and_original_triplets_impl<
          type_sequence<tuple, rest...>>;
#else
  template <typename detour, typename original, typename... rest>
  concept detours_and_originals =
      !pair_like_types<detour, original, rest...> &&
      (sizeof...(rest) % 2) == 0 &&
      helpers::detours_and_originals_impl<
          make_type_pairs_t<detour, original, rest...>>;

  template <typename key, typename detour, typename original, typename... rest>
  concept keys_detours_and_originals =
      !tuple_like_types<key, detour, original, rest...> &&
      (sizeof...(rest) % 3) == 0 &&
      helpers::keys_detours_and_originals_impl<
          key, make_type_triplets_t<key, detour, original, rest...>>;

  template <typename pair, typename... rest>
  concept detour_and_original_pairs =
      pair_like_types<pair, rest...> &&
      helpers::detours_and_originals_impl<
          type_sequence<remove_cvref_t<pair>, remove_cvref_t<rest>...>>;

  template <typename tuple, typename... rest>
  concept key_detour_and_original_triplets =
      fixed_tuple_like_types<3, tuple, rest...> &&
      helpers::keys_detours_and_originals_impl<
          std::tuple_element_t<0, remove_cvref_t<tuple>>,
          type_sequence<remove_cvref_t<tuple>, remove_cvref_t<rest>...>>;
#endif
} // namespace alterhook::utils

#if utils_msvc
  #pragma warning(pop)
#endif
