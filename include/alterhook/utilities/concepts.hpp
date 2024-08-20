/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <utility>
#include <initializer_list>
#include <unordered_map>
#include "macros.hpp"
#include "type_sequence.hpp"
#include "function_traits.hpp"

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
        } -> std::same_as<typename T::value_type&>;
        {
          *cp
        } -> std::same_as<const typename T::value_type&>;
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
      requires(const T& cinstance, T& instance, const typename T::key_type& key,
               helpers::visit_dummy func, const typename T::value_type& val,
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
      requires(const T& cinstance, T& instance,
               const typename T::value_type& val, typename T::iterator itr,
               std::initializer_list<typename T::value_type> list,
               const typename T::mapped_type&                obj,
               const typename T::key_type&                   key,
               typename T::const_iterator                    citr) {
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
          const typename T::key_type& key, typename T::const_iterator citr) {
        typename T::local_iterator;
        typename T::const_local_iterator;
        typename T::node_type;
        typename T::insert_return_type;
        {
          instance.extract(citr)
        } -> std::same_as<typename T::node_type>;
        {
          instance.extract(key)
        } -> std::same_as<typename T::node_type>;
        {
          instance.insert(instance.extract(key))
        } -> std::same_as<typename T::insert_return_type>;
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
      } &&
      requires(typename T::node_type& node, const typename T::node_type& cnode,
               typename T::insert_return_type& insert_ret,
               const typename T::key_type&     key,
               const typename T::mapped_type&  value) {
        typename T::node_type::key_type;
        typename T::node_type::mapped_type;
        typename T::node_type::allocator_type;
        requires std::default_initializable<typename T::node_type>;
        requires std::move_constructible<typename T::node_type>;
        requires std::assignable_from<typename T::node_type&,
                                      typename T::node_type>;
        {
          cnode.empty()
        } -> std::same_as<bool>;
        {
          cnode.get_allocator()
        } -> std::same_as<typename T::node_type::allocator_type>;
        cnode.key()    = key;
        cnode.mapped() = value;
        node.swap(node);
        {
          insert_ret.position
        } -> std::same_as<typename T::iterator&>;
        {
          insert_ret.inserted
        } -> std::same_as<bool&>;
        {
          insert_ret.node
        } -> std::same_as<typename T::node_type&>;
      };
#else
  namespace helpers
  {
  #define __utils_make_arg(type) std::declval<type>()
  #define __utils_make_args(...) utils_map_list(__utils_make_arg, __VA_ARGS__)

    /*
     * IMPLEMENTATION CODE GENERATORS
     */
  #define __utils_gen_method_checker(name)                                     \
    template <typename T, typename... args>                                    \
    using name##_method_ret_t =                                                \
        decltype(std::declval<T&>().name(std::declval<args>()...));            \
    template <typename T, typename args, typename = void>                      \
    inline constexpr bool has_##name##_method_impl_v = false;                  \
    template <typename T, typename... args>                                    \
    inline constexpr bool has_##name##_method_impl_v<                          \
        T, type_sequence<args...>,                                             \
        std::void_t<name##_method_ret_t<T, args...>>> = true;                  \
    template <typename T, typename... args>                                    \
    inline constexpr bool has_##name##_method_v =                              \
        has_##name##_method_impl_v<T, type_sequence<args...>>;

  #define __utils_gen_member_type_checker(name)                                \
    template <typename T, typename = void>                                     \
    inline constexpr bool has_##name##_member_type_v = false;                  \
    template <typename T>                                                      \
    inline constexpr bool                                                      \
        has_##name##_member_type_v<T, std::void_t<typename T::name>> = true;

    /*
     * CHECKS GENERATORS
     */
  #define __utils_has_method_noargs(cls, name) has_##name##_method_v<cls>

  #define __utils_has_method_args_impl(cls, name, args)                        \
    has_##name##_method_v<cls, utils_expand args>

  #define __utils_has_method_args(cls, pair)                                   \
    __utils_call(__utils_has_method_args_impl, (cls, utils_expand pair))

  #define __utils_has_method(name, cls)                                        \
    utils_if(utils_is_call_operator(name))(                                    \
        __utils_has_method_args, __utils_has_method_noargs)(cls, name)

  #define __utils_has_member_type(name, cls) has_##name##_member_type_v<cls>

  #define __utils_same_method_return_type_noargs(cls, name, type)              \
    std::is_same_v<name##_method_ret_t<cls>, type>

  #define __utils_same_method_return_type_args_impl(cls, name, args, type)     \
    std::is_same_v<name##_method_ret_t<cls, utils_expand args>, type>

  #define __utils_same_method_return_type_args(cls, pair, type)                \
    __utils_call(__utils_same_method_return_type_args_impl,                    \
                 (cls, utils_expand pair, type))

  #define __utils_same_method_return_type_impl(cls, name, type)                \
    utils_if(utils_is_call_operator(name))(                                    \
        __utils_same_method_return_type_args,                                  \
        __utils_same_method_return_type_noargs)(cls, name, type)

  #define __utils_same_method_return_type(pair, cls)                           \
    __utils_call2(__utils_same_method_return_type_impl,                        \
                  (cls, utils_expand pair))

  #define __utils_convertible_method_return_type_noargs(cls, name, type)       \
    std::is_convertible_v<name##_method_ret_t<cls>, type>

  #define __utils_convertible_method_return_type_args_impl(cls, name, args,    \
                                                           type)               \
    std::is_convertible_v<name##_method_ret_t<cls, utils_expand args>, type>

  #define __utils_convertible_method_return_type_args(cls, pair, type)         \
    __utils_call(__utils_convertible_method_return_type_args_impl,             \
                 (cls, utils_expand pair, type))

  #define __utils_convertible_method_return_type_impl(cls, name, type)         \
    utils_if(utils_is_call_operator(name))(                                    \
        __utils_convertible_method_return_type_args,                           \
        __utils_convertible_method_return_type_noargs)(cls, name, type)

  #define __utils_convertible_method_return_type(pair, cls)                    \
    __utils_call2(__utils_convertible_method_return_type_impl,                 \
                  (cls, utils_expand pair))

    /*
     * ABSTRACTED GENERATORS
     */
  #define __utils_has_methods(cls, ...)                                        \
    utils_map_separated_ud(__utils_has_method, &&, cls, __VA_ARGS__)

  #define __utils_has_member_types(cls, ...)                                   \
    utils_map_separated_ud(__utils_has_member_type, &&, cls, __VA_ARGS__)

  #define __utils_same_method_return_types(cls, ...)                           \
    utils_map_separated_ud(__utils_same_method_return_type, &&, cls,           \
                           __VA_ARGS__)

  #define __utils_convertible_method_return_types(cls, ...)                    \
    utils_map_separated_ud(__utils_convertible_method_return_type, &&, cls,    \
                           __VA_ARGS__)

    /*
     * IMPLEMENTATION GENERATION
     */
    // exception
    template <typename T, typename arg>
    using access_operator_ret_t =
        decltype(std::declval<T&>()[std::declval<arg>()]);
    template <typename T, typename arg, typename = void>
    inline constexpr bool has_access_operator_v = false;
    template <typename T, typename arg>
    inline constexpr bool has_access_operator_v<
        T, arg, std::void_t<access_operator_ret_t<T, arg>>> = true;

    // clang-format off
    utils_map(__utils_gen_method_checker, begin, end, cbegin, cend,
              get_allocator, empty, size, max_size, hash_function, key_eq,
              bucket_count, bucket_size, bucket, load_factor, max_load_factor,
              max_load, clear, max_bucket_count, allocate, deallocate, count,
              rehash, reserve, swap, visit, cvisit, visit_all, cvisit_all,
              insert, insert_or_visit, insert_or_cvisit, insert_or_assign,
              erase, merge, find, equal_range, at)

    /*utils_map(
        __utils_gen_args_checker,
        (begin, bbegin, __utils_make_args(typename T::size_type)),
        (end, bend, __utils_make_args(typename T::size_type)),
        (cbegin, bcbegin, __utils_make_args(typename T::size_type)),
        (cend, bcend, __utils_make_args(typename T::size_type)),
        (bucket_size, bucket_size, __utils_make_args(typename T::size_type)),
        (bucket, bucket, __utils_make_args(const typename T::key_type&)))*/

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
              bool = __utils_has_methods(T, begin, end, cbegin, cend) &&
                     __utils_has_member_types(T, iterator, const_iterator)>
    inline constexpr bool forward_iterable_impl = false;
    template <typename T>
    inline constexpr bool forward_iterable_impl<T, true> =
        __utils_convertible_method_return_types(
            T, (begin, typename T::iterator), (end, typename T::iterator)) &&
        __utils_convertible_method_return_types(
            const T, (begin, typename T::const_iterator),
            (end, typename T::const_iterator),
            (cbegin, typename T::const_iterator),
            (cend, typename T::const_iterator));

    template <typename T,
              bool = __utils_has_member_types(T, value_type) &&
                     __utils_has_methods(T, (allocate, (member_or_size_t_t<T>)),
                                         (deallocate, (member_or_pointer_t<T>,
                                                       member_or_size_t_t<T>)))>
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

    template <typename T,
              bool = __utils_has_methods(const T, get_allocator, empty, size,
                                         max_size, hash_function, key_eq,
                                         (count, (const typename T::key_type&)),
                                         max_load_factor, load_factor,
                                         bucket_count) &&
                     __utils_has_methods(T, (max_load_factor, (float)),
                                         (rehash, (typename T::size_type)),
                                         (reserve, (typename T::size_type)),
                                         (swap, (T&)))>
    inline constexpr bool has_map_impl2 = false;
    template <typename T>
    inline constexpr bool has_map_impl2<T, true> =
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
        __utils_same_method_return_types(
            const T, (get_allocator, typename T::allocator_type), (empty, bool),
            (size, typename T::size_type), (hash_function, typename T::hasher),
            (key_eq, typename T::key_equal),
            ((count, (const typename T::key_type&)), typename T::size_type),
            (bucket_count, typename T::size_type), (load_factor, float),
            (max_load_factor, float)) &&
        equal_comparable<T> && not_equal_comparable<T>;

    template <typename T, bool = takes_alloc_param<T> &&
                                 takes_hasher_param<T> &&
                                 __utils_has_member_types(
                                     T, key_type, mapped_type, value_type,
                                     hasher, key_equal, allocator_type, pointer,
                                     const_pointer, reference, const_reference,
                                     size_type, difference_type)>
    inline constexpr bool hash_map_impl = false;
    template <typename T>
    inline constexpr bool hash_map_impl<T, true> = has_map_impl2<T>;

    template <
        typename T,
        bool =
            __utils_has_methods(
                const T, (visit, (const typename T::key_type&, visit_dummy)),
                (cvisit, (const typename T::key_type&, visit_dummy)),
                (visit_all, (visit_dummy)), (cvisit_all, (visit_dummy)),
                max_load) &&
            __utils_has_methods(
                T, (insert, (const typename T::value_type&)),
                (insert, (std::initializer_list<typename T::value_type>)),
                (insert_or_visit, (const typename T::value_type&, visit_dummy)),
                (insert_or_cvisit,
                 (const typename T::value_type&, visit_dummy)))>
    inline constexpr bool concurrent_hash_map_impl2 = false;
    template <typename T>
    inline constexpr bool concurrent_hash_map_impl2<T, true> =
        __utils_same_method_return_types(
            const T,
            ((visit, (const typename T::key_type&, visit_dummy)), size_t),
            ((cvisit, (const typename T::key_type&, visit_dummy)), size_t),
            ((visit_all, (visit_dummy)), size_t),
            ((cvisit_all, (visit_dummy)), size_t),
            (max_load, typename T::size_type)) &&
        __utils_same_method_return_types(
            T, ((insert, (const typename T::value_type&)), bool),
            ((insert_or_visit, (const typename T::value_type&, visit_dummy)),
             bool),
            ((insert_or_cvisit, (const typename T::value_type&, visit_dummy)),
             bool));

    template <typename T, bool = hash_map_impl<T>>
    inline constexpr bool concurrent_hash_map_impl = false;
    template <typename T>
    inline constexpr bool concurrent_hash_map_impl<T, true> =
        concurrent_hash_map_impl2<T>;

    template <typename T>
    using itr_bool_pair_t = std::pair<typename T::iterator, bool>;
    template <typename T>
    using itr_itr_pair_t =
        std::pair<typename T::iterator, typename T::iterator>;
    template <typename T>
    using citr_citr_pair_t =
        std::pair<typename T::const_iterator, typename T::const_iterator>;

    template <typename T,
              bool =
                  __utils_has_methods(
                      T, (insert, (const typename T::value_type&)),
                      (insert, (std::initializer_list<typename T::value_type>)),
                      (insert, (typename T::iterator, typename T::iterator)),
                      (insert_or_assign, (const typename T::key_type&,
                                          const typename T::mapped_type&)),
                      (insert_or_assign,
                       (typename T::const_iterator, const typename T::key_type&,
                        const typename T::mapped_type&)),
                      (erase, (typename T::const_iterator)),
                      (erase, (const typename T::key_type&)), (merge, (T&))) &&
                  __utils_has_methods(
                      const T, (equal_range, (const typename T::key_type&)),
                      (at, (const typename T::key_type&)),
                      (find, (const typename T::key_type&))) &&
                  has_access_operator_v<T, const typename T::key_type&>>
    inline constexpr bool regular_hash_map_impl2 = false;
    template <typename T>
    inline constexpr bool regular_hash_map_impl2<T, true> =
        __utils_same_method_return_types(
            T, ((insert, (const typename T::value_type&)), itr_bool_pair_t<T>),
            ((insert_or_assign,
              (const typename T::key_type&, const typename T::mapped_type&)),
             itr_bool_pair_t<T>),
            ((erase, (const typename T::key_type&)), typename T::size_type),
            ((equal_range, (const typename T::key_type&)), itr_itr_pair_t<T>),
            ((at, (const typename T::key_type&)), typename T::mapped_type&)) &&
        __utils_same_method_return_types(
            const T,
            ((equal_range, (const typename T::key_type&)), citr_citr_pair_t<T>),
            ((at, (const typename T::key_type&)),
             const typename T::mapped_type&)) &&
        __utils_convertible_method_return_types(
            T, ((erase, (typename T::const_iterator)), typename T::iterator),
            ((insert_or_assign,
              (typename T::const_iterator, const typename T::key_type&,
               const typename T::mapped_type&)),
             typename T::iterator),
            ((find, (const typename T::key_type&)), typename T::iterator)) &&
        __utils_convertible_method_return_types(
            const T, ((find, (const typename T::key_type&)),
                      typename T::const_iterator)) &&
        std::is_same_v<access_operator_ret_t<T, const typename T::key_type&>,
                       typename T::mapped_type&>;

    template <typename T, bool = hash_map_impl<T> && forward_iterable_impl<T>>
    inline constexpr bool regular_hash_map_impl = false;
    template <typename T>
    inline constexpr bool regular_hash_map_impl<T, true> =
        regular_hash_map_impl2<T>;

    template <typename T,
              bool =
                  __utils_has_methods(
                      T, (insert, (const typename T::value_type&)),
                      (insert, (std::initializer_list<typename T::value_type>)),
                      (insert, (typename T::iterator, typename T::iterator)),
                      (erase, (typename T::const_iterator)),
                      (erase, (const typename T::key_type&)), (merge, (T&))) &&
                  __utils_has_methods(
                      const T, (equal_range, (const typename T::key_type&)),
                      (find, (const typename T::key_type&)))>
    inline constexpr bool multi_hash_map_impl2 = false;
    template <typename T>
    inline constexpr bool multi_hash_map_impl2<T, true> =
        __utils_same_method_return_types(
            T,
            ((insert, (const typename T::value_type&)), typename T::iterator),
            ((erase, (const typename T::key_type&)), typename T::size_type),
            ((equal_range, (const typename T::key_type&)),
             itr_itr_pair_t<T>)) &&
        __utils_same_method_return_types(
            const T, ((equal_range, (const typename T::key_type&)),
                      citr_citr_pair_t<T>)) &&
        __utils_convertible_method_return_types(
            T, ((erase, (typename T::const_iterator)), typename T::iterator),
            ((find, (const typename T::key_type&)), typename T::iterator)) &&
        __utils_convertible_method_return_types(
            const T, ((find, (const typename T::key_type&)),
                      typename T::const_iterator));

    template <typename T, bool = hash_map_impl<T> && forward_iterable_impl<T>>
    inline constexpr bool multi_hash_map_impl = false;
    template <typename T>
    inline constexpr bool multi_hash_map_impl<T, true> =
        multi_hash_map_impl2<T>;

    template <typename T,
              bool = __utils_has_methods(
                  const T, (begin, (typename T::size_type)),
                  (end, (typename T::size_type)),
                  (cbegin, (typename T::size_type)),
                  (cend, (typename T::size_type)),
                  (bucket_size, (typename T::size_type)),
                  (bucket, (const typename T::key_type&)), max_bucket_count)>
    inline constexpr bool closed_addressing_impl2 = false;
    template <typename T>
    inline constexpr bool closed_addressing_impl2<T, true> =
        __utils_same_method_return_types(
            T, ((begin, (typename T::size_type)), typename T::local_iterator),
            ((end, (typename T::size_type)), typename T::local_iterator)) &&
        __utils_same_method_return_types(
            const T,
            ((begin, (typename T::size_type)),
             typename T::const_local_iterator),
            ((end, (typename T::size_type)), typename T::const_local_iterator),
            ((cbegin, (typename T::size_type)),
             typename T::const_local_iterator),
            ((cend, (typename T::size_type)), typename T::const_local_iterator),
            ((bucket_size, (typename T::size_type)), typename T::size_type),
            ((bucket, (const typename T::key_type&)), typename T::size_type),
            (max_bucket_count, typename T::size_type));

    template <typename T,
              bool = __utils_has_member_types(T, local_iterator,
                                              const_local_iterator) &&
                     (regular_hash_map_impl<T> || multi_hash_map_impl<T>)>
    inline constexpr bool closed_addressing_impl = false;
    template <typename T>
    inline constexpr bool closed_addressing_impl<T, true> =
        closed_addressing_impl2<T>;
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
