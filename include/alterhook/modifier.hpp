/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <atomic>
#include <numeric>
#include "hook_map.hpp"

#if utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wunused-local-typedef"
#endif

namespace alterhook
{
  class managed_concurrent_hook_map : concurrent_hook_map<std::string>
  {
  public:
    typedef concurrent_hook_map<std::string> base;
    using typename base::allocator_type;
    using typename base::chain_iterator;
    using typename base::const_chain_iterator;
    using typename base::const_hook_reference;
    using typename base::const_list_iterator;
    using typename base::const_pointer;
    using typename base::const_reference;
    using typename base::const_reverse_list_iterator;
    using typename base::difference_type;
    using typename base::hasher;
    using typename base::hook;
    using typename base::hook_reference;
    using typename base::included_states;
    using typename base::key_equal;
    using typename base::key_type;
    using typename base::list_iterator;
    using typename base::mapped_type;
    using typename base::pointer;
    using typename base::reference;
    using typename base::reverse_list_iterator;
    using typename base::size_type;
    using typename base::value_type;
    using transfer = typename base::transfer;

    using base::base;
    using base::bucket_count;
    using base::count;
    using base::cvisit;
    using base::cvisit_all;
    using base::disabled_size;
    using base::empty;
    using base::empty_disabled;
    using base::empty_enabled;
    using base::enabled_size;
    using base::erase_if;
    using base::get_target;
    using base::insert;
    using base::insert_or_cvisit;
    using base::insert_or_visit;
    using base::load_factor;
    using base::max_load_factor;
    using base::rehash;
    using base::reserve;
    using base::splice;
    using base::visit;
    using base::visit_all;
    using base::operator bool;
    using base::clear;
    using base::disable_all;
    using base::enable_all;
    using base::erase;
    using base::get_allocator;
    using base::hash_function;
    using base::key_eq;
    using base::max_size;

    managed_concurrent_hook_map() = default;

  private:
    mutable std::atomic_size_t ref_count;

    struct deleter
    {
      constexpr deleter() noexcept = default;

      constexpr deleter(const deleter&) noexcept {}

      void operator()(
          const managed_concurrent_hook_map* instance) const noexcept;
    };

    friend class hook_manager;
    friend struct deleter;

    managed_concurrent_hook_map(const managed_concurrent_hook_map&) = delete;
    managed_concurrent_hook_map&
        operator=(const managed_concurrent_hook_map&) = delete;
  };

  class hook_manager
      : std::unordered_map<std::byte*, managed_concurrent_hook_map>
  {
  public:
    typedef std::unordered_map<std::byte*, managed_concurrent_hook_map> base;
    typedef std::unique_ptr<managed_concurrent_hook_map,
                            typename managed_concurrent_hook_map::deleter>
        handle;
    typedef std::unique_ptr<const managed_concurrent_hook_map,
                            typename managed_concurrent_hook_map::deleter>
        const_handle;

    ALTERHOOK_API static hook_manager& get();
    handle                             operator[](std::byte* target);
    const_handle                       operator[](std::byte* target) const;
    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    handle operator[](trg&& target);
    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    const_handle operator[](trg&& target) const;
    template <typename K, typename dtr, typename orig, typename... types>
    void insert(std::byte* target, K&& key, dtr&& detour, orig& original,
                types&&... rest);
    template <typename K>
    void erase(std::byte* target, const K& key);
    template <typename K>
    void enable(std::byte* target, const K& key);
    template <typename K>
    void disable(std::byte* target, const K& key);

  private:
    friend class managed_concurrent_hook_map;
    mutable std::shared_mutex manager_lock;

    using base::erase;

    hook_manager() {}

    hook_manager(const hook_manager&)            = delete;
    hook_manager& operator=(const hook_manager&) = delete;
  };

  inline void managed_concurrent_hook_map::deleter::operator()(
      const managed_concurrent_hook_map* map) const noexcept
  {
    typedef typename managed_concurrent_hook_map::adapted adapted;
    auto&            instance = hook_manager::get();
    std::unique_lock lock{ instance.manager_lock };
    if (!(--map->ref_count) && map->adapted::empty())
      instance.erase(map->get_target());
  }

  inline typename hook_manager::handle hook_manager::operator[](std::byte* key)
  {
    std::shared_lock             lock{ manager_lock };
    managed_concurrent_hook_map& entry = at(key);
    ++entry.ref_count;
    return handle(&entry);
  }

  inline typename hook_manager::const_handle
      hook_manager::operator[](std::byte* key) const
  {
    std::shared_lock                   lock{ manager_lock };
    const managed_concurrent_hook_map& entry = at(key);
    ++entry.ref_count;
    return const_handle(&entry);
  }

  template <typename trg, typename>
  typename hook_manager::handle hook_manager::operator[](trg&& target)
  {
    return operator[](get_target_address(std::forward<trg>(target)));
  }

  template <typename trg, typename>
  typename hook_manager::const_handle
      hook_manager::operator[](trg&& target) const
  {
    return operator[](get_target_address(std::forward<trg>(target)));
  }

  template <typename K, typename dtr, typename orig, typename... types>
  void hook_manager::insert(std::byte* target, K&& key, dtr&& detour,
                            orig& original, types&&... rest)
  {
    std::unique_lock lock{ manager_lock };
    auto [itr, status] = base::try_emplace(target, target);
    itr->second.insert(std::forward<K>(key), std::forward<dtr>(detour),
                       original, std::forward<types>(rest)...);
  }

  template <typename K>
  void hook_manager::erase(std::byte* target, const K& key)
  {
    typedef typename managed_concurrent_hook_map::adapted adapted;

    std::unique_lock lock{ manager_lock };
    auto             itr = base::find(target);
    if (itr == base::end())
      return;
    itr->second.erase(key);
    if (!itr->second.ref_count.load() && itr->second.adapted::empty())
      base::erase(target);
  }

  template <typename K>
  void hook_manager::enable(std::byte* target, const K& key)
  {
    std::shared_lock lock{ manager_lock };
    auto             itr = base::find(target);
    if (itr == base::end())
      return;
    itr->second.visit(key, [](auto pair) { pair.second.enable(); });
  }

  template <typename K>
  void hook_manager::disable(std::byte* target, const K& key)
  {
    std::shared_lock lock{ manager_lock };
    auto             itr = base::find(target);
    if (itr == base::end())
      return;
    itr->second.visit(key, [](auto pair) { pair.second.disable(); });
  }

#define __alterhook_call(x, y)  x y
#define __alterhook_call2(x, y) x y

#ifndef __INTELLISENSE__
  #define __alterhook_define_original_variable(tag, cv)                        \
    template <typename R, typename origcls, typename... args,                  \
              typename derived>                                                \
    decltype(get(tag{})) original_wrapper_##tag<R(cv origcls*, args...),       \
                                                derived>::original_##tag{};
#else
  #define __alterhook_define_original_variable(tag, cv)
#endif

#define __alterhook_define_original_wrapper_partial_specialization(cls, tag,   \
                                                                   name, cv)   \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      template <typename R, typename origcls, typename... args,                \
                typename derived>                                              \
      class original_wrapper_##tag<R(cv origcls*, args...), derived>           \
      {                                                                        \
      public:                                                                  \
        R name(args... values) cv;                                             \
                                                                               \
      protected:                                                               \
        static decltype(get(tag{})) original_##tag;                            \
      };                                                                       \
      __alterhook_define_original_variable(tag, cv)                            \
    }                                                                          \
  }

#define __alterhook_define_original_wrapper_class(cls, tag, name, ...)         \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      template <typename T, typename T2>                                       \
      class original_wrapper_##tag;                                            \
    }                                                                          \
  }                                                                            \
  __alterhook_define_original_wrapper_partial_specialization(cls, tag, name, ) \
      __alterhook_define_original_wrapper_partial_specialization(cls, tag,     \
                                                                 name, const)

#define __alterhook_define_original_wrapper_method(cls, modifier_handler, tag, \
                                                   name, cv)                   \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      template <typename R, typename origcls, typename... args,                \
                typename derived>                                              \
      R original_wrapper_##tag<R(cv origcls*, args...), derived>::name(        \
          args... values) cv                                                   \
      {                                                                        \
        return (static_cast<cv modifier_handler<derived>&>(*this).*            \
                original_##tag)(std::forward<args>(values)...);                \
      }                                                                        \
    }                                                                          \
  }

#define __alterhook_define_unique_method_getter(tag, name, cls)                \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      struct tag                                                               \
      {                                                                        \
      };                                                                       \
      template <auto value>                                                    \
      struct extract_method_##tag                                              \
      {                                                                        \
        friend constexpr auto get(tag) { return value; }                       \
      };                                                                       \
      template struct extract_method_##tag<&cls::name>;                        \
      constexpr auto get(tag);                                                 \
    }                                                                          \
  }

#define __alterhook_define_overloaded_method_getter(tag, name, type, cls)      \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      struct tag                                                               \
      {                                                                        \
      };                                                                       \
      template <typename ptr_t, ptr_t value>                                   \
      struct extract_method_##tag                                              \
      {                                                                        \
        friend constexpr ptr_t get(tag) { return value; }                      \
      };                                                                       \
      using alias_type_##tag = type;                                           \
      using ptr_t_##tag      = alias_type_##tag cls::*;                        \
      template struct extract_method_##tag<ptr_t_##tag, &cls::name>;           \
      constexpr ptr_t_##tag get(tag);                                          \
    }                                                                          \
  }

#define __alterhook_define_cached_target_address_getter(tag)                   \
  static std::byte* cached_get(__modifier_helpers::tag)                        \
  {                                                                            \
    static std::byte* cache =                                                  \
        ::alterhook::get_target_address(get(__modifier_helpers::tag{}));       \
    return cache;                                                              \
  }

#define __alterhook_define_unique_castable_concept(dummy, tag, name)
#if utils_cpp20
  #define __alterhook_define_overloaded_castable_concept(dummy, tag, name,     \
                                                         type)                 \
    template <typename T>                                                      \
    concept castable_##tag = requires {                                        \
      static_cast<::alterhook::utils::add_cls_t<type, T>>(&T::name);           \
    };
#else
  #define __alterhook_define_overloaded_castable_concept(dummy, tag, name,     \
                                                         type)                 \
    template <typename T, typename = void>                                     \
    inline constexpr bool castable_##tag = false;                              \
    template <typename T>                                                      \
    inline constexpr bool castable_##tag<                                      \
        T, std::void_t<decltype(static_cast<::alterhook::utils::add_cls_t<     \
                                    type, T>>(&T::name))>> = true;
#endif

/*
 * GENERATORS
 */
// cache generators
#define __alterhook_generate_cached_target_address_getter2(callback, tag, ...) \
  utils_defer(__alterhook_define_cached_target_address_getter)(tag)

#define __alterhook_generate_cached_target_address_getter(data)                \
  __alterhook_generate_cached_target_address_getter2 data

// Original Wrapper Inheritance List
#define __alterhook_generate_original_wrapper_inheritance3(tag, ...)           \
public                                                                         \
  __modifier_helpers::original_wrapper_##tag<                                  \
      ::alterhook::utils::clean_function_type_t<decltype(get(                  \
          __modifier_helpers::tag{}))>,                                        \
      derived>

#define __alterhook_generate_original_wrapper_inheritance2(callback, tag, ...) \
  __alterhook_generate_original_wrapper_inheritance3(tag, __VA_ARGS__)

#define __alterhook_generate_original_wrapper_inheritance(data)                \
  __alterhook_generate_original_wrapper_inheritance2 data

#define __alterhook_generate_original_wrapper_inheritance_list(info)           \
  __alterhook_call2(                                                           \
      utils_map_list,                                                          \
      (__alterhook_generate_original_wrapper_inheritance, utils_expand info))

// Original Wrapper Method Implementation
#define __alterhook_generate_original_wrapper_method_implenentation3(          \
    cls, modifier_handler, tag, name, ...)                                     \
  __alterhook_define_original_wrapper_method(cls, modifier_handler, tag,       \
                                             name, )                           \
      __alterhook_define_original_wrapper_method(cls, modifier_handler, tag,   \
                                                 name, const)

#define __alterhook_generate_original_wrapper_method_implementation2(          \
    cls, modifier_handler, callback, ...)                                      \
  utils_defer(__alterhook_generate_original_wrapper_method_implenentation3)(   \
      cls, modifier_handler, __VA_ARGS__)

#define __alterhook_generate_original_wrapper_method_implementation(data,      \
                                                                    extra)     \
  __alterhook_call(                                                            \
      __alterhook_generate_original_wrapper_method_implementation2,            \
      (utils_expand extra, utils_expand data))

#define __alterhook_generate_call(callback, modifier_name, dummy_callback,     \
                                  tag, name, ...)                              \
  utils_defer(callback)(modifier_name, tag, name)

#ifndef __INTELLISENSE__
  #define __alterhook_generate_original_wrapper_method_implementations(        \
      modifier_target, modifier_handler, info)                                 \
    __alterhook_call2(                                                         \
        utils_map_ud,                                                          \
        (__alterhook_generate_original_wrapper_method_implementation,          \
         (modifier_target, modifier_handler), utils_expand info))
  #define __alterhook_generate_cached_target_address_getters(info)             \
    __alterhook_call2(utils_map,                                               \
                      (__alterhook_generate_cached_target_address_getter,      \
                       utils_expand info))
#else
  #define __alterhook_generate_original_wrapper_method_implementations(        \
      modifier_target, modifier_handler, info)
  #define __alterhook_generate_cached_target_address_getters(info)
#endif

// Bring modifier wrapper methods to the scope
#define __alterhook_generate_base_typedef_and_using_wrapped_original_method_declaration3( \
    tag, name)                                                                            \
  typedef __modifier_helpers::original_wrapper_##tag<                                     \
      ::alterhook::utils::clean_function_type_t<decltype(get(                             \
          __modifier_helpers::tag{}))>,                                                   \
      derived>                                                                            \
      base_wrapper_##tag;                                                                 \
  using base_wrapper_##tag::name;

#define __alterhook_generate_base_typedef_and_using_wrapped_original_method_declaration2( \
    callback, tag, name, ...)                                                             \
  __alterhook_generate_base_typedef_and_using_wrapped_original_method_declaration3(       \
      tag, name)

#define __alterhook_generate_base_typedef_and_using_wrapped_original_method_declaration( \
    data)                                                                                \
  __alterhook_generate_base_typedef_and_using_wrapped_original_method_declaration2       \
      data

#define __alterhook_generate_base_typedefs_and_using_wrapped_original_method_declarations( \
    info)                                                                                  \
  __alterhook_call2(                                                                       \
      utils_map,                                                                           \
      (__alterhook_generate_base_typedef_and_using_wrapped_original_method_declaration,    \
       utils_expand info))

// hook insertion
#define __alterhook_generate_hook_insertion2(modifier_name, tag, name)         \
  instance.insert(                                                             \
      cached_get(__modifier_helpers::tag{}), #modifier_name "::" #name,        \
      static_cast<decltype(get(__modifier_helpers::tag{}))>(&derived::name),   \
      base_wrapper_##tag::original_##tag);

#define __alterhook_generate_hook_insertion(data, modifier_name)               \
  __alterhook_call(__alterhook_generate_call,                                  \
                   (__alterhook_generate_hook_insertion2, modifier_name,       \
                    utils_expand data))

#define __alterhook_generate_hook_insertions(modifier_name, info)              \
  __alterhook_call2(utils_map_ud, (__alterhook_generate_hook_insertion,        \
                                   modifier_name, utils_expand info))

// hook erasing
#define __alterhook_generate_hook_erasement2(modifier_name, tag, name)         \
  instance.erase(cached_get(__modifier_helpers::tag{}),                        \
                 #modifier_name "::" #name);

#define __alterhook_generate_hook_erasement(data, modifier_name)               \
  __alterhook_call(__alterhook_generate_call,                                  \
                   (__alterhook_generate_hook_erasement2, modifier_name,       \
                    utils_expand data))

#define __alterhook_generate_hook_erasements(modifier_name, info)              \
  __alterhook_call2(utils_map_ud, (__alterhook_generate_hook_erasement,        \
                                   modifier_name, utils_expand info))

// hook enabling
#define __alterhook_generate_hook_enabling2(modifier_name, tag, name)          \
  instance.enable(cached_get(__modifier_helpers::tag{}),                       \
                  #modifier_name "::" #name);

#define __alterhook_generate_hook_enabling(data, modifier_name)                \
  __alterhook_call(                                                            \
      __alterhook_generate_call,                                               \
      (__alterhook_generate_hook_enabling2, modifier_name, utils_expand data))

#define __alterhook_generate_hook_enablings(modifier_name, info)               \
  __alterhook_call2(utils_map_ud, (__alterhook_generate_hook_enabling,         \
                                   modifier_name, utils_expand info))

// hook disabling
#define __alterhook_generate_hook_disabling2(modifier_name, tag, name)         \
  instance.disable(cached_get(__modifier_helpers::tag{}),                      \
                   #modifier_name "::" #name);

#define __alterhook_generate_hook_disabling(data, modifier_name)               \
  __alterhook_call(__alterhook_generate_call,                                  \
                   (__alterhook_generate_hook_disabling2, modifier_name,       \
                    utils_expand data))

#define __alterhook_generate_hook_disablings(modifier_name, info)              \
  __alterhook_call2(utils_map_ud, (__alterhook_generate_hook_disabling,        \
                                   modifier_name, utils_expand info))

// assertion
#define __alterhook_generate_unique_detour_exists_assertion(modifier_name,     \
                                                            tag, name)         \
  if constexpr (::alterhook::utils::compare_or_false<                          \
                    &derived::name, &base_wrapper_##tag::name>)                \
  {                                                                            \
    static_assert(::alterhook::utils::always_false<T>,                         \
                  "the method \"" #modifier_name "::" #name                    \
                  "\" is not defined in the modifier class on "                \
                  "line " utils_stringify(__LINE__));                          \
    return false;                                                              \
  }

#define __alterhook_generate_overloaded_detour_exists_assertion(               \
    modifier_name, tag, name, type)                                            \
  if constexpr (!__modifier_helpers::castable_##tag<derived>)                  \
  {                                                                            \
    static_assert(                                                             \
        ::alterhook::utils::always_false<T>,                                   \
        "the method \"" #modifier_name "::" #name                              \
        "\" with explicitly specified type \"" #type                           \
        "\" is defined but has different signature than the specified one, "   \
        "modifier line is " utils_stringify(__LINE__));                        \
    return false;                                                              \
  }                                                                            \
  else if constexpr (static_cast<                                              \
                         ::alterhook::utils::add_cls_t<type, derived>>(        \
                         &derived::name) == &base_wrapper_##tag::name)         \
  {                                                                            \
    static_assert(                                                             \
        ::alterhook::utils::always_false<T>,                                   \
        "the method \"" #modifier_name "::" #name                              \
        "\" with explicitly specified type \"" #type                           \
        "\" is not defined in the modifier class on line " utils_stringify(    \
            __LINE__));                                                        \
    return false;                                                              \
  }

#define __alterhook_generate_unique_detour_return_type_assertion(              \
    modifier_name, tag, name)                                                  \
  if constexpr (!std::is_same_v<                                               \
                    ::alterhook::utils::fn_return_t<decltype(&derived::name)>, \
                    ::alterhook::utils::fn_return_t<                           \
                        decltype(&base_wrapper_##tag::name)>>)                 \
  {                                                                            \
    static_assert(                                                             \
        ::alterhook::utils::always_false<T>,                                   \
        "the return type of \"" #modifier_name "::" #name                      \
        "\" does not match the one from the target method, modifier "          \
        "is on line " utils_stringify(__LINE__));                              \
    return false;                                                              \
  }

#define __alterhook_generate_unique_detour_calling_convention_assertion(       \
    modifier_name, tag, name)                                                  \
  if constexpr (!::alterhook::utils::compatible_calling_convention_with<       \
                    decltype(&derived::name),                                  \
                    decltype(&base_wrapper_##tag::name)>)                      \
  {                                                                            \
    static_assert(                                                             \
        ::alterhook::utils::always_false<T>,                                   \
        "the calling convention of " #modifier_name "::" #name                 \
        " is not compatible with the one of the target method, modifier is "   \
        "on line " utils_stringify(__LINE__));                                 \
    return false;                                                              \
  }

#define __alterhook_generate_unique_detour_arguments_assertion(modifier_name,  \
                                                               tag, name)      \
  if constexpr (!::alterhook::utils::compatible_function_arguments_with<       \
                    decltype(&derived::name),                                  \
                    decltype(&base_wrapper_##tag::name)>)                      \
  {                                                                            \
    static_assert(::alterhook::utils::always_false<T>,                         \
                  "the arguments of " #modifier_name "::" #name                \
                  " are not compatible with the ones of the target method, "   \
                  "modifier is on line " utils_stringify(__LINE__));           \
    return false;                                                              \
  }

// nothing to assert for overloaded methods, the first assertion should always
// fail if the function signature is not identical
#define __alterhook_generate_overloaded_detour_return_type_assertion(          \
    modifier_name, tag, name, type)
#define __alterhook_generate_overloaded_detour_calling_convention_assertion(   \
    modifier_name, tag, name, type)
#define __alterhook_generate_overloaded_arguments_assertion(modifier_name,     \
                                                            tag, name, type)

#define __alterhook_generate_detour_exists_assertion2(modifier_name, callback, \
                                                      ...)                     \
  __alterhook_unique_or_overloaded_macro_selector(                             \
      __alterhook_generate_unique_detour_exists_assertion,                     \
      __alterhook_generate_overloaded_detour_exists_assertion, modifier_name,  \
      callback, __VA_ARGS__)

#define __alterhook_generate_detour_exists_assertion(data, modifier_name)      \
  __alterhook_call(__alterhook_generate_detour_exists_assertion2,              \
                   (modifier_name, utils_expand data))

#define __alterhook_generate_detour_exists_assertions(modifier_name, info)     \
  __alterhook_call2(utils_map_ud,                                              \
                    (__alterhook_generate_detour_exists_assertion,             \
                     modifier_name, utils_expand info))

#define __alterhook_generate_detour_return_type_assertion2(modifier_name,      \
                                                           callback, ...)      \
  __alterhook_unique_or_overloaded_macro_selector(                             \
      __alterhook_generate_unique_detour_return_type_assertion,                \
      __alterhook_generate_overloaded_detour_return_type_assertion,            \
      modifier_name, callback, __VA_ARGS__)

#define __alterhook_generate_detour_return_type_assertion(data, modifier_name) \
  __alterhook_call(__alterhook_generate_detour_return_type_assertion2,         \
                   (modifier_name, utils_expand data))

#define __alterhook_generate_detour_return_type_assertions(modifier_name,      \
                                                           info)               \
  __alterhook_call2(utils_map_ud,                                              \
                    (__alterhook_generate_detour_return_type_assertion,        \
                     modifier_name, utils_expand info))

#define __alterhook_generate_detour_calling_convention_assertion2(             \
    modifier_name, callback, ...)                                              \
  __alterhook_unique_or_overloaded_macro_selector(                             \
      __alterhook_generate_unique_detour_calling_convention_assertion,         \
      __alterhook_generate_overloaded_detour_calling_convention_assertion,     \
      modifier_name, callback, __VA_ARGS__)

#define __alterhook_generate_detour_calling_convention_assertion(              \
    data, modifier_name)                                                       \
  __alterhook_call(__alterhook_generate_detour_calling_convention_assertion2,  \
                   (modifier_name, utils_expand data))

#define __alterhook_generate_detour_arguments_assertion2(modifier_name,        \
                                                         callback, ...)        \
  __alterhook_unique_or_overloaded_macro_selector(                             \
      __alterhook_generate_unique_detour_arguments_assertion,                  \
      __alterhook_generate_overloaded_arguments_assertion, modifier_name,      \
      callback, __VA_ARGS__)

#define __alterhook_generate_detour_arguments_assertion(data, modifier_name)   \
  __alterhook_call(__alterhook_generate_detour_arguments_assertion2,           \
                   (modifier_name, utils_expand data))

#define __alterhook_generate_detour_arguments_assertions(modifier_name, info)  \
  __alterhook_call2(utils_map_ud,                                              \
                    (__alterhook_generate_detour_arguments_assertion,          \
                     modifier_name, utils_expand info))

// selectors
#define __alterhook_unique_or_overloaded_macro_selector__alterhook_define_unique_method_getter( \
    unique_macro, overloaded_macro, ...)                                                        \
  utils_defer(unique_macro)(__VA_ARGS__)

#define __alterhook_unique_or_overloaded_macro_selector__alterhook_define_overloaded_method_getter( \
    unique_macro, overloaded_macro, ...)                                                            \
  utils_defer(overloaded_macro)(__VA_ARGS__)

#define __alterhook_unique_or_overloaded_macro_selector(                       \
    unique_macro, overloaded_macro, modifier_name, info_callback, ...)         \
  utils_defer(utils_concat(__alterhook_unique_or_overloaded_macro_selector,    \
                           info_callback))(unique_macro, overloaded_macro,     \
                                           modifier_name, __VA_ARGS__)

// macro data generation
#define __alterhook_generate_tag_unique_method(name)                           \
  (__alterhook_define_unique_method_getter,                                    \
   utils_concat(modifier_tag_, __COUNTER__), name)

#define __alterhook_generate_tag_overloaded_method(pair)                       \
  (__alterhook_define_overloaded_method_getter,                                \
   utils_concat(modifier_tag_, __COUNTER__), utils_expand pair)

#define __alterhook_generate_tag(name)                                         \
  utils_if(utils_is_call_operator(name))(                                      \
      __alterhook_generate_tag_overloaded_method,                              \
      __alterhook_generate_tag_unique_method)(name)

/*
 * Setup Tools
 */
#define __alterhook_setup_method_getter2(callback, ...)                        \
  utils_defer(callback)(__VA_ARGS__)

#define __alterhook_setup_method_getter(data, cls)                             \
  __alterhook_call(__alterhook_setup_method_getter2, (utils_expand data, cls))

#define __alterhook_setup_method_getters(modifier_target, info)                \
  __alterhook_call2(utils_map_ud, (__alterhook_setup_method_getter,            \
                                   modifier_target, utils_expand info))

#define __alterhook_setup_original_wrapper2(cls, callback, ...)                \
  utils_defer(__alterhook_define_original_wrapper_class)(cls, __VA_ARGS__)

#define __alterhook_setup_original_wrapper(data, cls)                          \
  __alterhook_call(__alterhook_setup_original_wrapper2,                        \
                   (cls, utils_expand data))

#define __alterhook_setup_original_wrappers(modifier_target, info)             \
  __alterhook_call2(utils_map_ud, (__alterhook_setup_original_wrapper,         \
                                   modifier_target, utils_expand info))

#define __alterhook_setup_castable_concept2(callback, ...)                     \
  __alterhook_unique_or_overloaded_macro_selector(                             \
      __alterhook_define_unique_castable_concept,                              \
      __alterhook_define_overloaded_castable_concept, , callback, __VA_ARGS__)

#define __alterhook_setup_castable_concept(data)                               \
  __alterhook_setup_castable_concept2 data

/*
 * MODIFIER METHODS
 */
#ifndef __INTELLISENSE__
  #define __alterhook_setup_castable_concepts(info)                            \
    namespace                                                                  \
    {                                                                          \
      namespace __modifier_helpers                                             \
      {                                                                        \
        __alterhook_call2(utils_map, (__alterhook_setup_castable_concept,      \
                                      utils_expand info))                      \
      }                                                                        \
    }
  #if utils_cc_assertions
    #define __alterhook_generate_detour_calling_convention_assertions(         \
        modifier_name, info)                                                   \
      __alterhook_call2(                                                       \
          utils_map_ud,                                                        \
          (__alterhook_generate_detour_calling_convention_assertion,           \
           modifier_name, utils_expand info))
  #else
    #define __alterhook_generate_detour_calling_convention_assertions(         \
        modifier_name, info)
  #endif

  #define __alterhook_define_modifier_static_asserter(info, modifier_name)     \
    template <typename T = void>                                               \
    static utils_consteval bool modifier_static_assert()                       \
    {                                                                          \
      static_assert(                                                           \
          sizeof(derived) == sizeof(original),                                 \
          "The modifier with name \"" #modifier_name                           \
          "\" defined on line " utils_stringify(                               \
              __LINE__) " defines its own fields which is not allowed");       \
      __alterhook_generate_detour_exists_assertions(modifier_name, info);      \
      __alterhook_generate_detour_return_type_assertions(modifier_name, info); \
      __alterhook_generate_detour_calling_convention_assertions(modifier_name, \
                                                                info);         \
      __alterhook_generate_detour_arguments_assertions(modifier_name, info);   \
      return true;                                                             \
    }

  // modifier methods definition
  #define __alterhook_define_modifier_activate(info, modifier_name)            \
    static void activate_modifier()                                            \
    {                                                                          \
      if constexpr (modifier_static_assert())                                  \
      {                                                                        \
        if (modifier_activated)                                                \
          return;                                                              \
        auto& instance = ::alterhook::hook_manager::get();                     \
        __alterhook_generate_hook_insertions(modifier_name, info);             \
        modifier_activated = true;                                             \
        modifier_enabled   = true;                                             \
      }                                                                        \
    }
  #define __alterhook_define_modifier_deactivate(info, modifier_name)          \
    static void deactivate_modifier()                                          \
    {                                                                          \
      if constexpr (modifier_static_assert())                                  \
      {                                                                        \
        if (!modifier_activated)                                               \
          return;                                                              \
        auto& instance = ::alterhook::hook_manager::get();                     \
        __alterhook_generate_hook_erasements(modifier_name, info);             \
        modifier_activated = false;                                            \
        modifier_enabled   = false;                                            \
      }                                                                        \
    }
  #define __alterhook_define_modifier_enable(info, modifier_name)              \
    static void enable_modifier()                                              \
    {                                                                          \
      if (!modifier_activated)                                                 \
        return activate_modifier();                                            \
      if (modifier_enabled)                                                    \
        return;                                                                \
      auto& instance = ::alterhook::hook_manager::get();                       \
      __alterhook_generate_hook_enablings(modifier_name, info);                \
      modifier_enabled = true;                                                 \
    }
  #define __alterhook_define_modifier_disable(info, modifier_name)             \
    static void disable_modifier()                                             \
    {                                                                          \
      if (!modifier_activated || !modifier_enabled)                            \
        return;                                                                \
      auto& instance = ::alterhook::hook_manager::get();                       \
      __alterhook_generate_hook_disablings(modifier_name, info);               \
      modifier_enabled = false;                                                \
    }
#else
  #define __alterhook_setup_castable_concepts(info)
  #define __alterhook_define_modifier_static_asserter(info, modifier_name)
  #define __alterhook_define_modifier_activate(info, modifier_name)            \
    static void activate_modifier();
  #define __alterhook_define_modifier_deactivate(info, modifier_name)          \
    static void deactivate_modifier();
  #define __alterhook_define_modifier_enable(info, modifier_name)              \
    static void enable_modifier();
  #define __alterhook_define_modifier_disable(info, modifier_name)             \
    static void disable_modifier();
#endif

  /*
   * MODIFIER BASE CLASS
   */
//  DEFINE MODIFIER HANDLER CLASS
#define __alterhook_define_modifier(info, modifier_name, modifier_handler,               \
                                    modifier_target)                                     \
  namespace                                                                              \
  {                                                                                      \
    template <typename derived>                                                          \
    class modifier_handler                                                               \
        : public modifier_target,                                                        \
          __alterhook_generate_original_wrapper_inheritance_list(info)                   \
    {                                                                                    \
    private:                                                                             \
      inline static bool modifier_enabled   = false;                                     \
      inline static bool modifier_activated = false;                                     \
      __alterhook_generate_cached_target_address_getters(info);                          \
      __alterhook_define_modifier_static_asserter(info, modifier_name);                  \
                                                                                         \
    public:                                                                              \
      typedef modifier_handler original;                                                 \
      __alterhook_generate_base_typedefs_and_using_wrapped_original_method_declarations( \
          info);                                                                         \
      __alterhook_define_modifier_activate(info, modifier_name);                         \
      __alterhook_define_modifier_deactivate(info, modifier_name);                       \
      __alterhook_define_modifier_enable(info, modifier_name);                           \
      __alterhook_define_modifier_disable(info, modifier_name);                          \
    };                                                                                   \
  }

/*
 * MODIFIER IMPLEMENTATION
 */
#define __modifier(info, modifier_name, modifier_handler, modifier_target)     \
  __alterhook_setup_method_getters(modifier_target, info)                      \
      __alterhook_setup_original_wrappers(                                     \
          modifier_target, info) __alterhook_setup_castable_concepts(info)     \
          __alterhook_define_modifier(info, modifier_name, modifier_handler,   \
                                      modifier_target)                         \
              __alterhook_generate_original_wrapper_method_implementations(    \
                  modifier_target, modifier_handler, info) class modifier_name \
      : public modifier_handler<modifier_name>

#define modifier(modifier_name, modifier_target, ...)                          \
  utils_concat(                                                                \
      utils_concat(utils_concat(__very_hidden_dummy_, __COUNTER__), _),        \
      __LINE__);                                                               \
  __modifier((utils_map_list(__alterhook_generate_tag, __VA_ARGS__)),          \
             modifier_name, utils_concat(modifier_, __COUNTER__),              \
             modifier_target)
} // namespace alterhook

#if utils_clang
  #pragma clang diagnostic pop
#endif
