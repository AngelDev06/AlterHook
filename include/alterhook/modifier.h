/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "hook_map.h"

namespace alterhook
{
  class managed_concurrent_hook_map : concurrent_hook_map<std::string>
  {
  public:
    typedef concurrent_hook_map<std::string> base;
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
    using base::disable_all;
    using base::enable_all;
    using base::get_allocator;
    using base::hash_function;
    using base::key_eq;
    using base::max_size;

    managed_concurrent_hook_map() = default;

    template <typename K>
    void erase(const K& key);
    void clear();

  private:
    template <typename K>
    bool erase_unchecked(const K& key);

    friend class hook_manager;

    managed_concurrent_hook_map(const managed_concurrent_hook_map&) = delete;
    managed_concurrent_hook_map&
        operator=(const managed_concurrent_hook_map&) = delete;
  };

  class hook_manager
      : std::unordered_map<std::byte*, managed_concurrent_hook_map>
  {
  public:
    typedef std::unordered_map<std::byte*, managed_concurrent_hook_map> base;

    ALTERHOOK_API static hook_manager& get();
    managed_concurrent_hook_map&       operator[](std::byte* target);
    template <typename K, typename dtr, typename orig, typename... types>
    void insert(std::byte* target, K&& key, dtr&& detour, orig& original,
                types&&... rest);
    template <typename K>
    void erase(std::byte* target, const K& key);
    void erase(std::byte* target);
    template <typename K>
    void enable(std::byte* target, const K& key);
    template <typename K>
    void disable(std::byte* target, const K& key);

  private:
    friend class managed_concurrent_hook_map;
    mutable std::shared_mutex manager_lock;

    hook_manager() {}

    hook_manager(const hook_manager&)            = delete;
    hook_manager& operator=(const hook_manager&) = delete;
  };

  template <typename K>
  void managed_concurrent_hook_map::erase(const K& key)
  {
    if (erase_unchecked(key))
      hook_manager::get().erase(get_target());
  }

  template <typename K>
  bool managed_concurrent_hook_map::erase_unchecked(const K& key)
  {
    base::erase(key);
    return base::empty();
  }

  inline void managed_concurrent_hook_map::clear()
  {
    base::clear();
    hook_manager::get().erase(get_target());
  }

  inline managed_concurrent_hook_map& hook_manager::operator[](std::byte* key)
  {
    std::shared_lock lock{ manager_lock };
    return at(key);
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
    std::unique_lock lock{ manager_lock };
    auto             itr = base::find(target);
    utils_assert(itr != base::end(),
                 "Attempted to erase a non-existing entry on hook_manager");
    if (itr->second.erase_unchecked(key))
      base::erase(itr);
  }

  template <typename K>
  void hook_manager::enable(std::byte* target, const K& key)
  {
    std::shared_lock lock{ manager_lock };
    auto             itr = base::find(target);
    utils_assert(itr != base::end(),
                 "Attempted to enable a non-existing entry on hook_manager");
    itr->second.visit(key, [](auto pair) { pair.second.enable(); });
  }

  template <typename K>
  void hook_manager::disable(std::byte* target, const K& key)
  {
    std::shared_lock lock{ manager_lock };
    auto             itr = base::find(target);
    utils_assert(itr != base::end(),
                 "Attempted to disable a non-existing entry on hook_manager");
    itr->second.visit(key, [](auto pair) { pair.second.disable(); });
  }

  inline void hook_manager::erase(std::byte* target)
  {
    std::unique_lock lock{ manager_lock };
    base::erase(target);
  }

#define __alterhook_call(x, y)  x y
#define __alterhook_call2(x, y) x y
#define __alterhook_expand(...) __VA_ARGS__

/*
 * original wrappers generator
 */
#ifndef __INTELLISENSE__
  #define __alterhook_def_original_var(tag, cv)                                \
    template <typename R, typename origcls, typename... args,                  \
              typename derived>                                                \
    decltype(get(tag{})) original_wrapper_##tag<R(cv origcls*, args...),       \
                                                derived>::original_##tag{};
#else
  #define __alterhook_def_original_var(tag, cv)
#endif

#define __alterhook_original_wrapper_template(cls, tag, name, cv)              \
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
      __alterhook_def_original_var(tag, cv)                                    \
    }                                                                          \
  }

#define __alterhook_original_wrapper_setup(cls, tag, name, ...)                \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      template <typename T, typename T2>                                       \
      class original_wrapper_##tag;                                            \
    }                                                                          \
  }                                                                            \
  __alterhook_original_wrapper_template(cls, tag, name, )                      \
      __alterhook_original_wrapper_template(cls, tag, name, const)

/*
 * original wrappers inheritance generator
 */
#define __alterhook_inherit_from_original_wrapper_impl(tag, ...)               \
public                                                                         \
  __modifier_helpers::original_wrapper_##tag<                                  \
      ::alterhook::utils::clean_function_type_t<decltype(get(                  \
          __modifier_helpers::tag{}))>,                                        \
      derived>

#define __alterhook_inherit_from_original_wrapper_impl2(callback, tag, ...)    \
  __alterhook_inherit_from_original_wrapper_impl(tag, __VA_ARGS__)

#define __alterhook_inherit_from_original_wrapper(data)                        \
  __alterhook_inherit_from_original_wrapper_impl2 data

/*
 * original function wrapper implementation
 */
#define __alterhook_original_wrapper_implementation_template(cls, base_name,   \
                                                             tag, name, cv)    \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      template <typename R, typename origcls, typename... args,                \
                typename derived>                                              \
      R original_wrapper_##tag<R(cv origcls*, args...), derived>::name(        \
          args... values) cv                                                   \
      {                                                                        \
        return (static_cast<cv base_name<derived>&>(*this).*                   \
                original_##tag)(std::forward<args>(values)...);                \
      }                                                                        \
    }                                                                          \
  }

#define __alterhook_implement_original_wrappers(cls, base_name, tag, name,     \
                                                ...)                           \
  __alterhook_original_wrapper_implementation_template(cls, base_name, tag,    \
                                                       name, )                 \
      __alterhook_original_wrapper_implementation_template(cls, base_name,     \
                                                           tag, name, const)

/*
 * METHOD GETTER GENERATORS
 */
#define __alterhook_unique_method_getter_setup(tag, name, cls)                 \
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

#define __alterhook_overloaded_method_getter_setup(tag, name, type, cls)       \
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

/*
 * bring inherited original wrapper methods to the scope
 */
#define __alterhook_make_original_wrapper_methods_available_impl(tag, name)    \
  typedef __modifier_helpers::original_wrapper_##tag<                          \
      ::alterhook::utils::clean_function_type_t<decltype(get(                  \
          __modifier_helpers::tag{}))>,                                        \
      derived>                                                                 \
      base_wrapper_##tag;                                                      \
  using base_wrapper_##tag::name;

#define __alterhook_make_original_wrapper_methods_available_impl2(             \
    callback, tag, name, ...)                                                  \
  __alterhook_make_original_wrapper_methods_available_impl(tag, name)

#define __alterhook_make_original_wrapper_methods_available(data)              \
  __alterhook_make_original_wrapper_methods_available_impl2 data

/*
 * generate calls
 */
#define __alterhook_make_insertion(modifier_name, tag, name)                   \
  instance.insert(                                                             \
      cached_get(__modifier_helpers::tag{}), #modifier_name "::" #name,        \
      static_cast<decltype(get(__modifier_helpers::tag{}))>(&derived::name),   \
      base_wrapper_##tag::original_##tag);

#define __alterhook_make_erase(modifier_name, tag, name)                       \
  instance.erase(cached_get(__modifier_helpers::tag{}),                        \
                 #modifier_name "::" #name);

#define __alterhook_make_enable(modifier_name, tag, name)                      \
  instance.enable(cached_get(__modifier_helpers::tag{}),                       \
                  #modifier_name "::" #name);

#define __alterhook_make_disable(modifier_name, tag, name)                     \
  instance.disable(cached_get(__modifier_helpers::tag{}),                      \
                   #modifier_name "::" #name);

/*
 * generate cached address for targets
 */
#define __alterhook_generate_cached_method(tag)                                \
  static std::byte* cached_get(__modifier_helpers::tag)                        \
  {                                                                            \
    static std::byte* cache =                                                  \
        ::alterhook::get_target_address(get(__modifier_helpers::tag{}));       \
    return cache;                                                              \
  }

/*
 * asserter generators
 */
#define __alterhook_unique_castable_asserter(tag, name)
#if utils_cpp20
  #define __alterhook_overloaded_castable_asserter(tag, name, type)            \
    template <typename T>                                                      \
    concept castable_##tag = requires {                                        \
      static_cast<::alterhook::utils::add_cls_t<type, T>>(&T::name);           \
    };
#else
  #define __alterhook_overloaded_castable_asserter(tag, name, type)            \
    template <typename T, typename = void>                                     \
    inline constexpr bool castable_##tag = false;                              \
    template <typename T>                                                      \
    inline constexpr bool castable_##tag<                                      \
        T, std::void_t<decltype(static_cast<::alterhook::utils::add_cls_t<     \
                                    type, T>>(&T::name))>> = true;
#endif

#define __alterhook_unique_ptr_t_asserter(modifier_name, tag, name)            \
  if constexpr (::alterhook::utils::compare_or_false<                          \
                    &derived::name, &base_wrapper_##tag::name>)                \
  {                                                                            \
    static_assert(::alterhook::utils::always_false<T>,                         \
                  "the method \"" #modifier_name "::" #name                    \
                  "\" is not defined in the modifier class on "                \
                  "line " utils_stringify(__LINE__));                          \
    return false;                                                              \
  }

#define __alterhook_overloaded_ptr_t_asserter(modifier_name, tag, name, type)  \
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

#define __alterhook_unique_return_t_asserter(modifier_name, tag, name)         \
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

#define __alterhook_unique_cc_asserter(modifier_name, tag, name)               \
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

#define __alterhook_unique_args_asserter(modifier_name, tag, name)             \
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
#define __alterhook_overloaded_return_t_asserter(modifier_name, tag, name, type)
#define __alterhook_overloaded_cc_asserter(modifier_name, tag, name, type)
#define __alterhook_overloaded_args_asserter(modifier_name, tag, name, type)

#define __alterhook_select_asserter__alterhook_unique_method_getter_setup(     \
    unique_asserter, overloaded_asserter, ...)                                 \
  __utils_defer(unique_asserter)(__VA_ARGS__)

#define __alterhook_select_asserter__alterhook_overloaded_method_getter_setup( \
    unique_asserter, overloaded_asserter, ...)                                 \
  __utils_defer(overloaded_asserter)(__VA_ARGS__)

/*
 * TAG generation along with additional info such as which type of method getter
 * to generate
 */
#define __alterhook_gen_tag_unique_method(name)                                \
  (__alterhook_unique_method_getter_setup,                                     \
   utils_concat(modifier_tag_, __COUNTER__), name)

#define __alterhook_gen_tag_overloaded_method(pair)                            \
  (__alterhook_overloaded_method_getter_setup,                                 \
   utils_concat(modifier_tag_, __COUNTER__), __alterhook_expand pair)

#define __alterhook_gen_tag(name)                                              \
  __alterhook_call(                                                            \
      utils_is_call_operator(name, __alterhook_gen_tag_overloaded_method,      \
                             __alterhook_gen_tag_unique_method),               \
      (name))

/*
 * Forward info to callbacks responsible for setting up stuff
 */
#define __alterhook_setup_method_getter_impl(callback, ...)                    \
  __utils_defer(callback)(__VA_ARGS__)

#define __alterhook_setup_method_getter(data, cls)                             \
  __alterhook_call(__alterhook_setup_method_getter_impl,                       \
                   (__alterhook_expand data, cls))

#define __alterhook_setup_original_wrapper_impl(cls, callback, ...)            \
  __utils_defer(__alterhook_original_wrapper_setup)(cls, __VA_ARGS__)

#define __alterhook_setup_original_wrapper(data, cls)                          \
  __alterhook_call(__alterhook_setup_original_wrapper_impl,                    \
                   (cls, __alterhook_expand data))

#define __alterhook_setup_original_wrapper_implementation_impl(cls, base_name, \
                                                               callback, ...)  \
  __utils_defer(__alterhook_implement_original_wrappers)(cls, base_name,       \
                                                         __VA_ARGS__)

#define __alterhook_setup_original_wrapper_implementation(data, extra)         \
  __alterhook_call(__alterhook_setup_original_wrapper_implementation_impl,     \
                   (__alterhook_expand extra, __alterhook_expand data))

#define __alterhook_generate_call(callback, modifier_name, dummy_callback,     \
                                  tag, name, ...)                              \
  __utils_defer(callback)(modifier_name, tag, name)

#define __alterhook_generate_insertion(data, modifier_name)                    \
  __alterhook_call(                                                            \
      __alterhook_generate_call,                                               \
      (__alterhook_make_insertion, modifier_name, __alterhook_expand data))

#define __alterhook_generate_erase(data, modifier_name)                        \
  __alterhook_call(                                                            \
      __alterhook_generate_call,                                               \
      (__alterhook_make_erase, modifier_name, __alterhook_expand data))

#define __alterhook_generate_enable(data, modifier_name)                       \
  __alterhook_call(                                                            \
      __alterhook_generate_call,                                               \
      (__alterhook_make_enable, modifier_name, __alterhook_expand data))

#define __alterhook_generate_disable(data, modifier_name)                      \
  __alterhook_call(                                                            \
      __alterhook_generate_call,                                               \
      (__alterhook_make_disable, modifier_name, __alterhook_expand data))

#define __alterhook_generate_cached_target_address_method_impl(callback, tag,  \
                                                               ...)            \
  __utils_defer(__alterhook_generate_cached_method)(tag)

#define __alterhook_generate_cached_target_address_method(data)                \
  __alterhook_generate_cached_target_address_method_impl data

#define __alterhook_generate_castable_asserter_impl(callback, ...)             \
  __utils_defer(utils_concat(__alterhook_select_asserter, callback))(          \
      __alterhook_unique_castable_asserter,                                    \
      __alterhook_overloaded_castable_asserter, __VA_ARGS__)

#define __alterhook_generate_castable_asserter(data)                           \
  __alterhook_generate_castable_asserter_impl data

#define __alterhook_generate_diff_static_asserter_impl(modifier_name,          \
                                                       callback, ...)          \
  __utils_defer(utils_concat(__alterhook_select_asserter, callback))(          \
      __alterhook_unique_ptr_t_asserter,                                       \
      __alterhook_overloaded_ptr_t_asserter, modifier_name, __VA_ARGS__)

#define __alterhook_generate_diff_static_asserter(data, modifier_name)         \
  __alterhook_call(__alterhook_generate_diff_static_asserter_impl,             \
                   (modifier_name, __alterhook_expand data))

#define __alterhook_generate_return_static_asserter_impl(modifier_name,        \
                                                         callback, ...)        \
  __utils_defer(utils_concat(__alterhook_select_asserter, callback))(          \
      __alterhook_unique_return_t_asserter,                                    \
      __alterhook_overloaded_return_t_asserter, modifier_name, __VA_ARGS__)

#define __alterhook_generate_return_static_asserter(data, modifier_name)       \
  __alterhook_call(__alterhook_generate_return_static_asserter_impl,           \
                   (modifier_name, __alterhook_expand data))

#define __alterhook_generate_cc_static_asserter_impl(modifier_name, callback,  \
                                                     ...)                      \
  __utils_defer(utils_concat(__alterhook_select_asserter, callback))(          \
      __alterhook_unique_cc_asserter, __alterhook_overloaded_cc_asserter,      \
      modifier_name, __VA_ARGS__)

#define __alterhook_generate_cc_static_asserter(data, modifier_name)           \
  __alterhook_call(__alterhook_generate_cc_static_asserter_impl,               \
                   (modifier_name, __alterhook_expand data))

#define __alterhook_generate_args_static_asserter_impl(modifier_name,          \
                                                       callback, ...)          \
  __utils_defer(utils_concat(__alterhook_select_asserter, callback))(          \
      __alterhook_unique_args_asserter, __alterhook_overloaded_args_asserter,  \
      modifier_name, __VA_ARGS__)

#define __alterhook_generate_args_static_asserter(data, modifier_name)         \
  __alterhook_call(__alterhook_generate_args_static_asserter_impl,             \
                   (modifier_name, __alterhook_expand data))

/*
 * MODIFIER METHODS
 */
#ifndef __INTELLISENSE__
  #define __alterhook_define_castable_concepts(info)                           \
    namespace                                                                  \
    {                                                                          \
      namespace __modifier_helpers                                             \
      {                                                                        \
        __alterhook_call2(utils_map, (__alterhook_generate_castable_asserter,  \
                                      __alterhook_expand info))                \
      }                                                                        \
    }
  #if utils_cc_assertions
    #define __alterhook_add_cc_assertions(info, modifier_name)                 \
      __alterhook_call2(utils_map_ud,                                          \
                        (__alterhook_generate_cc_static_asserter,              \
                         modifier_name, __alterhook_expand info))
  #else
    #define __alterhook_add_cc_assertions(info, modifier_name)
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
      __alterhook_call2(utils_map_ud,                                          \
                        (__alterhook_generate_diff_static_asserter,            \
                         modifier_name, __alterhook_expand info))              \
          __alterhook_call2(utils_map_ud,                                      \
                            (__alterhook_generate_return_static_asserter,      \
                             modifier_name, __alterhook_expand info))          \
              __alterhook_add_cc_assertions(info, modifier_name)               \
                  __alterhook_call2(                                           \
                      utils_map_ud,                                            \
                      (__alterhook_generate_args_static_asserter,              \
                       modifier_name, __alterhook_expand info)) return true;   \
    }

  #define __alterhook_define_modifier_activate(info, modifier_name)            \
    static void activate_modifier()                                            \
    {                                                                          \
      if constexpr (modifier_static_assert())                                  \
      {                                                                        \
        if (modifier_activated)                                                \
          return;                                                              \
        auto& instance = ::alterhook::hook_manager::get();                     \
        __alterhook_call2(utils_map_ud,                                        \
                          (__alterhook_generate_insertion, modifier_name,      \
                           __alterhook_expand info)) modifier_activated =      \
            true;                                                              \
        modifier_enabled = true;                                               \
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
        __alterhook_call2(utils_map_ud,                                        \
                          (__alterhook_generate_erase, modifier_name,          \
                           __alterhook_expand info)) modifier_activated =      \
            false;                                                             \
        modifier_enabled = false;                                              \
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
      __alterhook_call2(utils_map_ud,                                          \
                        (__alterhook_generate_enable, modifier_name,           \
                         __alterhook_expand info)) modifier_enabled = true;    \
    }
  #define __alterhook_define_modifier_disable(info, modifier_name)             \
    static void disable_modifier()                                             \
    {                                                                          \
      if (!modifier_activated || !modifier_enabled)                            \
        return;                                                                \
      auto& instance = ::alterhook::hook_manager::get();                       \
      __alterhook_call2(utils_map_ud,                                          \
                        (__alterhook_generate_disable, modifier_name,          \
                         __alterhook_expand info)) modifier_enabled = false;   \
    }
#else
  #define __alterhook_define_castable_concepts(info)
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
#ifndef __INTELLISENSE__
  #define __alterhook_gen_orig_wrap_impl(modifier_target, base_name, info)     \
    __alterhook_call2(utils_map_ud,                                            \
                      (__alterhook_setup_original_wrapper_implementation,      \
                       (modifier_target, base_name), __alterhook_expand info))
  #define __alterhook_gen_cache_methods(info)                                  \
    __alterhook_call2(utils_map,                                               \
                      (__alterhook_generate_cached_target_address_method,      \
                       __alterhook_expand info))
#else
  #define __alterhook_gen_orig_wrap_impl(modifier_target, base_name, info)
  #define __alterhook_gen_cache_methods(info)
#endif

  // clang-format off
#define __alterhook_define_modifier_impl(info, base_name, modifier_name,       \
                                         modifier_target)                      \
  namespace                                                                    \
  {                                                                            \
    template <typename derived>                                                \
    class base_name                                                            \
        : public modifier_target,                                              \
          __alterhook_call2(utils_map_list,                                    \
                            (__alterhook_inherit_from_original_wrapper,        \
                             __alterhook_expand info))                         \
    {                                                                          \
    private:                                                                   \
      inline static bool modifier_enabled   = false;                           \
      inline static bool modifier_activated = false;                           \
      __alterhook_gen_cache_methods(info)                                      \
      __alterhook_define_modifier_static_asserter(info, modifier_name)         \
    public:                                                                    \
      typedef base_name original;                                              \
      __alterhook_call2(utils_map,                                             \
                        (__alterhook_make_original_wrapper_methods_available,  \
                         __alterhook_expand info))                             \
      __alterhook_define_modifier_activate(info, modifier_name)                \
      __alterhook_define_modifier_deactivate(info, modifier_name)              \
      __alterhook_define_modifier_enable(info, modifier_name)                  \
      __alterhook_define_modifier_disable(info, modifier_name)                 \
    };                                                                         \
  }                                                                            \
  __alterhook_gen_orig_wrap_impl(modifier_target, base_name,                   \
                                 info) class modifier_name                     \
      : public base_name<modifier_name>
  // clang-format on

#define __alterhook_define_modifier(info, modifier_name, modifier_target)      \
  __alterhook_define_modifier_impl(info, utils_concat(modifier_, __COUNTER__), \
                                   modifier_name, modifier_target)

/*
 * MODIFIER IMPLEMENTATION
 */
#define __modifier(info, modifier_name, modifier_target)                       \
  __alterhook_call2(utils_map_ud, (__alterhook_setup_method_getter,            \
                                   modifier_target, __alterhook_expand info))  \
      __alterhook_call2(utils_map_ud,                                          \
                        (__alterhook_setup_original_wrapper, modifier_target,  \
                         __alterhook_expand info))                             \
          __alterhook_define_castable_concepts(info)                           \
              __alterhook_define_modifier(info, modifier_name,                 \
                                          modifier_target)

#define modifier(modifier_name, modifier_target, ...)                          \
  utils_concat(                                                                \
      utils_concat(utils_concat(__very_hidden_dummy_, __COUNTER__), _),        \
      __LINE__);                                                               \
  __modifier((utils_map_list(__alterhook_gen_tag, __VA_ARGS__)),               \
             modifier_name, modifier_target)
} // namespace alterhook
