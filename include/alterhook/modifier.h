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
    template <typename K, typename trg, typename dtr, typename orig>
    void insert(K&& key, trg&& target, dtr&& detour, orig& original);
    template <typename K, typename trg, typename dtr, typename orig, typename... types>
    void insert(K&& key, trg&& target, dtr&& detour, orig& original,
                types&&... rest);
    void erase(std::byte* target);

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
    base::erase(key);
    if (base::empty())
      hook_manager::get().erase(hook_chain::get_target());
  }

  inline void managed_concurrent_hook_map::clear()
  {
    base::clear();
    hook_manager::get().erase(hook_chain::get_target());
  }

  inline managed_concurrent_hook_map& hook_manager::operator[](std::byte* key)
  {
    std::shared_lock lock{ manager_lock };
    return at(key);
  }

  template <typename K, typename trg, typename dtr, typename orig>
  inline void hook_manager::insert(K&& key, trg&& target, dtr&& detour,
                                   orig& original)
  {
    std::unique_lock lock{ manager_lock };
    std::byte* const address = nullptr;

    if constexpr (std::is_same_v<utils::remove_cvref_t<trg>, std::byte*>)
      address = target;
    else
      address = get_target_address(std::forward<trg>(target));

    auto [itr, status] = try_emplace(address, address, std::forward<K>(key),
                                     std::forward<dtr>(detour), original);
    if (!status)
      itr->insert(std::forward<K>(key), std::forward<dtr>(detour), original);
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
#define __alterhook_original_wrapper_template(cls, tag, name, cv)              \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      template <typename R, typename origcls, typename... args>                \
      class original_wrapper_##tag<R(cv origcls*, args...)>                    \
      {                                                                        \
      public:                                                                  \
        R name(args... values) cv;                                             \
                                                                               \
      protected:                                                               \
        static decltype(get(tag{})) original_##tag;                            \
      };                                                                       \
      template <typename R, typename origcls, typename... args>                \
      decltype(get(tag{}))                                                     \
          original_wrapper_##tag<R(cv origcls*, args...)>::original_##tag{};   \
    }                                                                          \
  }

#define __alterhook_original_wrapper_setup(cls, tag, name, ...)                \
  namespace                                                                    \
  {                                                                            \
    namespace __modifier_helpers                                               \
    {                                                                          \
      template <typename T>                                                    \
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
      utils::clean_function_type_t<decltype(get(__modifier_helpers::tag{}))>>

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
      template <typename R, typename origcls, typename... args>                \
      R original_wrapper_##tag<R(cv origcls*, args...)>::name(                 \
          args... values) cv                                                   \
      {                                                                        \
        return (static_cast<cv base_name&>(*this).*                            \
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
  using __modifier_helpers::original_wrapper_##tag<                            \
      utils::clean_function_type_t<decltype(get(                               \
          __modifier_helpers::tag{}))>>::name;

#define __alterhook_make_original_wrapper_methods_available_impl2(             \
    callback, tag, name, ...)                                                  \
  __alterhook_make_original_wrapper_methods_available_impl(tag, name)

#define __alterhook_make_original_wrapper_methods_available(data)              \
  __alterhook_make_original_wrapper_methods_available_impl2 data

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

/*
 * MODIFIER BASE CLASS
 */
#define __alterhook_define_modifier_impl(info, base_name, modifier_name,       \
                                         modifier_target)                      \
  namespace                                                                    \
  {                                                                            \
    class base_name                                                            \
        : public modifier_target,                                              \
          __alterhook_call2(utils_map_list,                                    \
                            (__alterhook_inherit_from_original_wrapper,        \
                             __alterhook_expand info))                         \
    {                                                                          \
    public:                                                                    \
      __alterhook_call2(utils_map,                                             \
                        (__alterhook_make_original_wrapper_methods_available,  \
                         __alterhook_expand info))                             \
    };                                                                         \
  }                                                                            \
  __alterhook_call2(utils_map_ud,                                              \
                    (__alterhook_setup_original_wrapper_implementation,        \
                     (modifier_target, base_name),                             \
                     __alterhook_expand info)) class modifier_name             \
      : public base_name

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
          __alterhook_define_modifier(info, modifier_name, modifier_target)

#define modifier(modifier_name, modifier_target, ...)                          \
  utils_concat(                                                                \
      utils_concat(utils_concat(__very_hidden_dummy_, __COUNTER__), _),        \
      __LINE__);                                                               \
  __modifier((utils_map_list(__alterhook_gen_tag, __VA_ARGS__)),               \
             modifier_name, modifier_target)
} // namespace alterhook
