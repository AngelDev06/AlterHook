# Modifier Implementation

This is literally such a cursed feature that pretty much deserves a seperate markdown file to explain how it works under the hood, not just for anyone curious enough to take a deeper look at it, but for myself included! There is no way I will remember how it works after some time so this documentation is a meaningful addition to the library. With that said:

<ins>**This is not a documentation on how to use the tool. Usage documentation is provided via Doxygen like the rest of the library**</ins>

## The modifier macro

In order to help explain the process I believe it's better to start of from higher level parts and move on to lower level ones as we proceed.

The definition is the following:
```cpp
#define modifier(modifier_name, modifier_target, ...)                          \
  utils_concat(                                                                \
      utils_concat(utils_concat(__very_hidden_dummy_, __COUNTER__), _),        \
      __LINE__);                                                               \
  __modifier((utils_map_list(__alterhook_generate_tag, __VA_ARGS__)),          \
             modifier_name, utils_concat(modifier_, __COUNTER__),              \
             modifier_target)
```

Lets break it down:
```cpp
#define modifier(modifier_name, modifier_target, ...)                          \
  utils_concat(                                                                \
      utils_concat(utils_concat(__very_hidden_dummy_, __COUNTER__), _),        \
      __LINE__);
```

This is just generating a dummy class declaration that won't be used anywhere. The combo of `__COUNTER__` and `__LINE__` is used to give it a unique name to avoid conflicts.
The reason for its existence is because as we will see, certain standalone tools need to be generated out of scope (inside a detail namespace) **before the modifier class is defined!** So this is a way to skip immediate definition. Also note that `utils_concat(a, b)` is just a safe `a##b` under the hood.

```cpp
  __modifier((utils_map_list(__alterhook_generate_tag, __VA_ARGS__)),          \
             modifier_name, utils_concat(modifier_, __COUNTER__),              \
             modifier_target)
```

This is the interesting part. `utils_map_list` generates a comma separated list where each item is the result of the macro passed "invoked" with the respective item in `__VA_ARGS__`.
`__alterhook_generate_tag` is this:
```cpp
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
```

So **generate tag** takes the name of the function (or a pair of name and type) and creates a new pack of items that include a macro to generate a tool (we will talk about that later on), a unique name tag that all tools generated shall use (again using `__COUNTER__`) and the argument passed expanded if possible. So at the of the day the map list code generates new packs of arguments which will be used by the next macro in line.

> Note that `utils_concat(modifier_, __COUNTER__)` will generate the name of the main base class (which the user class will directly inherit from). It will be discussed in depth later on.

Moving on to:
```cpp
#define __modifier(info, modifier_name, modifier_handler, modifier_target)     \
  __alterhook_setup_method_getters(modifier_target, info)                      \
      __alterhook_setup_original_wrappers(                                     \
          modifier_target, info) __alterhook_setup_castable_concepts(info)     \
          __alterhook_define_modifier(info, modifier_name, modifier_handler,   \
                                      modifier_target)                         \
              __alterhook_generate_original_wrapper_method_implementations(    \
                  modifier_target, modifier_handler, info) class modifier_name \
      : public modifier_handler<modifier_name>
```

This covers pretty much everything. 3 standalone tools are generated using the macros (the ones who have **setup**). After that, the base class that implements the modifier's functionality which we will call **modifier handler** from now on, will be defined and lastly the user's modifier class will be defined. Of course we don't provide the body of the user class, just the name and the inheritance list.

Let's cover those tools one by one.

## Method Getter

First tool in line is the method getter. The macro chain that follows till the point where the definition is actually applied is pretty mucj boilerplate. They unwrap arguments, they remove some, they apply the definition for each method and so on. So let's just skip to the part where the definition is provided (same logic will be used for the rest of the tools in this document).

```cpp
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
```

Yes there are two of them! The first one is used when the user provides just the name of the function (meaning it's the only one that exists with that name in our target, therefore "unique") and the other when the function type is also provided (for disambiguation purposes).

Both share the same main concept:
- a templated class is used that can accept a member function pointer
- a free function is defined as a friend inside and can therefore access the template parameter!
- the class template is instantiated explicitly to enforce the generation of the get function.
- the free function is declared outside the class scope and can therefore be reached easily with adl.
- the free function takes the unique tag generated earlier and because of this a new special overload is generated for each target.

But why the template and the free function? Well there is actually a loophole in the standard that allows us this way to fetch private methods from the target class **without having legal access to them**. This is allowed only in an explicit instatiation of a template class, hence why we did it this way. And the free function is just a helper that returns the pirated member function pointer.

The difference between the two definitions is that for overloaded methods, we explicitly force the type of the member function pointer beforehand in the explicit specialization (instead of using auto) which will also disambiguate the overload.

Moving on to the next tool.

## Original Wrappers

Those exist in order for the user to have an easy and clean interface to interact with in order to call the original function. Instead of keeping a list somewhere with the references to the original member functions, we generate base classes that have a member function with the exact same name and signature of the original, which the user can call. That method will be just an intermediate, it will proceed to invoke the actual original method through a reference stored as a static member inside the class.

```cpp
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
```

The first part is nothing special at all. Just a declaration of the wrapper class. The magic happens with the partial specializations:
```cpp
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
```

Here the partial specialization declares both the method and the variable we talked about. The member function is defined later on as we will see. The static variable cannot be defined in place, hence an out of scope default initialization is used:
```cpp
  #define __alterhook_define_original_variable(tag, cv)                        \
    template <typename R, typename origcls, typename... args,                  \
              typename derived>                                                \
    decltype(get(tag{})) original_wrapper_##tag<R(cv origcls*, args...),       \
                                                derived>::original_##tag{};
```

## Castable Concepts

Why do they exist? As we will soon see, we have a big assertion function inside the modifier handler that tells us exactly what the problem is and for which function. 
For overloaded methods one of the problems that can occur is the user providing an invalid function type associated with the method. Meaning it's not possible to disambiguate the method since there is no such method with the name and signature specified.
So these concepts determine just that, whether disambiguation is possible with the type provided:
```cpp
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
```

Again there are two of them, the unique one expands to nothing. The reason for that is that we don't have a type provided by the user that should match the method's signature and of course we don't need it, as the method is not expected to be ambiguous.
For the overloaded, the process is simple: we just check if `static_cast` to the target member function pointer is valid. For c++20 and above we use requires blocks as a modern and faster approach while for earlier versions we use good old SFINAE.

> Note that `add_cls_t` will be taking the simple function type and turn it into a member function pointer with the class being the one provided as a template parameter

Of course each tool we talked about carries the unique **tag** in its name so that we can selectively choose which one to use.

## Modifier Handler Definition

```cpp
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
```

Now this is a lot of code. The reason being that the handler does everything, from assertions to properly handling hook insertion and invocation, so that the user won't have to write anything more than the detours.

Let's analyse it step by step:
- The handler inherits from the target class. That's needed in order to be able to invoke the original methods using `*this` of the detour (the compiler won't complain if `*this` corresponds to an instance of a derived class). Of course it is necessary that this is the first class in the inheritance list so that the memory offsets of the fields of `*this` match those in the target class.
- `__alterhook_generate_original_wrapper_inheritance_list(info)` this will effectively generate the rest of the inheritance list, which is inheriting from every single one of the original wrappers that were generated earlier. This is also needed because it allows the wrappers to `static_cast` `*this` to the modifier handler reference (in order to actually invoke the original). We will see that in more detail in the definitions later on.
- `modifier_activated` and `modifier_enabled` are just flags that are pretty much self explanatory. But just to make sure the point is clear, "activated" is a state where all hooks are created and inserted in the container, while "enabled" means those hooks are enabled. It is not possible yet to selectively enable/disable hooks for each method. It is worth mentioning that an enabled modifier is always an activated modifier while the reverse isn't always true.
- `__alterhook_generate_cached_target_address_getters(info)` a tool used to generate some helper methods that cache the result of `get_target_address` for the target method. Specifically they just use a static variable inside that calls `get_target_address` the first time control passes. This is done because sometimes `get_target_address` can be a little bit heavy (regarding member functions) so it's better to do it only once.
- `__alterhook_define_modifier_static_asserter(info, modifier_name)` generates a `consteval` member function that does nothing other than static assertions which happens only when invoked. Since this is an important part of the modifier concept, a deeper look will be taken later on.
- `typedef modifier_handler original;` of course the modifier handler isn't the original class at all but it's a nice trick that allows the user to write code like `original::somefunc(args...)` in their detour method. This works because the handler publicly inherits from all the wrappers and therefore their methods.
- `__alterhook_generate_base_typedefs_and_using_wrapped_original_method_declarations(info)` this will bring all the methods inherited from the wrappers to the scope via a using declaration and therefore hiding effectively the actual original methods in the target class (meaning the target methods). So the user can't accidentally call the target methods as they have been overshadowed by the ones the wrappers brought in place (which properly handle original calls). The typedefs simply create an alias type (using the unique tag) for each of wrapper base classes. This will come in handy with the core methods of the handler as we will see later on.
- The rest of the macros genetate the public api which of course will be available on the user's modifier class due to public inheritance. Since they pretty much follow the exact same pattern, I am gonna cover just one of them in detail:
```cpp
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
```
For all the public api methods the code starts with an `if constexpr` statement that only activates the actual code if the tests passed. Since the hooking api already provides its own static checks, we put this guard to prevent the user's error list from being flooded with generalized error messages. The modifier's specific errors give a better understanding to the user about where the problem is. 
Next we obviously check if the operation we are trying to do has already be done before and skip the entire thing if that's true.
Then we are getting the global instance of the hook manager. This is the global container we have for storing hooks. The layout is a map with key being the target method and the value being another map with key a string and value the actual hook. The string has the format "modifier_class::function_name" and it allows quick fetching of the user's hook across others that might have been set for that specific target. I won't get into detail about its implementation as that's clean c++ code and can be read from the header file.
Moving on to the generation part. `__alterhook_generate_hook_insertions` is pretty much just a straight up spam of `insert` calls to the hook manager. It uses the cache getters we saw before to get the target address the (the key of the top level map) and for the value it generates the string (with the name of the modifier and the function name), gets the detour member function pointer and casts it to the respective target member function pointer (allowed since we are casting derived to base) and lastly it passes a reference to the respective original holder, which is that field of the wrapper we inherited from.
See for yourself:
```cpp
#define __alterhook_generate_hook_insertion2(modifier_name, tag, name)         \
  instance.insert(                                                             \
      cached_get(__modifier_helpers::tag{}), #modifier_name "::" #name,        \
      static_cast<decltype(get(__modifier_helpers::tag{}))>(&derived::name),   \
      base_wrapper_##tag::original_##tag);
```
