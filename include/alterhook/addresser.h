/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if utils_cpp20
  #include <concepts>
#endif
#include "macros.h"
#include "utilities/utils.h"
#if utils_windows
  #define __alterhook_is_virtual(memfunc)                                      \
    is_virtual_msvc_impl(reinterpret_cast<void*>(&memfunc))
#else
  #define __alterhook_is_virtual(memfunc)                                      \
    is_virtual_impl(reinterpret_cast<void*>(&memfunc))
#endif

#if utils_windows
  #if utils_msvc && !defined(NDEBUG)
    #define __alterhook_follow_thunk(address)                                  \
      follow_thunk_function(follow_msvc_debug_jmp(address))
  #else
    #define __alterhook_follow_thunk(address) follow_thunk_function(address)
  #endif
#else
  #define __alterhook_follow_thunk(address) address
#endif

#if utils_cpp20
  #define __alterhook_must_be_memfuncptr_nd(x) utils::member_function_type x
  #define __alterhook_must_be_memfuncptr(x)    utils::member_function_type x
#else
  #define __alterhook_must_be_memfuncptr_nd(x)                                 \
    typename x, std::enable_if_t<utils::member_function_type<x>, size_t>
  #define __alterhook_must_be_memfuncptr(x)                                    \
    __alterhook_must_be_memfuncptr_nd(x) = 0
#endif

namespace alterhook
{
  template <typename T>
  struct instanceptrof;

#if utils_cpp20
  template <typename T>
  concept has_instanceptrof = requires {
    {
      instanceptrof<T>{}()
    } -> std::same_as<T*>;
  };
#else
  namespace helpers
  {
    template <typename T, typename = void>
    inline constexpr bool has_instanceptrofsfinae = false;
    template <typename T>
    inline constexpr bool has_instanceptrofsfinae<
        T, std::void_t<decltype(instanceptrof<T>{}())>> =
        std::is_same_v<decltype(instanceptrof<T>{}()), T*>;
  } // namespace helpers

  template <typename T>
  inline constexpr bool has_instanceptrof = helpers::has_instanceptrofsfinae<T>;
#endif

  class ALTERHOOK_API addresser
  {
  public:
    // THE API
    template <__alterhook_must_be_memfuncptr(T)>
    static bool is_virtual(T memfuncptr);

    template <__alterhook_must_be_memfuncptr(T)>
    static uintptr_t address_of(T memfuncptr);

    // in order for both msvc & non-msvc implementation of this to work the
    // library has to get built with a compiler other than msvc
    template <__alterhook_must_be_memfuncptr(T)>
    static uintptr_t address_of_virtual(T memfuncptr);

    template <__alterhook_must_be_memfuncptr(T)>
    static uintptr_t address_of_regular(T memfuncptr);

  private:
    template <size_t>
    struct single_inheritance
    {
      virtual ~single_inheritance() {}
    };

    struct multiple_inheritance : single_inheritance<0>,
                                  single_inheritance<1>
    {
      ~multiple_inheritance() override {}
    };

    static multiple_inheritance* instance() noexcept;

    template <typename T>
    static uintptr_t vtableindexof(T memfuncptr);

    template <typename T>
    static uintptr_t adjustmentof(T memfuncptr);

    template <typename cls>
    static cls* generate_instance();

    template <typename cls>
    static cls* get_instance();

#if utils_windows
    static uintptr_t follow_thunk_function(uintptr_t address) noexcept;
  #ifndef NDEBUG
    // msvc adds an extra jump when calling functions on debug builds
    static uintptr_t follow_msvc_debug_jmp(uintptr_t address) noexcept;
  #endif
    // msvc abi specific implementation
    static bool is_virtual_msvc_impl(void* address) noexcept;
#else
    static bool is_virtual_impl(void* address) noexcept;
#endif
  };

  /*
  * TEMPLATE DEFINITIONS (ignore them)
  */
  template <__alterhook_must_be_memfuncptr_nd(T)>
  bool addresser::is_virtual(T memfuncptr)
  {
#if utils_clang && utils_windows
    static_assert(utils::always_false<T>,
                  "`addresser::is_virtual` doesn't work for windows builds "
                  "using the clang compiler due to ABI issues, use "
                  "`address_of_virtual` ahead of time");
#else
    return __alterhook_is_virtual(memfuncptr);
#endif
  }

  template <__alterhook_must_be_memfuncptr_nd(T)>
  uintptr_t addresser::address_of(T memfuncptr)
  {
    if (is_virtual(memfuncptr))
      return address_of_virtual(memfuncptr);
    return address_of_regular(memfuncptr);
  }

  template <__alterhook_must_be_memfuncptr_nd(T)>
  uintptr_t addresser::address_of_virtual(T memfuncptr)
  {
    typedef utils::fn_class_t<T> cls;

    cls* inst = get_instance<cls>();
    if (!inst)
      return 0;

    uintptr_t vtable_index = vtableindexof(memfuncptr);
    uintptr_t adjustment   = adjustmentof(memfuncptr);
    uintptr_t address      = *reinterpret_cast<uintptr_t*>(
        *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(inst) +
                                      adjustment) +
        vtable_index);
    return __alterhook_follow_thunk(address);
  }

  template <__alterhook_must_be_memfuncptr_nd(T)>
  uintptr_t addresser::address_of_regular(T memfuncptr)
  {
    return __alterhook_follow_thunk(*reinterpret_cast<uintptr_t*>(&memfuncptr));
  }

  template <typename T>
  uintptr_t addresser::vtableindexof(T memfuncptr)
  {
    typedef utils::fn_class_t<T> cls;
    typedef uintptr_t (cls::*method_t)();
    return (reinterpret_cast<cls*>(instance())
                ->*reinterpret_cast<method_t>(memfuncptr))();
  }

  template <typename T>
  uintptr_t addresser::adjustmentof(T memfuncptr)
  {
    if constexpr (sizeof(T) == sizeof(uintptr_t))
      return 0;
    else
    {
      uintptr_t adjustment = *(reinterpret_cast<uintptr_t*>(&memfuncptr) + 1);
      if (adjustment & 1)
        adjustment >>= 1;
      return adjustment;
    }
  }

  template <typename cls>
  cls* addresser::generate_instance()
  {
    if constexpr (has_instanceptrof<cls>)
      return instanceptrof<cls>{}();
    else if constexpr (std::is_abstract_v<cls> ||
                       !std::is_move_constructible_v<cls>)
      return nullptr;
    else
    {
      std::byte memoryblock[sizeof(cls)]{};
      return new cls(std::move(*reinterpret_cast<cls*>(memoryblock)));
    }
  }

  template <typename cls>
  cls* addresser::get_instance()
  {
    static cls* cache = generate_instance<cls>();
    return cache;
  }
} // namespace alterhook
