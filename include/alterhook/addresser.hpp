/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if utils_cpp20
  #include <concepts>
#endif
#include "detail/macros.h"
#include "utilities/utils.h"

namespace alterhook
{
  /**
   * @brief A utility that can optionally be implemented by the user and should
   * define `operator()` that returns `T*`
   * @tparam T the class type for which this utility can be implemented
   *
   * This is overall intended to make it possible for the user to customize how
   * a pointer to a valid instance is obtained. The reason this is needed is
   * because when trying to get the real address from a virtual method pointer
   * the library needs to have access to the vtable of the class. To do that it
   * by default heap allocates a "fake" instance that is move constructed from a
   * zero filled byte buffer of the same size. This may or may not be a good
   * solution and therefore if the latter is the case the user can:
   * - define a template specialization of `instanceptrof` (either full or
   *   partial)
   * - implement `operator()` and make it return `T*`
   * - make sure the pointer returned from `operator()` points to a valid
   *   instance and that its storage duration is NOT automatic as it's cached
   *   for later use.
   *
   * @par Example
   * @code{.cpp}
   * template <>
   * struct instanceptrof<MyClass>
   * {
   *   MyClass* operator()() { return new MyClass; }
   * };
   * @endcode
   *
   * @warning Failure to meet the third requirement will result in undefined
   * behavior but failure on the other two will make the library fallback to the
   * default implementation. Also the pointer returned should NOT point to an
   * instance of different underlying type than the one expected as the vtable
   * pointer will be incorrect.
   */
  template <typename T>
  struct instanceptrof;

#if utils_cpp20
  /// tells whether `instanceptrof<T>{}()` is a valid expression that returns T*
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

  /// @brief a class consisting of utilities to extract properties from member
  /// function pointers
  class ALTERHOOK_API addresser
  {
  public:
    /**
     * @brief Takes a member function pointer and returns whether it points to a
     * virtual function.
     * @param memfuncptr the member function pointer to check
     * @returns true if it points to a virtual function, false otherwise
     * @attention This is not implemented for clang on windows due to ABI issues
     */
    template <typename T,
              typename = std::enable_if_t<std::is_member_function_pointer_v<T>>>
    static bool is_virtual(T memfuncptr);

    /**
     * @brief Takes any member function pointer and returns the address of the
     * underlying function.
     * @param memfuncptr the member function pointer to obtain the address from
     * @returns the address of the underlying function as `uintptr_t`
     * @attention Because @ref alterhook::addresser::is_virtual is not
     * implemented for clang on windows, this will fail at compile time as it
     * needs to know whether `memfuncptr` points to a virtual method or not.
     */
    template <typename T,
              typename = std::enable_if_t<std::is_member_function_pointer_v<T>>>
    static uintptr_t address_of(T memfuncptr);

    /**
     * @brief Takes a virtual member function pointer and returns the address of
     * the underlying function.
     * @param memfuncptr the virtual member function pointer to obtain the
     * address from
     * @returns the address of the underlying function as `uintptr_t`
     * @note This involves looking up the function in the vtable and therefore
     * it needs to heap allocate a "fake" instance that is move constructed from
     * a zero filled byte buffer of the same size. If this process is damaging
     * for performance or can cause side effects, consider using
     * @ref alterhook::instanceptrof
     */
    template <typename T,
              typename = std::enable_if_t<std::is_member_function_pointer_v<T>>>
    static uintptr_t address_of_virtual(T memfuncptr);

    /**
     * @brief Takes a regular member function pointer and returns the address of
     * the underlying function.
     * @param memfuncptr the regular member function pointer to obtain the
     * address from
     * @returns the address of the underlying function as `uintptr_t`
     */
    template <typename T,
              typename = std::enable_if_t<std::is_member_function_pointer_v<T>>>
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
    // msvc abi specific implementation
    static bool      is_virtual_impl(void* address) noexcept;
#else
    static uintptr_t follow_thunk_function(uintptr_t address) noexcept
    {
      return address;
    }

    static bool is_virtual_impl(void* address) noexcept;
#endif
  };

  /*
   * TEMPLATE DEFINITIONS (ignore them)
   */
  template <typename T, typename>
  bool addresser::is_virtual(T memfuncptr)
  {
#if utils_clang && utils_windows
    static_assert(utils::always_false<T>,
                  "`addresser::is_virtual` doesn't work for windows builds "
                  "using the clang compiler due to ABI issues, use "
                  "`address_of_virtual` ahead of time");
#endif
    return is_virtual_impl(reinterpret_cast<void*>(&memfuncptr));
  }

  template <typename T, typename>
  uintptr_t addresser::address_of(T memfuncptr)
  {
    if (is_virtual(memfuncptr))
      return address_of_virtual(memfuncptr);
    return address_of_regular(memfuncptr);
  }

  template <typename T, typename>
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
    return follow_thunk_function(address);
  }

  template <typename T, typename>
  uintptr_t addresser::address_of_regular(T memfuncptr)
  {
    return follow_thunk_function(*reinterpret_cast<uintptr_t*>(&memfuncptr));
  }

  template <typename T>
  uintptr_t addresser::vtableindexof(T memfuncptr)
  {
    typedef utils::fn_class_t<T> cls;
    typedef uintptr_t            (cls::*method_t)();
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
