/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "detail/macros.h"
#include "utilities/utils.h"
#include "addresser.h"

namespace alterhook
{
  /**
   * @brief A struct that holds the protection information of a memory page in a
   * portable matter
   */
  struct protection_info
  {
    bool read    : 1;
    bool write   : 1;
    bool execute : 1;
  };

  /**
   * @brief Takes any address and returns its protection information.
   * @param address the address to check (can be any address, even null)
   * @returns an instance of @ref alterhook::protection_info that specifies the
   * protection used in the memory page `address` points to.
   * @note If `address` doesn't directly point to the beginning of a memory
   * page, the library will check wether it's within the bounds of one.
   */
  ALTERHOOK_API protection_info get_protection(const void* address);

  /**
   * @brief Takes any address and tells whether it points to executable memory
   * or not
   * @param address the address to check (can be any address, including null)
   * @returns true if `address` points to executable memory, false otherwise.
   */
  inline bool is_executable_address(const void* address)
  {
    return get_protection(address).execute;
  }

  /**
   * @brief Takes any callable type and tries to get its underlying address
   * @tparam T the callable type, it can be anything that satisfies
   * @ref alterhook::utils::callable_type
   * @param fn the instance of the callable type to get the underlying
   * address from
   * @returns a pointer to the underlying function of the callable passed, or
   * null on failure
   * @attention Since @ref alterhook::addresser::address_of is not implemented
   * for clang on windows due to ABI issues, it instead proceeds to use
   * @ref alterhook::addresser::address_of_regular for any member function
   * pointer passed. This however will result in inaccurate results if the
   * member function pointer points to a virtual method. It is advised that you
   * use @ref alterhook::addresser::address_of_virtual ahead of time if you know
   * it points to a virtual function.
   */
  template <typename T, typename = std::enable_if_t<utils::callable_type<T>>>
  constexpr std::byte* get_target_address(T&& fn) noexcept;

  /**
   * @brief Takes a raw address, casts it to `T` (or `T*` if `T` is a function
   * type) and returns it
   * @tparam T the function-like type to cast it to, i.e. anything that
   * satisfies @ref alterhook::utils::function_type
   * @param address the address that should be casted
   * @returns An instance of `T` (or `T*` if `T` is a function type) that
   * contains the original address.
   *
   * For member function pointers the library proceeds to first construct a
   * dummy one that's initialized with null and then put the address as its
   * first field. This prevents the address from being treated differently based
   * on the rest of the fields that the member function pointer may have. For
   * `std::function` it just constructs a normal instance of it with `address`
   * treated as a regular function pointer.
   * @warning It is not checked whether `address` points to executable memory,
   * so if an attempt is made to get and invoke a function-like type from an
   * address that doesn't point to executable memory the behavior is undefined.
   */
  template <typename T, typename = std::enable_if_t<utils::function_type<T>>>
  auto function_cast(void* address) noexcept;
  /// @copydoc alterhook::function_cast(void*)
  template <typename T, typename = std::enable_if_t<utils::function_type<T>>>
  auto function_cast(const void* address) noexcept;

  /**
   * @brief Takes an exception object and if there is already an exception being
   * handled, it throws a nested exception that includes both the old exception
   * and the new one, otherwise throws the exception object itself.
   * @tparam T the type of the exception object (can be anything)
   * @param exception the exception object to be thrown
   */
  template <typename T>
  [[noreturn]] void nested_throw(T&& exception);

  template <typename T, typename>
  constexpr std::byte* get_target_address(T&& fn) noexcept
  {
    typedef utils::remove_cvref_t<T> fn_t;
    static_assert(!utils::stl_function_type<fn_t>,
                  "Cannot get the underlying function address out of an "
                  "instance of `std::function`");

    if constexpr (utils::captureless_lambda<fn_t>)
      return reinterpret_cast<std::byte*>(
          static_cast<utils::captureless_lambda_actual_func_ptr_type_t<fn_t>>(
              fn));
#if utils_clang && utils_windows
    else if constexpr (utils::member_function_type<fn_t>)
      return reinterpret_cast<std::byte*>(addresser::address_of_regular(fn));
    else if constexpr (utils::fn_object_v<std::remove_pointer_t<fn_t>>)
      return reinterpret_cast<std::byte*>(
          addresser::address_of_regular(&fn_t::operator()));
#else
    else if constexpr (utils::member_function_type<fn_t>)
      return reinterpret_cast<std::byte*>(addresser::address_of(fn));
    else if constexpr (utils::fn_object_v<std::remove_pointer_t<fn_t>>)
      return reinterpret_cast<std::byte*>(
          addresser::address_of(&fn_t::operator()));
#endif
    else
      return reinterpret_cast<std::byte*>(fn);
  }

  template <typename T, typename>
  auto function_cast(void* address) noexcept
  {
    typedef utils::remove_cvref_t<T> fn_t;
    if constexpr (std::is_member_function_pointer_v<fn_t>)
    {
      T val{ nullptr };
      reinterpret_cast<void*&>(val) = address;
      return val;
    }
    else if constexpr (std::is_function_v<utils::clean_type_t<T>>)
      return reinterpret_cast<std::add_pointer_t<utils::clean_type_t<T>>>(
          address);
    else
      return fn_t(
          reinterpret_cast<utils::unwrap_stl_function_t<fn_t>>(address));
  }

  template <typename T, typename>
  auto function_cast(const void* address) noexcept
  {
    typedef utils::remove_cvref_t<T> fn_t;
    if constexpr (utils::member_function_type<fn_t>)
    {
      T val{ nullptr };
      reinterpret_cast<void*&>(val) = const_cast<void*>(address);
      return val;
    }
    else if constexpr (std::is_function_v<utils::clean_type_t<T>>)
      return reinterpret_cast<std::add_pointer_t<utils::clean_type_t<T>>>(
          const_cast<void*>(address));
    else
      return reinterpret_cast<utils::unwrap_stl_function_t<fn_t>>(
          const_cast<void*>(address));
  }

  template <typename T>
  [[noreturn]] void nested_throw(T&& exception)
  {
    struct nested : std::nested_exception,
                    utils::remove_cvref_t<T>
    {
      [[maybe_unused]] typedef utils::remove_cvref_t<T> base;

      nested(const std::nested_exception& other, T&& current)
          : std::nested_exception(other), base(std::forward<T>(current))
      {
      }
    };

    std::nested_exception other{};
    if (other.nested_ptr())
      throw(nested(other, std::forward<T>(exception)));
    else
      throw(std::forward<T>(exception));
  }

  namespace helpers
  {
    struct original
    {
      virtual original& operator=(std::nullptr_t null)      = 0;
      virtual original& operator=(const std::byte* address) = 0;

      // not needed but put nevertheless to prevent any compiler warnings
      virtual ~original() {}

      template <typename T>
      bool contains_ref(T& orig);
    };

    template <typename T>
    struct original_wrapper : original
    {
      T& val;

      original_wrapper(T& orig) : val(orig) {}

      original_wrapper& operator=(std::nullptr_t null) override
      {
        val = null;
        return *this;
      }

      original_wrapper& operator=(const std::byte* address) override
      {
        val = function_cast<T>(address);
        return *this;
      }
    };

    typedef std::aligned_storage_t<
        sizeof(original_wrapper<std::function<void()>>),
        alignof(original_wrapper<std::function<void()>>)>
        orig_buff_t;

    template <typename T>
    bool original::contains_ref(T& orig)
    {
      if (auto* wrapper = dynamic_cast<original_wrapper<T>*>(this))
        return &wrapper->val == &orig;
      return false;
    }

    template <typename dtr, typename orig>
    utils_consteval void assert_valid_detour_original_pair()
    {
      typedef utils::clean_type_t<dtr>  detour_type;
      typedef utils::clean_type_t<orig> storage_type;
      static_assert(std::is_same_v<utils::fn_return_t<detour_type>,
                                   utils::fn_return_t<storage_type>>,
                    "The return type of the detour and the original function "
                    "need to be the same");
#if utils_cc_assertions
      static_assert(
          utils::compatible_calling_convention_with<detour_type, storage_type>,
          "The calling conventions of the detour and the original function "
          "need to be compatible");
#endif
      static_assert(
          utils::compatible_function_arguments_with<detour_type, storage_type>,
          "The arguments the detour accepts aren't compatible with the "
          "original function");
    }

    template <typename trg, typename dtr>
    utils_consteval void assert_valid_target_and_detour_pair()
    {
      typedef utils::clean_type_t<trg> ctrg;
      typedef utils::clean_type_t<dtr> cdtr;
      static_assert(
          std::is_same_v<utils::fn_return_t<ctrg>, utils::fn_return_t<cdtr>>,
          "The return type of the target and the detour function need to be "
          "the same");
#if utils_cc_assertions
      static_assert(utils::compatible_calling_convention_with<ctrg, cdtr>,
                    "The calling conventions of the target and the detour "
                    "function need to be compatible");
#endif
      static_assert(utils::compatible_function_arguments_with<cdtr, ctrg>,
                    "The arguments the detour accepts aren't compatible with "
                    "the target function");
    }

    template <typename detour, typename... detours, typename original,
              typename... originals>
    utils_consteval void assert_valid_detour_and_original_pairs(
        utils::type_sequence<detour, detours...>,
        utils::type_sequence<original, originals...>)
    {
      typedef utils::clean_type_t<detour>   cdetour;
      typedef utils::clean_type_t<original> coriginal;
      static_assert(
          ((std::is_same_v<utils::fn_return_t<cdetour>,
                           utils::fn_return_t<utils::clean_type_t<detours>>> &&
            std::is_same_v<
                utils::fn_return_t<coriginal>,
                utils::fn_return_t<utils::clean_type_t<originals>>>)&&...) &&
              std::is_same_v<utils::fn_return_t<cdetour>,
                             utils::fn_return_t<coriginal>>,
          "The return types of the detours and the original function need to "
          "be the same");
#if utils_cc_assertions
      static_assert(
          ((utils::compatible_calling_convention_with<
                utils::clean_type_t<detours>, utils::clean_type_t<originals>> &&
            utils::compatible_calling_convention_with<
                cdetour, utils::clean_type_t<originals>> &&
            utils::compatible_calling_convention_with<
                utils::clean_type_t<detours>, coriginal>)&&...) &&
              utils::compatible_calling_convention_with<cdetour, coriginal>,
          "The calling conventions of the detours and the original function "
          "aren't compatible");
#endif
      static_assert(
          ((utils::compatible_function_arguments_with<
                utils::clean_type_t<detours>, utils::clean_type_t<originals>> &&
            utils::compatible_function_arguments_with<
                utils::clean_type_t<detours>, coriginal>)&&...) &&
              utils::compatible_function_arguments_with<cdetour, coriginal>,
          "The arguments of the detours and the original function aren't "
          "compatible");
    }

    template <typename trg, typename... detours>
    utils_consteval void
        assert_valid_target_and_detours(utils::type_sequence<detours...>)
    {
      typedef utils::clean_type_t<trg> ctrg;
      static_assert(
          (std::is_same_v<utils::fn_return_t<ctrg>,
                          utils::fn_return_t<utils::clean_type_t<detours>>> &&
           ...),
          "The return types of the target and the detour need to be the same");
#if utils_cc_assertions
      static_assert((utils::compatible_calling_convention_with<
                         ctrg, utils::clean_type_t<detours>> &&
                     ...),
                    "The calling conventions of the detours and the target "
                    "function aren't compatible");
#endif
      static_assert((utils::compatible_function_arguments_with<
                         utils::clean_type_t<detours>, ctrg> &&
                     ...),
                    "The arguments of the detours and the target function "
                    "aren't compatible");
    }

    template <typename iseq, typename tseq>
    struct extract_detour_sequence_impl;

    template <size_t... indexes, typename tseq>
    struct extract_detour_sequence_impl<std::index_sequence<indexes...>, tseq>
    {
      typedef utils::type_sequence<utils::type_at_t<indexes, tseq>...> type;
    };

    template <typename... types>
    struct extract_detour_sequence
        : extract_detour_sequence_impl<
              utils::make_index_sequence_with_step<sizeof...(types)>,
              utils::type_sequence<types...>>
    {
    };

    template <typename... types>
    using extract_detour_sequence_t =
        typename extract_detour_sequence<types...>::type;

    template <typename... tuples>
    struct extract_detour_sequence_from_tuples
    {
      typedef utils::type_sequence<std::tuple_element_t<0, tuples>...> type;
    };

    template <typename... tuples>
    using extract_detour_sequence_from_tuples_t =
        typename extract_detour_sequence_from_tuples<tuples...>::type;
  } // namespace helpers
} // namespace alterhook
