/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "detail/macros.hpp"
#include "detail/constants.hpp"
#include "utilities/function_traits.hpp"
#include "utilities/macros.hpp"
#include "addresser.hpp"
#include <cstddef>
#include <cstring>
#include <new>
#include <type_traits>
#include <utility>

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
   * @brief takes an instance of a callable type with an ambiguous overload of
   * either `operator()` or the conversion operator to a function pointer and
   * returns a member function pointer for the former and a function pointer for
   * the latter based on the function-like type `func`.
   * @tparam func the function-like type based on which a member function
   * pointer/function pointer will be generated in order to disambiguate the
   * overloads (must satisfy @ref alterhook::utils::function_type)
   * @tparam callable the callable type of the instance which should have an
   * ambiguous overload of `operator()` (i.e. one that cannot be accessed
   * normally via `&callable::operator()`) or optionally a conversion operator
   * to a function pointer. It is allowed to have no overload of `operator()` at
   * all but in that case it must have the conversion operator defined.
   * @param instance the instance to disambiguate. For regular ambiguous
   * callable types that do not provide a conversion operator to a function
   * pointer, the instance is not required. So a
   * @ref alterhook::disambiguate() "second overload" is provided for that
   * specific reason
   * @returns the disambiguated result. It is a member function pointer to the
   * ambiguous `operator()` overload if no conversion operator is provided,
   * otherwise it's a function pointer returned from the invocation of the
   * provided conversion operator.
   *
   * To generate the needed types based on `func`:
   * - @ref alterhook::utils::generic_lambda_disambiguation_type_t is used when
   *   @ref alterhook::utils::disambiguatable_lambda_with is satisfied
   * - @ref alterhook::utils::generic_callable_disambiguation_type_t is used
   *   when @ref alterhook::utils::disambiguatable_callable_with is satisfied
   *
   * If for some reason both are satisfied, the former is preferred, which is to
   * invoke the conversion operator. See the relevant documentation of those
   * utilities to find out how the types are generated and what the requirements
   * are.
   */
  template <
      typename func, typename callable,
      typename = std::enable_if_t<utils::disambiguatable_with<callable, func>>>
  auto disambiguate(callable&& instance) noexcept;

  /**
   * @brief a convenient overload of
   * @ref alterhook::disambiguate(callable&&) that does not require an instance,
   * because it disambiguates only the `operator()` and doesn't call any
   * conversion operator.
   * @returns always a member function pointer to the disambiguated `operator()`
   * overload.
   *
   * Since no conversion operator is called in this overload, the `callable`
   * type specified is expected to define an ambiguous overload of `operator()`
   * and @ref alterhook::utils::generic_callable_disambiguation_type_t is what
   * will be used to generate the member function pointer. See @ref
   * alterhook::utils::disambiguatable_callable_with for the requirements of
   * `func` and `callable`.
   */
  template <typename func, typename callable,
            typename = std::enable_if_t<
                utils::disambiguatable_callable_with<callable, func>>>
  auto disambiguate() noexcept;

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

  /// @brief An @ref alterhook::get_target_address() overload that tries to
  /// disambiguate `fn` first before further processing based on `func` using
  /// @ref alterhook::disambiguate(callable&&) or just calls the other overload
  /// if that's not possible
  template <typename func, typename T,
            typename =
                std::enable_if_t<!std::is_same_v<utils::remove_cvref_t<T>,
                                                 utils::remove_cvref_t<func>> &&
                                 (utils::callable_type<T> ||
                                  utils::disambiguatable_with<T, func>)>>
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

  template <typename func, typename callable, typename>
  auto disambiguate(callable&& instance) noexcept
  {
    if constexpr (utils::disambiguatable_lambda_with<callable, func>)
      return static_cast<utils::generic_lambda_disambiguation_type_t<func>>(
          instance);
    else
      return static_cast<
          utils::generic_callable_disambiguation_type_t<callable, func>>(
          &callable::operator());
  }

  template <typename func, typename callable, typename>
  auto disambiguate() noexcept
  {
    return static_cast<
        utils::generic_callable_disambiguation_type_t<callable, func>>(
        &callable::operator());
  }

  template <typename T, typename>
  constexpr std::byte* get_target_address(T&& fn) noexcept
  {
    typedef utils::remove_cvref_t<T> fn_t;
    static_assert(!utils::stl_function_type<fn_t>,
                  "get_target_address: Cannot get the underlying function "
                  "address out of an `std::function` instance");
    if constexpr (utils::lambda_type<fn_t>)
      static_assert(
          utils::captureless_lambda<fn_t>,
          "get_target_address: A lambda was passed that is not captureless");

    if constexpr (utils::captureless_lambda<fn_t>)
      return reinterpret_cast<std::byte*>(
          static_cast<utils::captureless_lambda_actual_func_ptr_type_t<fn_t>>(
              fn));
#if utils_clang && utils_windows
    else if constexpr (utils::member_function_type<fn_t>)
      return reinterpret_cast<std::byte*>(addresser::address_of_regular(fn));
    else if constexpr (utils::fn_object_v<fn_t>)
      return reinterpret_cast<std::byte*>(
          addresser::address_of_regular(&fn_t::operator()));
#else
    else if constexpr (utils::member_function_type<fn_t>)
      return reinterpret_cast<std::byte*>(addresser::address_of(fn));
    else if constexpr (utils::fn_object_v<fn_t>)
      return reinterpret_cast<std::byte*>(
          addresser::address_of(&fn_t::operator()));
#endif
    else
      return reinterpret_cast<std::byte*>(fn);
  }

  template <typename func, typename T, typename>
  constexpr std::byte* get_target_address(T&& fn) noexcept
  {
    if constexpr (utils::disambiguatable_with<T, func>)
      return get_target_address(disambiguate<func>(std::forward<T>(fn)));
    else
      return get_target_address(std::forward<T>(fn));
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
      return reinterpret_cast<utils::add_pointer_t<utils::clean_type_t<T>>>(
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
      return reinterpret_cast<utils::add_pointer_t<utils::clean_type_t<T>>>(
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
    // A wrapper over a reference to the original is needed to handle binding
    // and unbinding (as well as moving/copying) in a type safe way. Since the
    // original reference may refer to a simple function pointer or to a
    // complicated std::function instance, dynamic dispatch is used to allow
    // proper management of each type of reference. This is the abstract class
    // that defines the available tools that hooks can make use of.
    class abstract_original_ref
    {
    public:
      virtual ~abstract_original_ref()           = default;
      virtual void             unbind_original() = 0;
      virtual void             bind_original(const std::byte* address) = 0;
      virtual const std::byte* raw_address() const                     = 0;
      virtual bool             is_stl_function_ref() const noexcept    = 0;

      template <typename Fn,
                typename = std::enable_if_t<utils::function_type<Fn>>>
      bool operator==(const Fn& other_func) const noexcept
      {
        return raw_address() == get_target_address(other_func);
      }
    };

    // This is the reference wrapper that implements reference specific logic.
    // Of course it's a template which is why the abstract class was needed.
    template <typename Fn>
    class original_ref : public abstract_original_ref
    {
    public:
      original_ref(Fn& func) : func(func) {}

      void unbind_original() override { func = nullptr; }

      void bind_original(const std::byte* address) override
      {
        func = function_cast<Fn>(address);
      }

      const std::byte* raw_address() const override
      {
        if constexpr (utils::stl_function_type<Fn>)
        {
          utils_assert(false, "prohibited access of raw function address from "
                              "an std::function instance");
          return nullptr;
        }
        else
          return get_target_address(func);
      }

      bool is_stl_function_ref() const noexcept override
      {
        return utils::stl_function_type<Fn>;
      }

      operator auto() const noexcept;

    private:
      Fn& func;
    };

    using original_ref_buffer_t =
        std::aligned_storage_t<sizeof(original_ref<std::function<void()>>),
                               alignof(original_ref<std::function<void()>>)>;

    template <typename Fn>
    original_ref<Fn>::operator auto() const noexcept
    {
      original_ref_buffer_t buffer{};
      memcpy(&buffer, this, sizeof(original_ref));
      return buffer;
    }

    // Yet another wrapper basically, this one is used to control dynamic
    // dispatch in a raw buffer (big enough to hold a full instance of
    // original_ref) and it does that by laundering the pointer to the buffer
    // and effectively forwarding calls up to the original_ref instance that
    // knows how to deal with the reference it holds. This is the tool that
    // hooks should be using as it removes a lot of unecessary boilerplate. It
    // also keeps track of state and makes sure to deactivate moved instances
    // (meaning control over the reference is released). It should be noted that
    // copy/move operations manage the reference holder (which means that the
    // reference itself may be bound to something else or released) while the
    // bind/unbind functions will update the variable the reference refers to.
    class original_ref_handler
    {
    public:
      original_ref_handler() = default;

      template <typename Fn,
                typename = std::enable_if_t<utils::callable_type<Fn>>>
      original_ref_handler(Fn& func) : buffer(original_ref(func)), active(true)
      {
      }

      // Both instances will hold the same reference. Be careful with this one
      // as unbinding one of the instances will leave the other unaware of the
      // change. Might be deprecated in the future.
      original_ref_handler(const original_ref_handler&) = default;

      // As mentioned, old instance is deactivated when moved (just by setting
      // its state to false). It does not touch the original, just the reference
      // itself (releasing it).
      inline original_ref_handler(original_ref_handler&& other)
          : buffer(other.buffer), active(std::exchange(other.active, false))
      {
      }

      original_ref_handler&
          operator=(const original_ref_handler& other) = default;

      inline original_ref_handler& operator=(original_ref_handler&& other)
      {
        if (this == &other)
          return *this;
        buffer = other.buffer;
        active = std::exchange(other.active, false);
        return *this;
      }

      // Unlike the other methods, this one does two jobs: unsets the original
      // and releases the reference (by setting active to false). Since the
      // reference is released, the user should not be able to reuse this
      // instance and instead create a new one with Fn&. Of course all of this
      // is taken into account by the hooking api.
      inline void unbind_original()
      {
        if (!active)
          return;
        std::launder(reinterpret_cast<abstract_original_ref*>(&buffer))
            ->unbind_original();
        active = false;
      }

      // Note that this one modifies the original, not the reference itself like
      // the rest of the assignments and the constructors do. If rebinding the
      // reference is desired, then the assignment operators should be used.
      inline void bind_original(const std::byte* address)
      {
        // When active is set to false that means the reference is no longer
        // taken into account and therefore the user is free to erase or reuse
        // that variable for something else. Therefore we should not try and set
        // that variable using the released reference.
        utils_assert(active, "Prohibited use of the set operator to a released "
                             "original reference");
        std::launder(reinterpret_cast<abstract_original_ref*>(&buffer))
            ->bind_original(address);
      }

      inline bool is_stl_function_ref() const noexcept
      {
        return std::launder(
                   reinterpret_cast<const abstract_original_ref*>(&buffer))
            ->is_stl_function_ref();
      }

      inline bool is_active() const noexcept { return active; }

      inline operator bool() const noexcept { return active; }

      template <typename Fn>
      bool operator==(const Fn& other_func) const noexcept
      {
        return *std::launder(reinterpret_cast<const abstract_original_ref*>(
                   &buffer)) == other_func;
      }

    private:
      original_ref_buffer_t buffer{};
      bool                  active = false;
    };

#if utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wdynamic-class-memaccess"
#endif

#if utils_clang
  #pragma clang diagnostic pop
#endif

    template <typename dtr, typename orig>
    utils_consteval void assert_valid_detour_original_pair()
    {
      if constexpr (!utils::disambiguatable_with<dtr, orig>)
      {
        static_assert(
            std::is_same_v<utils::fn_return_t<dtr>, utils::fn_return_t<orig>>,
            "The return type of the detour and the original function "
            "need to be the same");
#if utils_cc_assertions
        static_assert(
            utils::compatible_calling_convention_with<dtr, orig>,
            "The calling conventions of the detour and the original function "
            "need to be compatible");
#endif
        static_assert(
            utils::compatible_function_arguments_with<dtr, orig>,
            "The arguments the detour accepts aren't compatible with the "
            "original function");
      }
    }

    template <typename trg, typename dtr>
    utils_consteval void assert_valid_target_and_detour_pair()
    {
      static_assert(
          std::is_same_v<utils::fn_return_t<trg>, utils::fn_return_t<dtr>>,
          "The return type of the target and the detour function need to "
          "be "
          "the same");
#if utils_cc_assertions
      static_assert(utils::compatible_calling_convention_with<trg, dtr>,
                    "The calling conventions of the target and the detour "
                    "function need to be compatible");
#endif
      static_assert(utils::compatible_function_arguments_with<dtr, trg>,
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
                utils::fn_return_t<utils::clean_type_t<originals>>>) &&
           ...) &&
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
                utils::clean_type_t<detours>, coriginal>) &&
           ...) &&
              utils::compatible_calling_convention_with<cdetour, coriginal>,
          "The calling conventions of the detours and the original function "
          "aren't compatible");
#endif
      static_assert(
          ((utils::compatible_function_arguments_with<
                utils::clean_type_t<detours>, utils::clean_type_t<originals>> &&
            utils::compatible_function_arguments_with<
                utils::clean_type_t<detours>, coriginal>) &&
           ...) &&
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

    inline void make_backup(std::byte* target, std::byte* dest,
                            bool patch_above) noexcept
    {
#if utils_arm
      target = reinterpret_cast<std::byte*>(
          reinterpret_cast<uintptr_t>(target) & ~1);
#endif
      if (patch_above)
        memcpy(dest, target - detail::constants::patch_above_target_offset,
               detail::constants::patch_above_backup_size);
      else
        memcpy(dest, target, detail::constants::backup_size);
    }

    inline std::byte* resolve_original([[maybe_unused]] std::byte* target,
                                       std::byte* trampoline) noexcept
    {
#if utils_arm
      // basically copies the thumb bit from `target` to `trampoline`
      return reinterpret_cast<std::byte*>(
          reinterpret_cast<uintptr_t>(trampoline) |
          (reinterpret_cast<uintptr_t>(target) & 1));
#else
      return trampoline;
#endif
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

    template <template <typename> typename alloc>
    struct alloc_wrapper
    {
      template <typename T>
      class allocator : public alloc<T>
      {
      public:
        template <typename U>
        struct rebind
        {
          typedef allocator<U> other;
        };

        template <typename U, typename... types>
        void construct(U* ptr, types&&... args)
        {
          new (ptr) U{ std::forward<types>(args)... };
        }
      };
    };
  } // namespace helpers
} // namespace alterhook
