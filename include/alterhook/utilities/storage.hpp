/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
#include "macros.hpp"

namespace alterhook::utils
{
  namespace helpers
  {
    template <typename T, bool = std::is_copy_constructible_v<T>>
    struct movable_box_assign_control;
    template <typename T, typename = void>
    struct movable_box_storage;
    template <typename T, bool is_move>
    struct movable_box_nothrow_assignment;
    template <typename T, bool is_move>
    static constexpr bool movable_box_nothrow_assignment_v =
        movable_box_nothrow_assignment<T, is_move>::value;
  } // namespace helpers

  template <typename T>
  class movable_box : helpers::movable_box_assign_control<T>,
                      helpers::movable_box_storage<T>
  {
  public:
    static_assert(std::is_move_constructible_v<T>,
                  "utils::movable_box: expected move constructible type");

    movable_box() = default;

    constexpr movable_box(T&& value) noexcept(
        std::is_nothrow_move_constructible_v<T>)
        : base(std::move(value))
    {
    }

    template <typename U               = T,
              std::enable_if_t<std::is_same_v<U, T> &&
                                   std::is_copy_constructible_v<T>,
                               size_t> = 0>
    constexpr movable_box(const T& value) noexcept(
        std::is_nothrow_copy_constructible_v<T>)
        : base(value)
    {
    }

    constexpr T& operator*() & noexcept { return base::value; }

    constexpr const T& operator*() const& noexcept { return base::value; }

    constexpr T&& operator*() && noexcept { return std::move(base::value); }

    constexpr const T&& operator*() const&& noexcept
    {
      return std::move(base::value);
    }

    constexpr T* operator->() noexcept { return std::addressof(base::value); }

    constexpr const T* operator->() const noexcept
    {
      return std::addressof(base::value);
    }

  private:
    template <typename, bool>
    friend struct helpers::movable_box_assign_control;

    using base = helpers::movable_box_storage<T>;

    template <typename Self>
    constexpr void assign(Self&& other)
    {
      constexpr bool is_move = std::is_rvalue_reference_v<Self&&>;

      if (this == &other)
        return;

      auto construct_inplace = [this, &other]
      {
#if utils_cpp20
        std::construct_at(std::addressof(base::value),
                          std::forward<Self>(other).value);
#else
        ::new (std::addressof(base::value)) T(std::forward<Self>(other).value);
#endif
        if constexpr (base::has_unengaged_state)
          base::engaged = true;
      };

      auto destruct_inplace = [this]
      {
        if constexpr (base::has_unengaged_state)
        {
          if (!base::engaged)
            return;
        }
        std::destroy_at(std::addressof(base::value));
        if constexpr (base::has_unengaged_state)
        {
          base::engaged = false;
          base::dummy   = 0;
        }
      };

      if constexpr (base::has_unengaged_state)
      {
        if (!other.engaged)
        {
          destruct_inplace();
          return;
        }
      }

      if constexpr (std::conditional_t<is_move, std::is_move_assignable<T>,
                                       std::is_copy_assignable<T>>::value)
      {
        if constexpr (base::has_unengaged_state)
        {
          if (!base::engaged)
          {
            construct_inplace();
            return;
          }
        }
        base::value = std::forward<Self>(other).value;
      }
      else
      {
        destruct_inplace();
        construct_inplace();
      }
    }
  };

  namespace helpers
  {
    template <typename T, bool>
    struct movable_box_assign_control
    {
      movable_box_assign_control()                             = default;
      movable_box_assign_control(movable_box_assign_control&&) = default;

      constexpr movable_box_assign_control&
          operator=(movable_box_assign_control&& other) noexcept(
              movable_box_nothrow_assignment_v<T, true>)
      {
        static_cast<derived&>(*this).assign(
            std::move(static_cast<derived&>(other)));
        return *this;
      }

    private:
      using derived = movable_box<T>;
    };

    template <typename T>
    struct movable_box_assign_control<T, true>
    {
      movable_box_assign_control()                                  = default;
      movable_box_assign_control(const movable_box_assign_control&) = default;
      movable_box_assign_control(movable_box_assign_control&&)      = default;

      constexpr movable_box_assign_control&
          operator=(const movable_box_assign_control& other) noexcept(
              movable_box_nothrow_assignment_v<T, false>)
      {
        static_cast<derived&>(*this).assign(static_cast<const derived&>(other));
        return *this;
      }

      constexpr movable_box_assign_control&
          operator=(movable_box_assign_control&& other) noexcept(
              movable_box_nothrow_assignment_v<T, true>)
      {
        static_cast<derived&>(*this).assign(
            std::move(static_cast<derived&>(other)));
        return *this;
      }

    private:
      using derived = movable_box<T>;
    };

    template <typename T>
    struct needs_union_wrap
        : std::disjunction<
              std::negation<std::is_move_assignable<T>>,
              std::conjunction<std::negation<std::is_copy_assignable<T>>,
                               std::is_copy_constructible<T>>>
    {
    };

    template <typename T>
    struct potentially_unengaged_on_assign
        : std::disjunction<
              std::conjunction<
                  std::negation<std::is_move_assignable<T>>,
                  std::negation<std::is_nothrow_move_constructible<T>>>,
              std::conjunction<
                  std::negation<std::is_copy_assignable<T>>,
                  std::is_copy_constructible<T>,
                  std::negation<std::is_nothrow_copy_constructible<T>>>>
    {
    };

    template <typename T, typename>
    struct movable_box_storage
    {
      T value;

      static constexpr bool has_unengaged_state = false;

      movable_box_storage() = default;

      constexpr movable_box_storage(T&& value) : value(std::move(value)) {}

      constexpr movable_box_storage(const T& value) : value(value) {}

      movable_box_storage(const movable_box_storage&) = default;
      movable_box_storage(movable_box_storage&&)      = default;

      /*
       * Assignment operators are defined as no-op here because
       * movable_box_assign_control is responsible for doing the assignment.
       */
      constexpr movable_box_storage&
          operator=(const movable_box_storage&) noexcept
      {
        return *this;
      }

      constexpr movable_box_storage& operator=(movable_box_storage&&) noexcept
      {
        return *this;
      }
    };

    struct defer_engage_t
    {
    };

    inline constexpr defer_engage_t defer_engage{};

    template <typename T, bool = std::is_default_constructible_v<T>>
    struct movable_box_inner_storage;

    template <typename T>
    struct movable_box_storage<
        T, std::enable_if_t<std::conjunction_v<
               std::negation<potentially_unengaged_on_assign<T>>,
               needs_union_wrap<T>>>> : movable_box_inner_storage<T>
    {
      static constexpr bool has_unengaged_state = false;

      movable_box_storage() = default;

      constexpr movable_box_storage(T&& value) : base(std::move(value)) {}

      constexpr movable_box_storage(const T& value) : base(value) {}

      constexpr movable_box_storage(movable_box_storage&& other) noexcept(
          std::is_nothrow_move_constructible_v<T>)
          : base(std::move(other.value))
      {
      }

      /*
       * Unconditionally define both copy and move constructors. If the copy
       * constructor is not implemented for T, it is automatically deleted from
       * movable_box via movable_box_assign_control which won't define it. We do
       * however perform noexcept checks so that exception specifications are
       * properly inherited from the implicitly generated constructors in
       * movable_box.
       */
      constexpr movable_box_storage(const movable_box_storage& other) noexcept(
          std::is_nothrow_copy_constructible_v<T>)
          : base(other.value)
      {
      }

      constexpr movable_box_storage& operator=(movable_box_storage&&) noexcept
      {
        return *this;
      }

      constexpr movable_box_storage&
          operator=(const movable_box_storage&) noexcept
      {
        return *this;
      }

      utils_constexpr20 ~movable_box_storage()
      {
        std::destroy_at(std::addressof(base::value));
      }

    private:
      using base = movable_box_inner_storage<T>;
    };

    template <typename T>
    struct movable_box_storage<
        T, std::enable_if_t<potentially_unengaged_on_assign<T>::value>>
        : movable_box_inner_storage<T>
    {
      static constexpr bool has_unengaged_state = true;

      bool engaged = true;

      movable_box_storage() = default;

      constexpr movable_box_storage(T&& value) : base(std::move(value)) {}

      constexpr movable_box_storage(const T& value) : base(value) {}

      utils_constexpr20
          movable_box_storage(movable_box_storage&& other) noexcept(
              std::is_nothrow_move_constructible_v<T>)
          : base(defer_engage), engaged(false)
      {
        construct(std::move(other));
      }

      utils_constexpr20
          movable_box_storage(const movable_box_storage& other) noexcept(
              std::is_nothrow_copy_constructible_v<T>)
          : base(defer_engage), engaged(false)
      {
        construct(other);
      }

      constexpr movable_box_storage& operator=(movable_box_storage&&) noexcept
      {
        return *this;
      }

      constexpr movable_box_storage&
          operator=(const movable_box_storage&) noexcept
      {
        return *this;
      }

      utils_constexpr20 ~movable_box_storage()
      {
        if (engaged)
          std::destroy_at(std::addressof(base::value));
      }

    private:
      using base = movable_box_inner_storage<T>;

      template <typename Self>
      utils_constexpr20 void construct(Self&& other)
      {
        if (!other.engaged)
          return;
#if utils_cpp20
        std::construct_at(std::addressof(base::value),
                          std::forward<Self>(other).value);
#else
        ::new (std::addressof(base::value)) T(std::forward<Self>(other).value);
#endif
        engaged = true;
      }
    };

    template <typename T, bool>
    struct movable_box_inner_storage
    {
      union
      {
        char dummy;
        T    value;
      };

      constexpr movable_box_inner_storage(defer_engage_t) noexcept : dummy(0) {}

      constexpr movable_box_inner_storage(T&& value) : value(std::move(value))
      {
      }

      constexpr movable_box_inner_storage(const T& value) : value(value) {}

      utils_constexpr20 ~movable_box_inner_storage() noexcept {}
    };

    template <typename T>
    struct movable_box_inner_storage<T, true>
    {
      union
      {
        char dummy;
        T    value;
      };

      constexpr movable_box_inner_storage() noexcept(
          std::is_nothrow_default_constructible_v<T>)
          : value()
      {
      }

      constexpr movable_box_inner_storage(defer_engage_t) noexcept : dummy(0) {}

      constexpr movable_box_inner_storage(T&& value) : value(std::move(value))
      {
      }

      constexpr movable_box_inner_storage(const T& value) : value(value) {}

      utils_constexpr20 ~movable_box_inner_storage() noexcept {}
    };

    template <typename T, bool is_move>
    struct movable_box_nothrow_assignment
        : std::disjunction<
              std::conditional_t<is_move, std::is_nothrow_move_assignable<T>,
                                 std::is_nothrow_copy_assignable<T>>,
              std::conditional_t<
                  is_move,
                  std::conjunction<std::negation<std::is_move_assignable<T>>,
                                   std::is_nothrow_move_constructible<T>>,
                  std::conjunction<std::negation<std::is_copy_assignable<T>>,
                                   std::is_nothrow_copy_constructible<T>>>>

    {
    };
  } // namespace helpers
} // namespace alterhook::utils
