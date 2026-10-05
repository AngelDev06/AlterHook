/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <algorithm>
#include <cstddef>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <ranges>
#include <type_traits>
#include <utility>
#include "traits/iterator_traits.hpp"
#include "macros.hpp"
#include "storage.hpp"
#include "other.hpp"

namespace alterhook::utils::iter
{
  namespace helpers
  {
    template <typename ParentView, typename Itr, typename Range>
    class filter_view_iterator;
    template <typename Itr, bool = has_arrow_operator<const Itr>>
    struct select_pointer;

    template <typename T, template <typename...> typename Tmpl>
    struct is_instantiation_of_s
        : std::bool_constant<is_instantiation_of<T, Tmpl>>
    {
    };

    template <typename T>
    struct has_arrow_operator_s : std::bool_constant<has_arrow_operator<T>>
    {
    };

    template <typename Itr, typename T>
    struct arrow_ret_same_as_s
        : std::is_same<decltype(std::declval<Itr&>().operator->()), T>
    {
    };
  } // namespace helpers

  template <typename Itr>
  using select_pointer_t = typename helpers::select_pointer<Itr>::type;

  inline constexpr struct
  {
    template <typename Range>
    constexpr auto operator()(Range& range) const -> range_begin_t<Range>
    {
      using std::begin;
      return begin(range);
    }
  } begin{};

  inline constexpr struct
  {
    template <typename Range>
    constexpr auto operator()(Range& range) const -> range_end_t<Range>
    {
      using std::end;
      return end(range);
    }
  } end{};

  template <typename Itr,
            std::enable_if_t<is_valid_forward_iterator<Itr>, size_t> = 0>
  constexpr auto distance(Itr first, Itr last)
  {
    using size_type =
        std::make_unsigned_t<iter_difference_t<Itr, iter_category_t<Itr>>>;
    if constexpr (is_valid_random_access_iterator<Itr>)
      return static_cast<size_type>(last - first);
    else
    {
      size_type count = 0;
      for (Itr itr = first; !(itr == last); ++itr)
        ++count;
      return count;
    }
  }

  inline constexpr struct
  {
    template <typename Range, std::enable_if_t<is_sizeable<Range>, size_t> = 0>
    constexpr auto operator()(Range& range) const
    {
      if constexpr (helpers::has_size_impl<Range>)
      {
        using std::size;
        return size(range);
      }
      else
      {
        auto result = end(range) - begin(range);
        return static_cast<std::make_unsigned_t<decltype(result)>>(result);
      }
    }
  } size{};

  inline constexpr struct
  {
    template <typename Range, std::enable_if_t<is_emptyable<Range>, size_t> = 0>
    constexpr bool operator()(Range& range) const
    {
      if constexpr (helpers::has_empty_impl<Range>)
      {
        using std::empty;
        return empty(range);
      }
      else if constexpr (helpers::has_comparable_edges<Range>)
        return begin(range) == end(range);
      else
        return size(range) == 0;
    }
  } empty{};

  template <typename Reference>
  class pointer_wrapper
  {
    using value_type = std::remove_reference_t<Reference>;

  public:
    template <typename Callable,
              std::enable_if_t<std::is_constructible_v<
                                   value_type, std::invoke_result_t<Callable&>>,
                               size_t> = 0>
    constexpr explicit pointer_wrapper(Callable&& deref) : value(deref())
    {
    }

    constexpr value_type* operator->() noexcept
    {
      return std::addressof(value);
    }

    constexpr const value_type* operator->() const noexcept
    {
      return std::addressof(value);
    }

  private:
    value_type value;

    pointer_wrapper(const pointer_wrapper&)            = delete;
    pointer_wrapper& operator=(const pointer_wrapper&) = delete;
  };

  template <typename Callable>
  explicit pointer_wrapper(Callable&&)
      -> pointer_wrapper<std::invoke_result_t<Callable&>>;

  template <typename Derived, typename Itr, typename ExpectedVal = void,
            typename ExpectedRef = void>
  class iterator_wrapper_interface
  {
  public:
    static_assert(
        is_valid_forward_iterator<Itr>,
        "iterator_interface: can't provide an interface for an iterator that"
        "doesn't meet at least the forward iterator criteria");
    static_assert(
        std::disjunction_v<
            std::is_same<ExpectedVal, void>, std::is_same<ExpectedRef, void>,
            helpers::is_iterator_yielding_s<Itr, ExpectedVal, ExpectedRef>>,
        "iterator_interface: iterator passed doesn't yield the "
        "expected value/reference");

    using reference  = std::conditional_t<std::is_same_v<ExpectedRef, void>,
                                          iter_reference_t<Itr>, ExpectedRef>;
    using value_type = value_type_optional_type_member_of<
        Itr, std::conditional_t<std::is_same_v<ExpectedVal, void>,
                                remove_cvref_t<reference>, ExpectedVal>>;
    using pointer           = select_pointer_t<Itr>;
    using iterator_concept  = iter_category_t<Itr>;
    using iterator_category = std::conditional_t<
        std::conjunction_v<std::is_lvalue_reference<reference>,
                           std::is_same<remove_cvref_t<reference>, value_type>>,
        iterator_concept, std::input_iterator_tag>;
    using difference_type = iter_difference_t<Itr, iterator_category>;

    template <typename U = Derived,
              std::enable_if_t<
                  std::conjunction_v<
                      std::is_same<U, Derived>,
                      std::disjunction<
                          helpers::is_instantiation_of_s<typename U::pointer,
                                                         pointer_wrapper>,
                          std::conjunction<
                              std::is_lvalue_reference<typename U::reference>,
                              std::is_convertible<
                                  std::add_pointer_t<typename U::reference>,
                                  typename U::pointer>>,
                          std::is_convertible<typename U::reference,
                                              typename U::pointer>>>,
                  size_t> = 0>
    constexpr typename U::pointer operator->() const
    {
      if constexpr (is_instantiation_of<typename U::pointer, pointer_wrapper>)
        return pointer_wrapper{ [this]
                                { return *static_cast<Derived&>(*this); } };
      else if constexpr (std::conjunction_v<
                             std::is_lvalue_reference<typename U::reference>,
                             std::is_convertible<
                                 std::add_pointer_t<typename U::reference>,
                                 typename U::pointer>>)
        return std::addressof(*static_cast<const Derived&>(*this));
      else
        return *static_cast<const Derived&>(*this);
    }

    constexpr Derived operator++(int)
    {
      Derived tmp = static_cast<const Derived&>(*this);
      ++static_cast<Derived&>(*this);
      return tmp;
    }

    template <
        typename U               = Derived,
        std::enable_if_t<std::is_same_v<U, Derived> &&
                             std::is_base_of_v<std::bidirectional_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    constexpr Derived operator--(int)
    {
      Derived tmp = static_cast<const Derived&>(*this);
      --static_cast<Derived&>(*this);
      return tmp;
    }

    template <
        typename U               = Derived,
        std::enable_if_t<std::is_same_v<U, Derived> &&
                             std::is_base_of_v<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    constexpr Derived operator+(difference_type n) const
    {
      Derived tmp  = static_cast<const Derived&>(*this);
      tmp         += n;
      return tmp;
    }

    template <
        typename U               = Derived,
        std::enable_if_t<std::is_same_v<U, Derived> &&
                             std::is_base_of_v<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    friend constexpr Derived operator+(difference_type                   n,
                                       const iterator_wrapper_interface& self)
    {
      return self + n;
    }

    template <
        typename U               = Derived,
        std::enable_if_t<std::is_same_v<U, Derived> &&
                             std::is_base_of_v<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    constexpr Derived operator-(difference_type n) const
    {
      Derived tmp  = static_cast<const Derived&>(*this);
      tmp         -= n;
      return tmp;
    }

    template <
        typename U               = Derived,
        std::enable_if_t<std::is_same_v<U, Derived> &&
                             std::is_base_of_v<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    constexpr typename U::reference operator[](difference_type n) const
    {
      return *(static_cast<const Derived&>(*this) + n);
    }

    template <
        typename OtherDerived, typename OtherItr, typename OtherExpectedRef,
        std::enable_if_t<
            std::is_convertible_v<decltype(std::declval<const Derived&>() ==
                                           std::declval<const OtherDerived&>()),
                                  bool>,
            size_t> = 0>
    constexpr bool operator!=(
        const iterator_wrapper_interface<OtherDerived, OtherItr, ExpectedVal,
                                         OtherExpectedRef>& other) const
    {
      return !(static_cast<const Derived&>(*this) ==
               static_cast<const OtherDerived&>(other));
    }

    /* assuming at least one of the < and > operators is defined on Derived,
     * otherwise the bellow pairs infinitely recurse with each other*/
    template <
        typename OtherDerived, typename OtherItr, typename OtherExpectedRef,
        typename U               = Derived,
        std::enable_if_t<std::conjunction_v<
                             std::is_same<U, Derived>,
                             std::is_base_of<std::random_access_iterator_tag,
                                             iter_supplied_category_t<U>>,
                             helpers::greater_than_comparable<OtherDerived, U>>,
                         size_t> = 0>
    constexpr bool operator<(
        const iterator_wrapper_interface<OtherDerived, OtherItr, ExpectedVal,
                                         OtherExpectedRef>& other) const
    {
      return static_cast<const OtherDerived&>(other) >
             static_cast<const Derived&>(*this);
    }

    template <
        typename OtherDerived, typename OtherItr, typename OtherExpectedRef,
        typename U = Derived,
        std::enable_if_t<
            std::conjunction_v<std::is_same<U, Derived>,
                               std::is_base_of<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                               helpers::less_than_comparable<OtherDerived, U>>,
            size_t> = 0>
    constexpr bool operator>(
        const iterator_wrapper_interface<OtherDerived, OtherItr, ExpectedVal,
                                         OtherExpectedRef>& other) const
    {
      return static_cast<const OtherDerived&>(other) <
             static_cast<const Derived&>(*this);
    }

    template <
        typename OtherDerived, typename OtherItr, typename OtherExpectedRef,
        typename U               = Derived,
        std::enable_if_t<std::conjunction_v<
                             std::is_same<U, Derived>,
                             std::is_base_of<std::random_access_iterator_tag,
                                             iter_supplied_category_t<U>>,
                             helpers::greater_than_comparable<U, OtherDerived>>,
                         size_t> = 0>
    constexpr bool operator<=(
        const iterator_wrapper_interface<OtherDerived, OtherItr, ExpectedVal,
                                         OtherExpectedRef>& other) const
    {
      return !(static_cast<const Derived&>(*this) >
               static_cast<const OtherDerived&>(other));
    }

    template <
        typename OtherDerived, typename OtherItr, typename OtherExpectedRef,
        typename U = Derived,
        std::enable_if_t<
            std::conjunction_v<std::is_same<U, Derived>,
                               std::is_base_of<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                               helpers::less_than_comparable<U, OtherDerived>>,
            size_t> = 0>
    constexpr bool operator>=(
        const iterator_wrapper_interface<OtherDerived, OtherItr, ExpectedVal,
                                         OtherExpectedRef>& other) const
    {
      return !(static_cast<const Derived&>(*this) <
               static_cast<const OtherDerived&>(other));
    }
  };

  template <typename Itr, typename Derived = void, typename ExpectedVal = void,
            typename ExpectedRef = void>
  class basic_iterator_wrapper
      : public iterator_wrapper_interface<
            std::conditional_t<
                std::is_same_v<Derived, void>,
                basic_iterator_wrapper<Itr, Derived, ExpectedVal, ExpectedRef>,
                Derived>,
            Itr, ExpectedVal, ExpectedRef>
  {
    using injected_class = std::conditional_t<std::is_same_v<Derived, void>,
                                              basic_iterator_wrapper, Derived>;
    using base = iterator_wrapper_interface<injected_class, Itr, ExpectedVal,
                                            ExpectedRef>;

  public:
    constexpr explicit basic_iterator_wrapper(Itr itr) : itr(itr) {}

    template <
        typename OtherItr, typename OtherDerived, typename OtherExpectedRef,
        std::enable_if_t<
            std::conjunction_v<
                std::disjunction<
                    std::negation<std::is_same<OtherItr, Itr>>,
                    std::negation<std::is_same<OtherDerived, Derived>>,
                    std::negation<std::is_same<OtherExpectedRef, ExpectedRef>>>,
                std::is_convertible<const OtherItr&, Itr>>,
            size_t> = 0>
    constexpr basic_iterator_wrapper(
        const basic_iterator_wrapper<OtherItr, OtherDerived, ExpectedVal,
                                     OtherExpectedRef>& other)
        : itr(other.itr)
    {
    }

    basic_iterator_wrapper() = default;

    using reference = typename base::reference;

    constexpr reference operator*() const { return *itr; }

    template <
        typename U = injected_class, typename B = base, typename I = Itr,
        std::enable_if_t<
            std::conjunction_v<
                std::is_same<U, injected_class>, std::is_same<B, base>,
                std::is_same<I, Itr>,
                std::disjunction<
                    std::conjunction<helpers::has_arrow_operator_s<const I>,
                                     helpers::arrow_ret_same_as_s<
                                         const I, typename U::pointer>>,
                    helpers::has_arrow_operator_s<const B>>>,
            size_t> = 0>
    constexpr typename U::pointer operator->() const
    {
      if constexpr (std::conjunction_v<
                        helpers::has_arrow_operator_s<const Itr>,
                        helpers::arrow_ret_same_as_s<
                            const Itr, typename injected_class::pointer>>)
        return itr.operator->();
      else
        return base::operator->();
    }

    constexpr injected_class& operator++()
    {
      ++itr;
      return static_cast<injected_class&>(*this);
    }

    using base::operator++;

    template <
        typename U               = injected_class,
        std::enable_if_t<std::is_same_v<U, injected_class> &&
                             std::is_base_of_v<std::bidirectional_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    constexpr injected_class& operator--()
    {
      --itr;
      return static_cast<injected_class&>(*this);
    }

    using base::operator--;

    template <
        typename U               = injected_class,
        std::enable_if_t<std::is_same_v<U, injected_class> &&
                             std::is_base_of_v<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    constexpr typename U::difference_type
        operator-(const injected_class& other) const
    {
      return itr - other.itr;
    }

    using base::operator-;

    template <
        typename U               = injected_class,
        std::enable_if_t<std::is_same_v<U, injected_class> &&
                             std::is_base_of_v<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    constexpr injected_class& operator+=(typename U::difference_type n)
    {
      itr += n;
      return static_cast<injected_class&>(*this);
    }

    template <
        typename U               = injected_class,
        std::enable_if_t<std::is_same_v<U, injected_class> &&
                             std::is_base_of_v<std::random_access_iterator_tag,
                                               iter_supplied_category_t<U>>,
                         size_t> = 0>
    constexpr injected_class& operator-=(typename U::difference_type n)
    {
      itr -= n;
      return static_cast<injected_class&>(*this);
    }

    template <typename OtherItr, typename OtherDerived,
              typename OtherExpectedRef,
              std::enable_if_t<
                  std::disjunction_v<helpers::equal_comparable<Itr, OtherItr>,
                                     helpers::equal_comparable<OtherItr, Itr>>,
                  size_t> = 0>
    constexpr bool operator==(
        const basic_iterator_wrapper<OtherItr, OtherDerived, ExpectedVal,
                                     OtherExpectedRef>& other) const
    {
      if constexpr (helpers::equal_comparable<Itr, OtherItr>::value)
        return itr == other.itr;
      else
        return other.itr == itr;
    }

    template <typename OtherItr, typename OtherDerived,
              typename OtherExpectedRef, typename U = injected_class,
              std::enable_if_t<
                  std::conjunction_v<
                      std::is_same<U, Derived>,
                      std::is_base_of<std::random_access_iterator_tag,
                                      iter_supplied_category_t<U>>,
                      std::disjunction<
                          helpers::less_than_comparable<Itr, OtherItr>,
                          helpers::greater_than_comparable<OtherItr, Itr>>>,
                  size_t> = 0>
    constexpr bool operator<(
        const basic_iterator_wrapper<OtherItr, OtherDerived, ExpectedVal,
                                     OtherExpectedRef>& other) const
    {
      if constexpr (helpers::less_than_comparable<Itr, OtherItr>::value)
        return itr < other.itr;
      else
        return other.itr > itr;
    }

    template <typename U               = injected_class,
              std::enable_if_t<std::is_same_v<U, injected_class> &&
                                   std::is_void_v<Derived>,
                               size_t> = 0>
    constexpr Itr unwrap() const
    {
      return itr;
    }

  protected:
    Itr itr;

    template <typename, typename, typename, typename>
    friend class basic_iterator_wrapper;
  };

#if defined(__cpp_lib_ranges) && __cpp_lib_ranges >= 201'911L
  template <typename Derived>
  class basic_view : public std::ranges::view_interface<Derived>
  {
  };
#else
  template <typename Derived>
  class basic_view
  {
    template <typename U>
    using diff_t =
        iter_difference_t<decltype(begin(std::declval<U&>())),
                          iter_category_t<decltype(begin(std::declval<U&>()))>>;
    template <typename U>
    static constexpr bool activate_empty =
        std::disjunction_v<std::bool_constant<range_has_comparable_edges<U>>,
                           helpers::range_has_computable_size_s<U>>;

  public:
    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   has_valid_forward_iterators<const U>,
                               size_t> = 0>
    constexpr decltype(auto) cbegin() const
    {
      return begin(static_cast<const Derived&>(*this));
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   has_valid_forward_iterators<const U>,
                               size_t> = 0>
    constexpr decltype(auto) cend() const
    {
      return end(static_cast<const Derived&>(*this));
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   range_has_computable_size<U>,
                               size_t> = 0>
    constexpr auto size()
    {
      return size_impl(*this);
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   range_has_computable_size<const U>,
                               size_t> = 0>
    constexpr auto size() const
    {
      return size_impl(*this);
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> && activate_empty<U>,
                               size_t> = 0>
    constexpr bool empty()
    {
      return empty_impl(*this);
    }

    template <
        typename U               = Derived,
        std::enable_if_t<std::is_same_v<U, Derived> && activate_empty<const U>,
                         size_t> = 0>
    constexpr bool empty() const
    {
      return empty_impl(*this);
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> && activate_empty<U>,
                               size_t> = 0>
    constexpr explicit operator bool()
    {
      return !empty();
    }

    template <
        typename U               = Derived,
        std::enable_if_t<std::is_same_v<U, Derived> && activate_empty<const U>,
                         size_t> = 0>
    constexpr explicit operator bool() const
    {
      return !empty();
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   has_valid_forward_iterators<U>,
                               size_t> = 0>
    constexpr decltype(auto) front()
    {
      return *begin(static_cast<Derived&>(*this));
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   has_valid_forward_iterators<const U>,
                               size_t> = 0>
    constexpr decltype(auto) front() const
    {
      return *begin(static_cast<const Derived&>(*this));
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   has_valid_bidirectional_iterators<U>,
                               size_t> = 0>
    constexpr decltype(auto) back()
    {
      return *std::prev(end(static_cast<Derived&>(*this)));
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   has_valid_bidirectional_iterators<const U>,
                               size_t> = 0>
    constexpr decltype(auto) back() const
    {
      return *std::prev(end(static_cast<const Derived&>(*this)));
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   has_valid_random_access_iterators<U>,
                               size_t> = 0>
    constexpr decltype(auto) operator[](diff_t<U> n)
    {
      auto tmp  = begin(static_cast<Derived&>(*this));
      tmp      += n;
      return *tmp;
    }

    template <typename U               = Derived,
              std::enable_if_t<std::is_same_v<U, Derived> &&
                                   has_valid_random_access_iterators<const U>,
                               size_t> = 0>
    constexpr decltype(auto) operator[](diff_t<U> n) const
    {
      auto tmp  = begin(static_cast<const Derived&>(*this));
      tmp      += n;
      return *tmp;
    }

  private:
    template <typename Self>
    using derived_t =
        std::conditional_t<std::is_const_v<Self>, const Derived, Derived>;

    template <typename Self>
    static constexpr auto size_impl(Self& self)
    {
      auto& dself  = static_cast<derived_t<Self>&>(self);
      auto  result = end(dself) - begin(dself);
      return static_cast<std::make_unsigned_t<decltype(result)>>(result);
    }

    template <typename Self>
    static constexpr bool empty_impl(Self& self)
    {
      if constexpr (range_has_comparable_edges<derived_t<Self>>)
      {
        auto& dself = static_cast<derived_t<Self>&>(self);
        return end(dself) == begin(dself);
      }
      else
        return size_impl(self) == 0;
    }
  };
#endif

  template <typename Derived, typename ParentView, typename Range>
  class basic_view_iterator
      : public basic_iterator_wrapper<
            range_iterator_t<Range>, Derived,
            value_type_optional_type_member_of<Range, void>,
            helpers::optional_possible_reference_t<Range>>
  {
    using wrapped_itr = range_iterator_t<Range>;
    using base =
        basic_iterator_wrapper<wrapped_itr, Derived,
                               value_type_optional_type_member_of<Range, void>,
                               helpers::optional_possible_reference_t<Range>>;

  public:
    constexpr explicit basic_view_iterator(ParentView& view, wrapped_itr itr)
        : base(itr), pview(&view)
    {
    }

    template <typename OtherDerived, typename OtherRange,
              std::enable_if_t<
                  std::conjunction_v<
                      std::disjunction<
                          std::negation<std::is_same<OtherDerived, Derived>>,
                          std::negation<std::is_same<OtherRange, Range>>>,
                      std::is_convertible<
                          const typename basic_view_iterator<
                              OtherDerived, ParentView, OtherRange>::base&,
                          base>>,
                  size_t> = 0>
    constexpr basic_view_iterator(
        const basic_view_iterator<OtherDerived, ParentView, OtherRange>& other)
        : base(other), pview(other.pview)
    {
    }

    basic_view_iterator() = default;

  protected:
    ParentView* pview = nullptr;

    template <typename, typename, typename>
    friend class basic_view_iterator;
  };

  template <typename Range, typename Pred>
  class filter_view : public basic_view<filter_view<Range, Pred>>
  {
  public:
    static_assert(has_valid_forward_iterators<Range>,
                  "utils::filter_view: invalid range used");

    using base_iterator = range_iterator_t<Range>;
    using iterator =
        helpers::filter_view_iterator<filter_view, base_iterator, Range>;

    constexpr explicit filter_view(Range& range, Pred&& pred)
        : prange(&range), pred(std::move(pred))
    {
    }

    template <typename U               = Pred,
              std::enable_if_t<std::is_same_v<U, Pred> &&
                                   std::is_copy_constructible_v<U>,
                               size_t> = 0>
    constexpr explicit filter_view(Range& range, const Pred& pred)
        : prange(&range), pred(pred)
    {
    }

    filter_view() = default;

    constexpr iterator begin()
    {
      if (!cached_begin)
        cached_begin = std::find_if(raw_begin(), raw_end(), std::ref(*pred));
      return iterator{ *this, *cached_begin };
    }

    constexpr iterator end() { return iterator{ *this, raw_end() }; }

  private:
    Range*                       prange = nullptr;
    movable_box<Pred>            pred;
    std::optional<base_iterator> cached_begin;

    template <typename, typename, typename>
    friend class helpers::filter_view_iterator;

    constexpr base_iterator raw_begin()
    {
      utils_assert(prange, "utils::filter_view: accessing iterators of an "
                           "uninitialized instance");
      return iter::begin(*prange);
    }

    constexpr base_iterator raw_end()
    {
      utils_assert(prange, "utils::filter_view: accessing iterators of an "
                           "uninitialized instance");
      return iter::end(*prange);
    }
  };

  template <typename Range, typename Functor>
  class transform_view : public basic_view<transform_view<Range, Functor>>
  {
    template <bool const_qualified>
    class iterator;
    template <typename R>
    using iterator_t = iterator<std::is_const_v<R>>;

  public:
    constexpr explicit transform_view(Range& range, Functor&& func)
        : prange(&range), func(std::move(func))
    {
    }

    template <typename F               = Functor,
              std::enable_if_t<std::is_same_v<F, Functor> &&
                                   std::is_copy_constructible_v<F>,
                               size_t> = 0>
    constexpr explicit transform_view(Range& range, const Functor& func)
        : prange(&range), func(func)
    {
    }

    transform_view() = default;

    template <typename R               = Range,
              std::enable_if_t<std::is_same_v<R, Range> &&
                                   has_valid_forward_iterators<R>,
                               size_t> = 0>
    constexpr iterator_t<R> begin()
    {
      return iterator_t<R>{ *this, iter::begin(*prange) };
    }

    template <typename R               = Range,
              std::enable_if_t<std::is_same_v<R, Range> &&
                                   has_valid_forward_iterators<R>,
                               size_t> = 0>
    constexpr iterator_t<R> end()
    {
      return iterator_t<R>{ *this, iter::end(*prange) };
    }

    template <
        typename R               = const Range,
        std::enable_if_t<std::conjunction_v<
                             std::is_same<R, const Range>,
                             helpers::has_valid_forward_iterators_s<R>,
                             std::is_invocable<
                                 const Functor&,
                                 decltype(*std::declval<range_begin_t<R>&>())>>,
                         size_t> = 0>
    constexpr iterator_t<R> begin() const
    {
      return iterator_t<R>{ *this,
                            iter::begin(static_cast<const Range&>(*prange)) };
    }

    template <
        typename R               = const Range,
        std::enable_if_t<std::conjunction_v<
                             std::is_same<R, const Range>,
                             helpers::has_valid_forward_iterators_s<R>,
                             std::is_invocable<
                                 const Functor&,
                                 decltype(*std::declval<range_begin_t<R>&>())>>,
                         size_t> = 0>
    constexpr iterator_t<R> end() const
    {
      return iterator_t<R>{ *this,
                            iter::end(static_cast<const Range&>(*prange)) };
    }

    template <typename R               = Range,
              std::enable_if_t<std::is_same_v<R, Range> && is_sizeable<R>,
                               size_t> = 0>
    constexpr auto size()
    {
      return iter::size(*prange);
    }

    template <typename R               = const Range,
              std::enable_if_t<std::is_same_v<R, const Range> && is_sizeable<R>,
                               size_t> = 0>
    constexpr auto size() const
    {
      return iter::size(static_cast<const Range&>(*prange));
    }

  private:
    Range*               prange = nullptr;
    movable_box<Functor> func;
  };

  template <typename Range, typename Functor>
  template <bool const_qualified>
  class transform_view<Range, Functor>::iterator
      : public basic_view_iterator<
            iterator<const_qualified>,
            std::conditional_t<const_qualified, const transform_view,
                               transform_view>,
            std::conditional_t<const_qualified, const Range, Range>>
  {
    using range_type = std::conditional_t<const_qualified, const Range, Range>;
    using view_type  = std::conditional_t<const_qualified, const transform_view,
                                          transform_view>;
    using functor_type =
        std::conditional_t<const_qualified, const Functor, Functor>;

  public:
    using base_iterator = range_begin_t<range_type>;

  private:
    using base = basic_view_iterator<iterator, view_type, range_type>;

  public:
    static_assert(std::is_invocable_v<functor_type&, typename base::reference>,
                  "utils::iter::transform_view: invalid functor");
    static_assert(
        !std::is_void_v<
            std::invoke_result_t<functor_type&, typename base::reference>>,
        "utils::iter::transform_view: Functor cannot return void");
    using reference =
        std::invoke_result_t<functor_type&, typename base::reference>;
    using pointer    = std::conditional_t<std::is_lvalue_reference_v<reference>,
                                          std::add_pointer_t<reference>,
                                          pointer_wrapper<reference>>;
    using value_type = remove_cvref_t<reference>;
    using iterator_category =
        std::conditional_t<std::is_lvalue_reference_v<reference>,
                           typename base::iterator_category,
                           std::input_iterator_tag>;

    using base::base;

    constexpr reference operator*() const
    {
      return (*base::pview->func)(base::operator*());
    }
  };

  namespace helpers
  {
    template <typename ParentView, typename Itr, typename Range>
    class filter_view_iterator
        : public basic_view_iterator<
              filter_view_iterator<ParentView, Itr, Range>, ParentView, Range>
    {
      using base =
          basic_view_iterator<filter_view_iterator<ParentView, Itr, Range>,
                              ParentView, Range>;
      template <typename Category>
      using limit_category_t = std::conditional_t<
          std::is_base_of_v<std::bidirectional_iterator_tag, Category>,
          std::bidirectional_iterator_tag, Category>;

    public:
      using iterator_concept =
          limit_category_t<typename base::iterator_concept>;
      using iterator_category =
          limit_category_t<typename base::iterator_category>;

      using base::base;

      constexpr decltype(auto) operator*() const
      {
        assert_dereferencable();
        return base::operator*();
      }

      constexpr filter_view_iterator& operator++()
      {
        assert_forward_traversal();
        base::itr = std::find_if(std::next(base::itr), base::pview->raw_end(),
                                 std::ref(*base::pview->pred));
        return *this;
      }

      using base::operator++;

      template <typename U = filter_view_iterator,
                std::enable_if_t<
                    std::is_same_v<U, filter_view_iterator> &&
                        std::is_base_of_v<std::bidirectional_iterator_tag,
                                          typename U::iterator_concept>,
                    size_t> = 0>
      constexpr filter_view_iterator& operator--()
      {
        assert_usable();
        base::itr = assert_and_fix_backwards_traversal(std::find_if(
            std::reverse_iterator(basic_iterator_wrapper(base::itr)),
            std::reverse_iterator(
                basic_iterator_wrapper(base::pview->raw_begin())),
            std::ref(*base::pview->pred)));
        return *this;
      }

      using base::operator--;

      constexpr bool operator==(const filter_view_iterator& other) const
      {
        assert_compatible(other);
        return base::operator==(other);
      }

    protected:
      constexpr void assert_dereferencable() const noexcept
      {
        assert_usable();
        utils_assert(base::itr != base::pview->raw_end(),
                     "utils::filter_iterator: cannot dereference "
                     "the end iterator");
      }

      constexpr void assert_usable() const noexcept
      {
        utils_assert(base::pview, "utils::filter_iterator: attempted use of an "
                                  "uninitialized iterator");
        utils_assert(base::itr == base::pview->raw_end() ||
                         (*base::pview->pred)(*base::itr),
                     "utils::filter_iterator: cannot use logically invalidated "
                     "iterator");
      }

      constexpr void assert_forward_traversal() const noexcept
      {
        assert_usable();
        utils_assert(base::itr != base::pview->raw_end(),
                     "utils::filter_iterator: cannot increment past end");
      }

      template <typename WrappedItr>
      constexpr Itr assert_and_fix_backwards_traversal(
          std::reverse_iterator<WrappedItr> r_found) const noexcept
      {
        utils_assert(r_found != std::reverse_iterator(basic_iterator_wrapper(
                                    base::pview->raw_begin())),
                     "utils::filter_iterator: cannot decrement past first "
                     "valid element");
        return std::prev(r_found.base().unwrap());
      }

      constexpr void
          assert_compatible(const filter_view_iterator& other) const noexcept
      {
        utils_assert(base::pview == other.pview,
                     "utils::filter_iterator: iterators incompatible");
      }
    };

    template <typename Itr, typename = void>
    struct select_pointer_impl
    {
      using ref = iter_reference_t<Itr>;
      using type =
          std::conditional_t<std::is_lvalue_reference_v<ref>,
                             std::add_pointer_t<ref>, pointer_wrapper<ref>>;
    };

    template <typename Itr>
    struct select_pointer_impl<Itr, std::void_t<typename Itr::pointer>>
    {
      using type = typename Itr::pointer;
    };

    template <typename Itr, bool>
    struct select_pointer : select_pointer_impl<Itr>
    {
    };

    template <typename Itr>
    struct select_pointer<Itr, true>
    {
      using type = decltype(std::declval<Itr&>().operator->());
    };
  } // namespace helpers
} // namespace alterhook::utils::iter
