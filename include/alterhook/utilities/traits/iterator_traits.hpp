/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <concepts>
#include <cstddef>
#include <iterator>
#include <type_traits>
#include <utility>
#include "../macros.hpp"
#include "../other.hpp"
#include "../tuple_tools.hpp"

namespace alterhook::utils::iter
{
  namespace helpers
  {
    template <typename Itr, typename = void>
    struct iter_reference;
    template <typename itr, typename iterator_category>
    struct iter_difference_type;
    template <typename Itr, typename = void>
    struct iter_category;
    template <typename Itr, typename = void>
    struct iter_supplied_category;
    template <typename T, typename ExpectedVal, typename ExpectedRef>
    struct is_iterator_yielding_s;
    template <typename T>
    struct has_valid_forward_iterators_s;
    template <typename T>
    struct range_has_computable_size_s;
    template <typename Range, bool = std::is_const_v<Range>>
    struct range_possible_reference;
    template <typename Range, typename = void>
    struct optional_possible_reference;

    template <typename Range>
    using optional_possible_reference_t = typename optional_possible_reference<
        std::remove_reference_t<Range>>::type;

    namespace adl
    {
      using std::begin;
      using std::empty;
      using std::end;
      using std::rbegin;
      using std::rend;
      using std::size;

      template <typename T>
      using adl_begin_t = decltype(begin(std::declval<T&>()));
      template <typename T>
      using adl_end_t = decltype(end(std::declval<T&>()));
      template <typename T>
      using adl_rbegin_t = decltype(rbegin(std::declval<T&>()));
      template <typename T>
      using adl_rend_t = decltype(rend(std::declval<T&>()));
      template <typename T>
      using adl_size_t = decltype(size(std::declval<T&>()));
      template <typename T>
      using adl_empty_t = decltype(empty(std::declval<T&>()));
    } // namespace adl
  } // namespace helpers

  template <typename Itr>
  using iter_reference_t =
      typename helpers::iter_reference<remove_cvref_t<Itr>>::type;
  template <typename itr, typename iterator_category>
  using iter_difference_t =
      typename helpers::iter_difference_type<remove_cvref_t<itr>,
                                             iterator_category>::type;
  template <typename Itr>
  using iter_category_t = typename helpers::iter_category<Itr>::type;
  template <typename Itr>
  using iter_supplied_category_t =
      typename helpers::iter_supplied_category<remove_cvref_t<Itr>>::type;
  template <typename Range>
  using range_possible_reference_t = typename helpers::range_possible_reference<
      std::remove_reference_t<Range>>::type;

#if defined(__cpp_lib_concepts) && __cpp_lib_concepts >= 201'907L
  namespace helpers
  {
    template <typename T>
    concept is_forward_iterable_impl = requires {
      typename adl::adl_begin_t<T>;
      typename adl::adl_end_t<T>;
    };

    template <typename Itr>
    concept has_ref_type_member = requires { typename Itr::reference; };

    template <typename DerefType, typename Itr, typename ExpectedRef>
    concept yields_reference =
        ((has_ref_type_member<Itr> &&
          std::same_as<DerefType, typename Itr::reference>) ||
         !has_ref_type_member<Itr>) &&
        std::convertible_to<DerefType, ExpectedRef>;

    template <typename Itr, typename ExpectedVal>
    concept optionally_yields_expected_value =
        !requires { typename Itr::value_type; } ||
        std::same_as<typename Itr::value_type, ExpectedVal> ||
        std::convertible_to<typename Itr::value_type, ExpectedVal>;

    template <typename Itr, typename ExpectedVal, typename ExpectedRef>
    concept is_iterator_yielding_impl =
        optionally_yields_expected_value<Itr, ExpectedVal> &&
        requires(const Itr cit) {
          { *cit } -> yields_reference<Itr, ExpectedRef>;
        };

    template <typename Itr>
    concept is_valid_forward_iterator_impl =
        std::is_default_constructible_v<Itr> &&
        std::is_copy_constructible_v<Itr> && std::is_copy_assignable_v<Itr> &&
        requires(Itr it, const Itr cit) {
          *cit;
          { ++it } -> std::same_as<Itr&>;
          { cit == cit } -> std::convertible_to<bool>;
        };

    template <typename Itr, typename Range>
    concept optionally_associated_with_range =
        !requires { typename Range::value_type; } ||
        is_iterator_yielding_impl<Itr, typename Range::value_type,
                                  range_possible_reference_t<Range>>;

    template <typename BeginItr, typename EndItr, typename Range>
    concept forward_range_iterators_requirements =
        std::same_as<BeginItr, EndItr> &&
        is_valid_forward_iterator_impl<BeginItr> &&
        optionally_associated_with_range<BeginItr, Range>;

    template <typename T>
    concept has_valid_forward_iterators_impl =
        requires {
          typename adl::adl_begin_t<T>;
          typename adl::adl_end_t<T>;
        } && forward_range_iterators_requirements<adl::adl_begin_t<T>,
                                                  adl::adl_end_t<T>, T>;

    template <typename T>
    concept has_valid_forward_local_iterators_impl =
        requires(T& map, size_type_member_or_size_t<T> n) {
          map.end(n);
          {
            map.begin(n)
          } -> forward_range_iterators_requirements<decltype(map.end(n)), T>;
        };

    template <typename Itr>
    concept is_valid_bidirectional_iterator_impl =
        is_valid_forward_iterator_impl<Itr> && requires(Itr it) {
          { --it } -> std::same_as<Itr&>;
        };

    template <typename T>
    concept has_valid_bidirectional_iterators_impl =
        has_valid_forward_iterators_impl<T> &&
        is_valid_bidirectional_iterator_impl<adl::adl_begin_t<T>>;

    template <typename T>
    concept signed_integral = std::is_integral_v<T> && std::is_signed_v<T>;

    template <typename itr>
    concept has_random_access_ordering_requirements_impl =
        requires(const itr cit) {
          { cit < cit } -> std::convertible_to<bool>;
        } || requires(const itr cit) {
          { cit > cit } -> std::convertible_to<bool>;
        };

    template <typename itr, typename diff_t>
    concept same_as_optional_difference_type_member = !requires {
      typename itr::difference_type;
    } || std::is_same_v<diff_t, typename itr::difference_type>;

    template <typename Itr>
    concept is_valid_random_access_iterator_impl =
        is_valid_bidirectional_iterator_impl<Itr> &&
        has_random_access_ordering_requirements_impl<Itr> &&
        requires(Itr it, const Itr cit) {
          { cit - cit } -> signed_integral;
          requires same_as_optional_difference_type_member<Itr,
                                                           decltype(cit - cit)>;
          { it += (cit - cit) } -> std::same_as<Itr&>;
          { it -= (cit - cit) } -> std::same_as<Itr&>;
        };

    template <typename T>
    concept has_valid_random_access_iterators_impl =
        has_valid_bidirectional_iterators_impl<T> &&
        is_valid_random_access_iterator_impl<adl::adl_begin_t<T>>;

    template <typename T>
    concept has_less_than_operator_impl = requires(const T v) { v < v; };

    template <typename T>
    concept has_size_impl = requires { typename adl::adl_size_t<T>; };

    template <typename T>
    concept can_compute_size =
        requires(adl::adl_begin_t<T> first, adl::adl_end_t<T> last) {
          { last - first } -> std::signed_integral;
        };

    template <typename T>
    concept is_sizeable_impl = has_size_impl<T> || can_compute_size<T>;

    template <typename T>
    concept has_empty_impl = requires {
      typename adl::adl_empty_t<T>;
      requires std::same_as<adl::adl_empty_t<T>, bool>;
    };

    template <typename T>
    concept has_comparable_edges =
        requires(adl::adl_begin_t<T> first, adl::adl_end_t<T> last) {
          { first == last } -> std::same_as<bool>;
        };

    template <typename T>
    concept is_emptyable_impl =
        has_empty_impl<T> || has_comparable_edges<T> || is_sizeable_impl<T>;

    template <typename Itr>
    concept has_arrow_operator_impl = requires(Itr itr) { itr.operator->(); };

    template <typename T, typename Range>
    concept is_iterator_of = requires { typename adl::adl_begin_t<T>; } &&
                             std::same_as<T, adl::adl_begin_t<T>>;

    template <typename T, typename Range>
    concept is_any_iterator_of =
        is_iterator_of<T, Range> || is_iterator_of<T, const Range>;

    template <typename T, typename Range>
    concept is_iterator_pair_of =
        requires { typename adl::adl_begin_t<Range>; } &&
        std::is_copy_constructible_v<remove_cvref_t<T>> &&
        tuple_unpacks_to<T, adl::adl_begin_t<Range>, adl::adl_begin_t<Range>>;

    template <typename T, typename Range>
    concept is_any_iterator_pair_of =
        is_iterator_pair_of<T, Range> || is_iterator_pair_of<T, const Range>;

    template <typename T, typename Range>
    concept converts_to_iterator_of = requires {
      typename adl::adl_begin_t<Range>;
    } && std::convertible_to<T, adl::adl_begin_t<Range>>;

    template <typename T, typename Range>
    concept converts_to_any_iterator_of =
        converts_to_iterator_of<T, Range> ||
        converts_to_iterator_of<T, const Range>;
  } // namespace helpers
#else
  namespace helpers
  {
    template <typename T, typename = void>
    constexpr bool is_forward_iterable_impl = false;
    template <typename T>
    constexpr bool is_forward_iterable_impl<
        T, std::void_t<adl::adl_begin_t<T>, adl::adl_end_t<T>>> = true;

    template <typename Itr, typename = void>
    constexpr bool has_ref_type_member = false;
    template <typename Itr>
    constexpr bool
        has_ref_type_member<Itr, std::void_t<typename Itr::reference>> = true;

    template <typename DerefType, typename Itr>
    struct same_as_ref : std::is_same<DerefType, typename Itr::reference>
    {
    };

    template <typename Itr, typename ExpectedVal, typename = void>
    constexpr bool optionally_yields_expected_value = true;
    template <typename Itr, typename ExpectedVal>
    constexpr bool optionally_yields_expected_value<
        Itr, ExpectedVal, std::void_t<typename Itr::value_type>> =
        std::disjunction_v<
            std::is_same<typename Itr::value_type, ExpectedVal>,
            std::is_convertible<typename Itr::value_type, ExpectedVal>>;

    template <typename DerefType, typename Itr, typename ExpectedRef>
    constexpr bool yields_reference = std::conjunction_v<
        std::conditional_t<has_ref_type_member<Itr>,
                           same_as_ref<DerefType, Itr>, std::true_type>,
        std::is_convertible<DerefType, ExpectedRef>>;

    template <typename DerefType, typename Itr, typename ExpectedRef>
    struct yields_reference_s
        : std::bool_constant<yields_reference<DerefType, Itr, ExpectedRef>>
    {
    };

    template <typename Itr, typename ExpectedVal, typename ExpectedRef,
              typename = void>
    constexpr bool is_iterator_yielding_impl = false;
    template <typename Itr, typename ExpectedVal, typename ExpectedRef>
    constexpr bool is_iterator_yielding_impl<
        Itr, ExpectedVal, ExpectedRef,
        std::enable_if_t<std::conjunction_v<
            std::bool_constant<
                optionally_yields_expected_value<Itr, ExpectedVal>>,
            yields_reference_s<decltype(*std::declval<const Itr&>()), Itr,
                               ExpectedRef>>>> = true;

    template <typename itr, typename = void>
    constexpr bool is_valid_forward_iterator_impl = false;
    template <typename Itr>
    constexpr bool is_valid_forward_iterator_impl<
        Itr,
        std::enable_if_t<
            std::is_same_v<decltype(++std::declval<Itr&>()), Itr&> &&
                std::is_convertible_v<decltype(std::declval<const Itr&>() ==
                                               std::declval<const Itr&>()),
                                      bool>,
            std::void_t<decltype(*std::declval<const Itr&>())>>> =
        std::is_default_constructible_v<Itr> &&
        std::is_copy_constructible_v<Itr> && std::is_copy_assignable_v<Itr>;

    template <typename Itr>
    struct is_valid_forward_iterator_impl_s
        : std::bool_constant<is_valid_forward_iterator_impl<Itr>>
    {
    };

    template <typename Itr, typename Range>
    struct is_associated_with_range
        : std::bool_constant<
              is_iterator_yielding_impl<Itr, typename Range::value_type,
                                        range_possible_reference_t<Range>>>
    {
    };

    template <typename T, typename = void>
    struct has_value_type : std::false_type
    {
    };

    template <typename T>
    struct has_value_type<T, std::void_t<typename T::value_type>>
        : std::true_type
    {
    };

    template <typename BeginItr, typename EndItr, typename Range>
    constexpr bool forward_range_iterators_requirements = std::conjunction_v<
        std::is_same<BeginItr, EndItr>,
        is_valid_forward_iterator_impl_s<BeginItr>,
        std::disjunction<std::negation<has_value_type<Range>>,
                         is_associated_with_range<BeginItr, Range>>>;

    template <typename T, typename = void>
    constexpr bool has_valid_forward_iterators_impl = false;
    template <typename T>
    constexpr bool has_valid_forward_iterators_impl<
        T, std::enable_if_t<forward_range_iterators_requirements<
               adl::adl_begin_t<T>, adl::adl_end_t<T>, T>>> = true;

    template <typename T>
    using local_begin_t = decltype(std::declval<T&>().begin(
        std::declval<size_type_member_or_size_t<T>>()));
    template <typename T>
    using local_end_t = decltype(std::declval<T&>().end(
        std::declval<size_type_member_or_size_t<T>>()));

    template <typename T, typename = void>
    constexpr bool has_valid_forward_local_iterators_impl = false;
    template <typename T>
    constexpr bool has_valid_forward_local_iterators_impl<
        T, std::enable_if_t<forward_range_iterators_requirements<
               local_begin_t<T>, local_end_t<T>, T>>> = true;

    template <typename Itr, typename = void>
    constexpr bool is_valid_bidirectional_iterator_impl = false;
    template <typename Itr>
    constexpr bool is_valid_bidirectional_iterator_impl<
        Itr, std::enable_if_t<
                 std::is_same_v<decltype(--std::declval<Itr&>()), Itr&>>> =
        is_valid_forward_iterator_impl<Itr>;

    template <typename T, typename = void>
    constexpr bool has_valid_bidirectional_iterators_impl = false;
    template <typename T>
    constexpr bool has_valid_bidirectional_iterators_impl<
        T, std::enable_if_t<
               is_valid_bidirectional_iterator_impl<adl::adl_begin_t<T>>>> =
        has_valid_forward_iterators_impl<T>;

    template <typename T>
    constexpr bool signed_integral =
        std::is_integral_v<T> && std::is_signed_v<T>;

    template <typename T, typename = void>
    struct has_greater_than_impl : std::false_type
    {
    };

    template <typename T>
    struct has_greater_than_impl<
        T, std::void_t<decltype(bool(std::declval<const T&>() >
                                     std::declval<const T&>()))>>
        : std::true_type
    {
    };

    template <typename T, typename = void>
    struct has_less_than_impl : std::false_type
    {
    };

    template <typename T>
    struct has_less_than_impl<
        T, std::void_t<decltype(bool(std::declval<const T&>() <
                                     std::declval<const T&>()))>>
        : std::true_type
    {
    };

    template <typename T>
    constexpr bool has_random_access_ordering_requirements_impl =
        std::disjunction_v<has_less_than_impl<T>, has_greater_than_impl<T>>;

    template <typename itr, typename diff_t, typename = void>
    constexpr bool same_as_optional_difference_type_member = true;
    template <typename itr, typename diff_t>
    constexpr bool same_as_optional_difference_type_member<
        itr, diff_t, std::void_t<typename itr::difference_type>> =
        std::is_same_v<diff_t, typename itr::difference_type>;

    template <typename Itr, typename Diff, typename = void>
    constexpr bool is_valid_random_access_iterator_impl2 = false;
    template <typename Itr, typename Diff>
    constexpr bool is_valid_random_access_iterator_impl2<
        Itr, Diff,
        std::enable_if_t<
            signed_integral<Diff> &&
            same_as_optional_difference_type_member<Itr, Diff> &&
            std::is_same_v<
                decltype(std::declval<Itr&>() += std::declval<Diff>()), Itr&> &&
            std::is_same_v<decltype(std::declval<Itr&>() -=
                                    std::declval<Diff>()),
                           Itr&>>> = true;

    template <typename Itr, typename = void>
    constexpr bool is_valid_random_access_iterator_impl = false;
    template <typename Itr>
    constexpr bool is_valid_random_access_iterator_impl<
        Itr, std::enable_if_t<is_valid_random_access_iterator_impl2<
                 Itr, decltype(std::declval<const Itr&>() -
                               std::declval<const Itr&>())>>> =
        is_valid_bidirectional_iterator_impl<Itr> &&
        has_random_access_ordering_requirements_impl<Itr>;

    template <typename T, typename = void>
    constexpr bool has_valid_random_access_iterators_impl = false;
    template <typename T>
    constexpr bool has_valid_random_access_iterators_impl<
        T, std::enable_if_t<
               is_valid_random_access_iterator_impl<adl::adl_begin_t<T>>>> =
        has_valid_bidirectional_iterators_impl<T>;

    template <typename T, typename = void>
    constexpr bool has_less_than_operator_impl = false;
    template <typename T>
    constexpr bool has_less_than_operator_impl<
        T, std::void_t<decltype(std::declval<const T&>() <
                                std::declval<const T&>())>> = true;

    template <typename T>
    constexpr bool unsigned_integral_impl =
        std::is_integral_v<T> && std::is_unsigned_v<T>;

    template <typename T, typename = void>
    constexpr bool has_size_impl = false;
    template <typename T>
    constexpr bool has_size_impl<
        T, std::enable_if_t<unsigned_integral_impl<adl::adl_size_t<T>>>> = true;

    template <typename T, typename = void>
    constexpr bool can_compute_size = false;
    template <typename T>
    constexpr bool can_compute_size<
        T, std::enable_if_t<signed_integral<
               decltype(std::declval<adl::adl_end_t<T>>() -
                        std::declval<adl::adl_begin_t<T>>())>>> = true;

    template <typename T>
    struct can_compute_size_s : std::bool_constant<can_compute_size<T>>
    {
    };

    template <typename T>
    constexpr bool is_sizeable_impl =
        std::disjunction_v<std::bool_constant<has_size_impl<T>>,
                           can_compute_size_s<T>>;

    template <typename T>
    struct is_sizeable_impl_s : std::bool_constant<is_sizeable_impl<T>>
    {
    };

    template <typename T, typename = void>
    constexpr bool has_empty_impl = false;
    template <typename T>
    constexpr bool has_empty_impl<
        T, std::enable_if_t<std::is_same_v<adl::adl_empty_t<T>, bool>>> = true;

    template <typename T, typename = void>
    constexpr bool has_comparable_edges = false;
    template <typename T>
    constexpr bool has_comparable_edges<
        T, std::enable_if_t<
               std::is_same_v<decltype(std::declval<adl::adl_begin_t<T>>() ==
                                       std::declval<adl::adl_end_t<T>>()),
                              bool>>> = true;

    template <typename T>
    struct has_comparable_edges_s : std::bool_constant<has_comparable_edges<T>>
    {
    };

    template <typename T>
    constexpr bool is_emptyable_impl =
        std::disjunction_v<std::bool_constant<has_empty_impl<T>>,
                           has_comparable_edges_s<T>, is_sizeable_impl_s<T>>;

    template <typename Itr, typename = void>
    constexpr bool has_arrow_operator_impl = false;
    template <typename Itr>
    constexpr bool has_arrow_operator_impl<
        Itr, std::void_t<decltype(std::declval<Itr&>().operator->())>> = true;

    template <typename T, typename Range, typename = void>
    constexpr bool is_iterator_of = false;
    template <typename T, typename Range>
    constexpr bool is_iterator_of<
        T, Range,
        std::enable_if_t<std::is_same_v<T, adl::adl_begin_t<Range>>>> = true;

    template <typename T, typename Range>
    struct is_iterator_of_s : std::bool_constant<is_iterator_of<T, Range>>
    {
    };

    template <typename T, typename Range>
    constexpr bool is_any_iterator_of =
        std::disjunction_v<is_iterator_of_s<T, Range>,
                           is_iterator_of_s<T, const Range>>;

    template <typename T, typename Range, typename = void>
    constexpr bool is_iterator_pair_of = false;
    template <typename T, typename Range>
    constexpr bool is_iterator_pair_of<
        T, Range,
        std::enable_if_t<tuple_unpacks_to<T, adl::adl_begin_t<Range>,
                                          adl::adl_begin_t<Range>>>> = true;

    template <typename T, typename Range>
    struct is_iterator_pair_of_s
        : std::bool_constant<is_iterator_pair_of<T, Range>>
    {
    };

    template <typename T, typename Range>
    constexpr bool is_any_iterator_pair_of =
        std::disjunction_v<is_iterator_pair_of_s<T, Range>,
                           is_iterator_pair_of_s<T, const Range>>;

    template <typename T, typename Range, typename = void>
    constexpr bool converts_to_iterator_of = false;
    template <typename T, typename Range>
    constexpr bool converts_to_iterator_of<
        T, Range,
        std::enable_if_t<std::is_convertible_v<T, adl::adl_begin_t<Range>>>> =
        true;

    template <typename T, typename Range>
    struct converts_to_iterator_of_s
        : std::bool_constant<converts_to_iterator_of<T, Range>>
    {
    };

    template <typename T, typename Range>
    constexpr bool converts_to_any_iterator_of =
        std::disjunction_v<converts_to_iterator_of_s<T, Range>,
                           converts_to_iterator_of_s<T, const Range>>;
  } // namespace helpers
#endif

  template <typename T, typename ExpectedVal, typename ExpectedRef>
  utils_concept is_iterator_yielding =
      helpers::is_iterator_yielding_impl<remove_cvref_t<T>, ExpectedVal,
                                         ExpectedRef>;

  template <typename T>
  utils_concept is_forward_iterable =
      helpers::is_forward_iterable_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept is_valid_forward_iterator =
      helpers::is_valid_forward_iterator_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept is_valid_bidirectional_iterator =
      helpers::is_valid_bidirectional_iterator_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept is_valid_random_access_iterator =
      helpers::is_valid_random_access_iterator_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept has_valid_forward_iterators =
      helpers::has_valid_forward_iterators_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_valid_forward_local_iterators =
      helpers::has_valid_forward_local_iterators_impl<
          std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_valid_bidirectional_iterators =
      helpers::has_valid_bidirectional_iterators_impl<
          std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_valid_random_access_iterators =
      helpers::has_valid_random_access_iterators_impl<
          std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_less_than_operator =
      helpers::has_less_than_operator_impl<remove_cvref_t<T>>;

  template <typename T>
  utils_concept range_has_computable_size =
      helpers::can_compute_size<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept is_sizeable =
      helpers::is_sizeable_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept range_has_comparable_edges =
      helpers::has_comparable_edges<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept is_emptyable =
      helpers::is_emptyable_impl<std::remove_reference_t<T>>;

  template <typename T>
  utils_concept has_arrow_operator =
      helpers::has_arrow_operator_impl<std::remove_reference_t<T>>;

  template <typename T, typename Range>
  utils_concept is_iterator_of =
      helpers::is_iterator_of<T, std::remove_reference_t<Range>>;
  template <typename T, typename Range>
  utils_concept is_any_iterator_of =
      helpers::is_any_iterator_of<T, remove_cvref_t<Range>>;
  template <typename T, typename Range>
  utils_concept is_iterator_pair_of =
      helpers::is_iterator_pair_of<remove_cvref_t<T>,
                                   std::remove_reference_t<Range>>;
  template <typename T, typename Range>
  utils_concept is_any_iterator_pair_of =
      helpers::is_any_iterator_pair_of<remove_cvref_t<T>,
                                       remove_cvref_t<Range>>;
  template <typename T, typename Range>
  utils_concept converts_to_iterator_of =
      helpers::converts_to_iterator_of<T, std::remove_reference_t<Range>>;
  template <typename T, typename Range>
  utils_concept converts_to_any_iterator_of =
      helpers::converts_to_any_iterator_of<T, remove_cvref_t<Range>>;

  template <typename T>
  using range_begin_t = helpers::adl::adl_begin_t<std::remove_reference_t<T>>;
  template <typename T>
  using range_end_t = helpers::adl::adl_end_t<std::remove_reference_t<T>>;
  template <typename T>
  using range_rbegin_t = helpers::adl::adl_rbegin_t<std::remove_reference_t<T>>;
  template <typename T>
  using range_rend_t = helpers::adl::adl_rend_t<std::remove_reference_t<T>>;
  template <typename T>
  using range_iterator_t = range_begin_t<T>;

  namespace helpers
  {
    template <typename Itr, typename = void>
    struct iter_reference_impl
    {
    };

    template <typename Itr>
    struct iter_reference_impl<
        Itr, std::void_t<decltype(*std::declval<const Itr&>())>>
    {
      using type = decltype(*std::declval<const Itr&>());
    };

    template <typename Itr, typename>
    struct iter_reference : iter_reference_impl<Itr>
    {
    };

    template <typename Itr>
    struct iter_reference<Itr, std::void_t<typename Itr::reference>>
    {
      using type = typename Itr::reference;
    };

    template <typename itr, typename iterator_category>
    struct iter_difference_type
    {
      using type = difference_type_optional_type_member_of<itr, ptrdiff_t>;
    };

    template <typename itr>
    struct iter_difference_type<itr, std::random_access_iterator_tag>
    {
      using type =
          decltype(std::declval<const itr&>() - std::declval<const itr&>());
    };

    template <typename Itr, typename supplied_category = void>
    struct iter_category_def
    {
      using determined_category = std::conditional_t<
          is_valid_random_access_iterator<Itr>, std::random_access_iterator_tag,
          std::conditional_t<is_valid_bidirectional_iterator<Itr>,
                             std::bidirectional_iterator_tag,
                             std::forward_iterator_tag>>;
      static_assert(
          std::disjunction_v<
              std::is_void<supplied_category>,
              std::is_same<determined_category, supplied_category>,
              std::negation<
                  std::is_base_of<determined_category, supplied_category>>,
              std::is_same<determined_category,
                           std::random_access_iterator_tag>>,
          "utils::iter::iterator_category: iterator_category given is of "
          "higher level than what was determined from the api provided");
      using type = std::conditional_t<std::is_void_v<supplied_category>,
                                      determined_category, supplied_category>;
    };

    template <typename Itr, typename>
    struct iter_category : iter_category_def<Itr>
    {
    };

    template <typename Itr>
    struct iter_category<Itr, std::void_t<iter_supplied_category_t<Itr>>>
        : iter_category_def<Itr, iter_supplied_category_t<Itr>>
    {
    };

    template <typename Itr, typename = void>
    struct iter_supplied_category_impl
    {
    };

    template <typename Itr>
    struct iter_supplied_category_impl<
        Itr, std::void_t<typename Itr::iterator_category>>
    {
      using type = typename Itr::iterator_category;
    };

    template <typename Itr, typename>
    struct iter_supplied_category : iter_supplied_category_impl<Itr>
    {
    };

    template <typename Itr>
    struct iter_supplied_category<Itr,
                                  std::void_t<typename Itr::iterator_concept>>
    {
      using type = typename Itr::iterator_concept;
    };

    template <typename T, typename ExpectedVal, typename ExpectedRef>
    struct is_iterator_yielding_s
        : std::bool_constant<is_iterator_yielding<T, ExpectedVal, ExpectedRef>>
    {
    };

    template <typename T>
    struct has_valid_forward_iterators_s
        : std::bool_constant<has_valid_forward_iterators<T>>
    {
    };

    template <typename T>
    struct range_has_computable_size_s
        : std::bool_constant<range_has_computable_size<T>>
    {
    };

    template <typename Range, bool>
    struct range_possible_reference
    {
      using type =
          reference_optional_type_member_of<Range, typename Range::value_type&>;
    };

    template <typename Range>
    struct range_possible_reference<Range, true>
    {
      using type = const_reference_optional_type_member_of<
          Range, const typename Range::value_type&>;
    };

    template <typename Range, typename>
    struct optional_possible_reference
    {
      using type = std::conditional_t<
          std::is_const_v<Range>,
          const_reference_optional_type_member_of<Range, void>,
          reference_optional_type_member_of<Range, void>>;
    };

    template <typename Range>
    struct optional_possible_reference<Range,
                                       std::void_t<typename Range::value_type>>
    {
      using type = range_possible_reference_t<Range>;
    };

    template <typename T1, typename T2, typename = void>
    struct equal_comparable : std::false_type
    {
    };

    template <typename T1, typename T2>
    struct equal_comparable<
        T1, T2,
        std::enable_if_t<std::is_convertible_v<
            decltype(std::declval<const T1&>() == std::declval<const T2&>()),
            bool>>> : std::true_type
    {
    };

    template <typename T1, typename T2, typename = void>
    struct less_than_comparable : std::false_type
    {
    };

    template <typename T1, typename T2>
    struct less_than_comparable<
        T1, T2,
        std::enable_if_t<std::is_convertible_v<
            decltype(std::declval<const T1&>() < std::declval<const T2&>()),
            bool>>> : std::true_type
    {
    };

    template <typename T1, typename T2, typename = void>
    struct greater_than_comparable : std::false_type
    {
    };

    template <typename T1, typename T2>
    struct greater_than_comparable<
        T1, T2,
        std::enable_if_t<std::is_convertible_v<
            decltype(std::declval<const T1&>() > std::declval<const T2&>()),
            bool>>> : std::true_type
    {
    };
  } // namespace helpers
} // namespace alterhook::utils::iter
