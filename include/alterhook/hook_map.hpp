/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <shared_mutex>
#include <variant>
#include <vector>
#include "detail/constants.hpp"
#include "tools.hpp"
#include "utilities/traits/concepts.hpp"
#include "utilities/data_processing.hpp"
#include "utilities/traits/function_traits.hpp"
#include "utilities/iterators.hpp"
#include "utilities/macros.hpp"
#include "utilities/other.hpp"
#include "utilities/traits/map_traits.hpp"
#include "utilities/traits/type_sequence.hpp"
#include "hook_chain.hpp"
#include "utilities/traits/iterator_traits.hpp"
#include "utilities/tuple_tools.hpp"
#include "detail/hook_map_codegen_flags.hpp"

namespace alterhook
{
  enum class thread_safety
  {
    automatic,
    concurrent,
    single_threaded
  };

  namespace helpers
  {
    template <typename adapted, thread_safety safety>
    struct map_bases;
    template <typename adapted>
    struct map_optional_aliases;
    template <typename adapted, thread_safety safety, typename = void>
    class map_mutex_wrapper;
    template <typename Adapted, typename Itr>
    class map_iterator_wrapper;
    template <typename AdaptedMappedType>
    class mapped_iterator_wrapper;
    template <typename T>
    constexpr auto extract_key_value(T&& item) noexcept;

    template <typename Tuple>
    struct map_elem_init_tuple_s;
    template <typename reference>
    struct map_callable_requirement_enclosure;

    enum class bulk_process_type
    {
      erase,
      enable,
      disable
    };

    struct insert_uses_and_visitation; // and functor
    struct insert_uses_or_visitation;
    struct insert_const_visit;
    struct insert_has_hint;
    struct insert_bulk;

    struct visit_no_map_lock;
    struct visit_conditional;
    struct visit_const;

    template <typename Adapted>
    utils_concept is_concurrent_map =
        utils::traits::has_map_basic_visit_method<Adapted>;

    template <typename Adapted, typename = void>
    constexpr bool map_modifiable_range = false;
    template <typename... Tuples>
    constexpr bool map_tuples_structure_requirements =
        std::conjunction_v<map_elem_init_tuple_s<Tuples>...>;
    template <typename Itr, typename = void>
    constexpr bool map_valid_init_iterator = false;
    template <typename Range, typename = void>
    constexpr bool map_valid_init_range = false;
    template <typename TuplesSeq, typename CallablesSeq, size_t max_callables,
              typename = void>
    constexpr bool map_insertion_and_visitation_layout_requirements_impl =
        false;
    template <typename TypesSeq, size_t max_callables, typename reference>
    constexpr bool map_insertion_and_visitation_layout_requirements =
        map_insertion_and_visitation_layout_requirements_impl<
            typename TypesSeq::template reversed<>::template drop_while<
                map_callable_requirement_enclosure<reference>::template check>,
            typename TypesSeq::template reversed<>::template take_while<
                map_callable_requirement_enclosure<reference>::template check>,
            max_callables>;
  } // namespace helpers

  // for constructor selection purposes
  template <typename... types>
  struct map_init_args
  {
    std::tuple<types&&...> args;
  };

  template <typename... types>
  constexpr map_init_args<types...> map_init(types&&... args) noexcept
  {
    return { std::forward_as_tuple(std::forward<types>(args)...) };
  }

  template <typename K,
            template <typename...> typename Map = std::unordered_map,
            thread_safety safety                = thread_safety::automatic,
            typename... map_type_args>
  class hook_map
      : public helpers::map_bases<
            Map<K, helpers::mapped_iterator_wrapper<hook_chain::iterator>,
                map_type_args...>,
            safety>
  {
  public:
    using adapted_map =
        Map<K, helpers::mapped_iterator_wrapper<hook_chain::iterator>,
            map_type_args...>;

  private:
    using bases               = helpers::map_bases<adapted_map, safety>;
    using adapted_mapped_type = typename adapted_map::mapped_type;

  public:
    static_assert(std::is_same_v<K, utils::remove_cvref_t<K>>,
                  "hook_map: the key type cannot be cv or reference qualified");

    struct flags;

    static_assert(
        utils::traits::is_core_map<adapted_map>,
        "hook_map: the type provided doesn't meet the criteria of a basic map");

    using key_type        = typename adapted_map::key_type;
    using mapped_type     = hook_chain::hook;
    using value_type      = std::pair<key_type, mapped_type>;
    using reference       = std::pair<const key_type&, mapped_type&>;
    using const_reference = std::pair<const key_type&, const mapped_type&>;
    using size_type =
        utils::size_type_optional_type_member_of<adapted_map, size_t>;
    using difference_type =
        utils::difference_type_optional_type_member_of<adapted_map, ptrdiff_t>;

    template <typename KeyFwd>
    class lazy_hook_proxy;

    static constexpr thread_safety thread_safety_requested = safety;

    using bases::adapts_concurrent_map;
    using bases::is_concurrent;

    static utils_consteval bool is_multimap();

    template <typename Target, typename Tuple, typename... Tuples,
              std::enable_if_t<utils::callable_type<Target> &&
                                   helpers::map_tuples_structure_requirements<
                                       Tuple, Tuples...>,
                               size_t> = 0>
    hook_map(Target&& target, Tuple&& first, Tuples&&... rest)
        : hook_map(map_init(), std::forward<Target>(target),
                   std::forward<Tuple>(first), std::forward<Tuples>(rest)...)
    {
    }

    template <typename Tuple, typename... Tuples,
              std::enable_if_t<
                  helpers::map_tuples_structure_requirements<Tuple, Tuples...>,
                  size_t> = 0>
    hook_map(std::byte* target, Tuple&& first, Tuples&&... rest)
        : hook_map(map_init(), target, std::forward<Tuple>(first),
                   std::forward<Tuples>(rest)...)
    {
    }

    template <
        typename... MapInitTypes, typename Target, typename Tuple,
        typename... Tuples,
        std::enable_if_t<
            std::is_constructible_v<adapted_map, MapInitTypes&&...> &&
                utils::callable_type<Target> &&
                helpers::map_tuples_structure_requirements<Tuple, Tuples...>,
            size_t> = 0>
    hook_map(map_init_args<MapInitTypes...> map_args, Target&& target,
             Tuple&& first, Tuples&&... rest)
        : chain(chain_from_map_tuples(std::forward<Target>(target),
                                      std::forward<Tuple>(first),
                                      std::forward<Tuples>(rest)...)),
          map(std::make_from_tuple<adapted_map>(std::move(map_args.args)))
    {
      init_map(std::forward<Tuple>(first), std::forward<Tuples>(rest)...);
    }

    template <
        typename... MapInitTypes, typename Tuple, typename... Tuples,
        std::enable_if_t<
            std::is_constructible_v<adapted_map, MapInitTypes&&...> &&
                helpers::map_tuples_structure_requirements<Tuple, Tuples...>,
            size_t> = 0>
    hook_map(map_init_args<MapInitTypes...> map_args, std::byte* target,
             Tuple&& first, Tuples&&... rest)
        : chain(chain_from_map_tuples(target, std::forward<Tuple>(first),
                                      std::forward<Tuples>(rest)...)),
          map(std::make_from_tuple<adapted_map>(std::move(map_args.args)))
    {
      init_map(std::forward<Tuple>(first), std::forward<Tuples>(rest)...);
    }

    template <typename Target, typename Itr,
              std::enable_if_t<utils::callable_type<Target> &&
                                   helpers::map_valid_init_iterator<Itr>,
                               size_t> = 0>
    hook_map(Target&& target, Itr first, Itr last)
        : hook_map(get_target_address(std::forward<Target>(target)), first,
                   last)
    {
    }

    template <
        typename Itr,
        std::enable_if_t<helpers::map_valid_init_iterator<Itr>, size_t> = 0>
    hook_map(std::byte* target, Itr first, Itr last)
        : hook_map(map_init(), target, first, last)
    {
    }

    template <typename... MapInitTypes, typename Target, typename Itr,
              std::enable_if_t<
                  std::is_constructible_v<adapted_map, MapInitTypes&&...> &&
                      utils::callable_type<Target> &&
                      helpers::map_valid_init_iterator<Itr>,
                  size_t> = 0>
    hook_map(map_init_args<MapInitTypes...> map_args, Target&& target,
             Itr first, Itr last)
        : hook_map(std::move(map_args),
                   get_target_address(std::forward<Target>(target)), first,
                   last)
    {
    }

    template <typename... MapInitTypes, typename Itr,
              std::enable_if_t<
                  std::is_constructible_v<adapted_map, MapInitTypes&&...> &&
                      helpers::map_valid_init_iterator<Itr>,
                  size_t> = 0>
    hook_map(map_init_args<MapInitTypes...> map_args, std::byte* target,
             Itr first, Itr last);

    template <typename Target, typename Range,
              std::enable_if_t<utils::callable_type<Target> &&
                                   helpers::map_valid_init_range<Range>,
                               size_t> = 0>
    hook_map(Target&& target, Range&& range)
        : hook_map(get_target_address(std::forward<Target>(target)),
                   std::forward<Range>(range))
    {
    }

    template <
        typename Range,
        std::enable_if_t<helpers::map_valid_init_range<Range>, size_t> = 0>
    hook_map(std::byte* target, Range&& range)
        : hook_map(map_init(), target, std::forward<Range>(range))
    {
    }

    template <typename... MapInitTypes, typename Target, typename Range,
              std::enable_if_t<
                  std::is_constructible_v<adapted_map, MapInitTypes&&...> &&
                      utils::callable_type<Target> &&
                      helpers::map_valid_init_range<Range>,
                  size_t> = 0>
    hook_map(map_init_args<MapInitTypes...> map_args, Target&& target,
             Range&& range)
        : hook_map(std::move(map_args),
                   get_target_address(std::forward<Target>(target)),
                   std::forward<Range>(range))
    {
    }

    template <typename... MapInitTypes, typename Range,
              std::enable_if_t<
                  std::is_constructible_v<adapted_map, MapInitTypes&&...> &&
                      helpers::map_valid_init_range<Range>,
                  size_t> = 0>
    hook_map(map_init_args<MapInitTypes...> map_args, std::byte* target,
             Range&& range)
        : hook_map(std::move(map_args), target, utils::iter::begin(range),
                   utils::iter::end(range))
    {
    }

    hook_map() = default;

    template <typename... map_types>
    hook_map(map_init_args<map_types...> map_args)
        : map(std::make_from_tuple<adapted_map>(std::move(map_args.args)))
    {
    }

    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    explicit hook_map(trg&& target) : chain(std::forward<trg>(target))
    {
    }

    explicit hook_map(std::byte* target) : chain(target) {}

    hook_map(hook_map&& other) noexcept(
        std::is_nothrow_move_constructible_v<adapted_map>)
        : hook_map(std::move(other), std::unique_lock{ other.get_map_mutex() })
    {
    }

    hook_map& operator=(hook_map&& other) noexcept(
        std::is_nothrow_move_assignable_v<adapted_map>);

    size_type size() const
    {
      std::shared_lock lock1{ get_map_mutex() };
      std::shared_lock lock2{ get_chain_mutex() };
      return static_cast<size_type>(chain.size());
    }

    bool empty() const { return !size(); }

    explicit operator bool() const { return !empty(); }

    size_type enable_all() { return set_status_if<true>(); }

    size_type disable_all() { return set_status_if<false>(); }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_single_state_update(),
                               size_t> = 0>
    size_type enable(KeyFwd&& key)
    {
      return set_status_if<true>(
          std::forward_as_tuple(std::forward<KeyFwd>(key)));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_single_state_update(),
                               size_t> = 0>
    size_type disable(KeyFwd&& key)
    {
      return set_status_if<false>(
          std::forward_as_tuple(std::forward<KeyFwd>(key)));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_range_state_update(),
                               size_t> = 0>
    size_type enable(typename U::iterator first, typename U::iterator last)
    {
      return set_status_if<true>(std::tuple(first.unwrap(), last.unwrap()));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_range_state_update(),
                               size_t> = 0>
    size_type disable(typename U::iterator first, typename U::iterator last)
    {
      return set_status_if<false>(std::tuple(first.unwrap(), last.unwrap()));
    }

    template <typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_conditional_full_state_update(),
                  size_t> = 0>
    size_type enable_if(Callable&& pred)
    {
      return set_status_if<true>(pred);
    }

    template <typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_conditional_full_state_update(),
                  size_t> = 0>
    size_type disable_if(Callable&& pred)
    {
      return set_status_if<false>(pred);
    }

    template <typename KeyFwd, typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_single_state_update(),
                  size_t> = 0>
    size_type enable_if(KeyFwd&& key, Callable&& pred)
    {
      return set_status_if<true>(
          std::forward_as_tuple(std::forward<KeyFwd>(key)), pred);
    }

    template <typename KeyFwd, typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_single_state_update(),
                  size_t> = 0>
    size_type disable_if(KeyFwd&& key, Callable&& pred)
    {
      return set_status_if<false>(
          std::forward_as_tuple(std::forward<KeyFwd>(key)), pred);
    }

    template <typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_range_state_update(),
                  size_t> = 0>
    size_type enable_if(typename U::iterator first, typename U::iterator last,
                        Callable&& pred)
    {
      return set_status_if<true>(std::tuple(first.unwrap(), last.unwrap()),
                                 pred);
    }

    template <typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_range_state_update(),
                  size_t> = 0>
    size_type disable_if(typename U::iterator first, typename U::iterator last,
                         Callable&& pred)
    {
      return set_status_if<false>(std::tuple(first.unwrap(), last.unwrap()),
                                  pred);
    }

    template <typename Tuple, typename... Tuples, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   helpers::map_tuples_structure_requirements<
                                       Tuple, Tuples...> &&
                                   U::flags::can_adapt_element_insertion(),
                               size_t> = 0>
    auto insert(Tuple&& first, Tuples&&... rest)
    {
      return insert_impl(std::tuple(), std::forward<Tuple>(first),
                         std::forward<Tuples>(rest)...);
    }

    template <typename Itr, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   helpers::map_valid_init_iterator<Itr> &&
                                   U::flags::can_adapt_element_insertion(),
                               size_t> = 0>
    size_type insert(Itr first, Itr last)
    {
      return insert_range_impl(std::tuple(), first, last);
    }

    template <typename Range, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   helpers::map_valid_init_range<Range> &&
                                   U::flags::can_adapt_element_insertion(),
                               size_t> = 0>
    size_type insert(Range&& range)
    {
      return insert_range_impl(std::tuple(), utils::iter::begin(range),
                               utils::iter::end(range));
    }

    template <typename Tuple, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      helpers::map_tuples_structure_requirements<Tuple> &&
                      U::flags::can_adapt_hint_insertion(),
                  size_t> = 0>
    typename U::iterator insert(typename U::const_iterator hint, Tuple&& elem)
    {
      return insert_impl<helpers::insert_has_hint>(std::tuple(hint.unwrap()),
                                                   std::forward<Tuple>(elem));
    }

    template <typename Tuple, typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      helpers::map_tuples_structure_requirements<Tuple> &&
                      std::is_invocable_v<Callable&, reference> &&
                      U::flags::can_adapt_insertion_with_visitation(),
                  size_t> = 0>
    size_type insert_or_visit(Tuple&& entry, Callable&& visitor)
    {
      return insert_impl<helpers::insert_uses_or_visitation>(
          std::tie(visitor), std::forward<Tuple>(entry));
    }

    template <typename... Types, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      helpers::map_insertion_and_visitation_layout_requirements<
                          utils::type_sequence<Types...>, 1, const_reference> &&
                      U::flags::can_adapt_insertion_with_visitation(),
                  size_t> = 0>
    size_type insert_or_cvisit(Types&&... args)
    {
      return unwrap_visitors_and_invoke<const_reference>(
          [this](auto, auto&& visitors, auto&&... tuples)
          {
            return insert_impl<helpers::insert_uses_or_visitation,
                               helpers::insert_const_visit>(
                visitors, std::forward<decltype(tuples)>(tuples)...);
          },
          std::forward<Types>(args)...);
    }

    template <
        typename Itr, typename Callable, typename U = hook_map,
        std::enable_if_t<std::is_same_v<U, hook_map> &&
                             helpers::map_valid_init_iterator<Itr> &&
                             std::is_invocable_v<Callable&, const_reference> &&
                             U::flags::can_adapt_insertion_with_visitation(),
                         size_t> = 0>
    size_type insert_or_cvisit(Itr first, Itr last, Callable&& visitor)
    {
      return insert_range_impl<helpers::insert_uses_or_visitation,
                               helpers::insert_const_visit>(std::tie(visitor),
                                                            first, last);
    }

    template <
        typename Range, typename Callable, typename U = hook_map,
        std::enable_if_t<std::is_same_v<U, hook_map> &&
                             helpers::map_valid_init_range<Range> &&
                             std::is_invocable_v<Callable&, const_reference> &&
                             U::flags::can_adapt_insertion_with_visitation(),
                         size_t> = 0>
    size_type insert_or_cvisit(Range&& range, Callable&& visitor)
    {
      return insert_range_impl<helpers::insert_uses_or_visitation,
                               helpers::insert_const_visit>(
          std::tie(visitor), utils::iter::begin(range),
          utils::iter::end(range));
    }

    template <
        typename Tuple, typename Callable1, typename Callable2 = utils::nothing,
        typename U = hook_map,
        std::enable_if_t<
            std::is_same_v<U, hook_map> &&
                helpers::map_tuples_structure_requirements<Tuple> &&
                std::is_invocable_v<Callable1&, reference> &&
                std::disjunction_v<std::is_same<Callable2, utils::nothing>,
                                   std::is_invocable<Callable2&, reference>> &&
                U::flags::can_adapt_insertion_with_visitation(),
            size_t> = 0>
    size_type insert_and_visit(Tuple&& entry, Callable1&& and_visitor,
                               Callable2&& or_visitor = Callable2{})
    {
      return insert_impl<helpers::insert_uses_and_visitation,
                         or_visitor_flag_t<Callable2>>(
          pack_visitors(and_visitor, or_visitor), std::forward<Tuple>(entry));
    }

    template <typename... Types, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      helpers::map_insertion_and_visitation_layout_requirements<
                          utils::type_sequence<Types...>, 2, const_reference> &&
                      U::flags::can_adapt_insertion_with_visitation(),
                  size_t> = 0>
    size_type insert_and_cvisit(Types&&... args)
    {
      return unwrap_visitors_and_invoke<const_reference>(
          [this](auto callable_count, auto&& visitors, auto&&... entries)
          {
            using has_or_visitor =
                std::conditional_t<decltype(callable_count)::value == 2,
                                   helpers::insert_uses_or_visitation,
                                   utils::nothing>;
            return insert_impl<helpers::insert_uses_and_visitation,
                               has_or_visitor, helpers::insert_const_visit>(
                visitors, std::forward<decltype(entries)>(entries)...);
          },
          std::forward<Types>(args)...);
    }

    template <typename Itr, typename Callable1,
              typename Callable2 = utils::nothing, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      helpers::map_valid_init_iterator<Itr> &&
                      std::is_invocable_v<Callable1&, const_reference> &&
                      std::disjunction_v<
                          std::is_same<Callable2, utils::nothing>,
                          std::is_invocable<Callable2&, const_reference>> &&
                      U::flags::can_adapt_insertion_with_visitation(),
                  size_t> = 0>
    size_type insert_and_cvisit(Itr first, Itr last, Callable1&& and_visitor,
                                Callable2&& or_visitor = Callable2{})
    {
      return insert_range_impl<helpers::insert_uses_and_visitation,
                               or_visitor_flag_t<Callable2>,
                               helpers::insert_const_visit>(
          pack_visitors(and_visitor, or_visitor), first, last);
    }

    template <typename Range, typename Callable1,
              typename Callable2 = utils::nothing, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      helpers::map_valid_init_range<Range> &&
                      std::is_invocable_v<Callable1&, const_reference> &&
                      std::disjunction_v<
                          std::is_same<Callable2, utils::nothing>,
                          std::is_invocable<Callable2&, const_reference>> &&
                      U::flags::can_adapt_insertion_with_visitation(),
                  size_t> = 0>
    size_type insert_and_cvisit(Range&& range, Callable1&& and_visitor,
                                Callable2&& or_visitor = Callable2{})
    {
      return insert_range_impl<helpers::insert_uses_and_visitation,
                               or_visitor_flag_t<Callable2>,
                               helpers::insert_const_visit>(
          pack_visitors(and_visitor, or_visitor), utils::iter::begin(range),
          utils::iter::end(range));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_key_erasure(),
                               size_t> = 0>
    size_type erase(KeyFwd&& key)
    {
      return erase_impl(std::forward_as_tuple(std::forward<KeyFwd>(key)));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_iterator_erasure(),
                               size_t> = 0>
    auto erase(typename hook_map::template erase_iterator_t<U> pos)
    {
      return erase_impl(std::tuple(pos.unwrap()));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_iterator_erasure(),
                               size_t> = 0>
    auto erase(typename hook_map::template erase_iterator_t<U> first,
               typename hook_map::template erase_iterator_t<U> last)
    {
      return erase_impl(std::tuple(first.unwrap(), last.unwrap()));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_clear(),
                               size_t> = 0>
    void clear()
    {
      erase_impl();
    }

    template <typename KeyFwd, typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_key_erasure(),
                  size_t> = 0>
    size_type erase_if(KeyFwd&& key, Callable&& pred)
    {
      return erase_impl(std::forward_as_tuple(std::forward<KeyFwd>(key)), pred);
    }

    template <typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_iterator_erasure(),
                  size_t> = 0>
    size_type erase_if(typename hook_map::template erase_iterator_t<U> pos,
                       Callable&&                                      pred)
    {
      return erase_impl(std::tuple(pos.unwrap()), pred);
    }

    template <typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_iterator_erasure(),
                  size_t> = 0>
    size_type erase_if(typename hook_map::template erase_iterator_t<U> first,
                       typename hook_map::template erase_iterator_t<U> last,
                       Callable&&                                      pred)
    {
      return erase_impl(std::tuple(first.unwrap(), last.unwrap()), pred);
    }

    template <typename Callable, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Callable&, const_reference> &&
                      U::flags::can_adapt_conditional_full_erasure(),
                  size_t> = 0>
    size_type erase_if(Callable&& pred)
    {
      return erase_impl(pred);
    }

    template <typename Key1, typename Key2, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_rekey(),
                               size_t> = 0>
    bool rekey(Key1&& old_key, Key2&& new_key)
    {
      return rekey_impl(std::forward<Key1>(old_key),
                        std::forward<Key2>(new_key));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_at_method(),
                               size_t> = 0>
    mapped_type& at(KeyFwd&& key)
    {
      return at_impl(map, std::forward<KeyFwd>(key));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_at_method(),
                               size_t> = 0>
    const mapped_type& at(KeyFwd&& key) const
    {
      return at_impl(map, std::forward<KeyFwd>(key));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_element_insertion() &&
                                   U::flags::can_adapt_at_method(),
                               size_t> = 0>
    lazy_hook_proxy<KeyFwd> operator[](KeyFwd&& key) noexcept
    {
      return { *this, std::forward<KeyFwd>(key) };
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_find_method(),
                               size_t> = 0>
    typename U::iterator find(KeyFwd&& key)
    {
      return find_impl(map, std::forward<KeyFwd>(key));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_find_method(),
                               size_t> = 0>
    typename U::const_iterator find(KeyFwd&& key) const
    {
      return find_impl(map, std::forward<KeyFwd>(key));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_equal_range(),
                               size_t> = 0>
    std::pair<typename U::iterator, typename U::iterator>
        equal_range(KeyFwd&& key)
    {
      return equal_range_impl(map, std::forward<KeyFwd>(key));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_equal_range(),
                               size_t> = 0>
    std::pair<typename U::const_iterator, typename U::const_iterator>
        equal_range(KeyFwd&& key) const
    {
      return equal_range_impl(map, std::forward<KeyFwd>(key));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_count_method(),
                               size_t> = 0>
    size_type count(KeyFwd&& key) const
    {
      return count_impl(std::forward<KeyFwd>(key));
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_contains_method(),
                               size_t> = 0>
    bool contains(KeyFwd&& key) const
    {
      return contains_impl<true>(std::forward<KeyFwd>(key));
    }

    template <typename KeyFwd, typename Visitor, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   std::is_invocable_v<Visitor&, reference> &&
                                   U::flags::can_adapt_element_visitor_method(),
                               size_t> = 0>
    size_type visit(KeyFwd&& key, Visitor&& visitor)
    {
      return visit_impl(std::forward_as_tuple(std::forward<KeyFwd>(key)),
                        visitor);
    }

    template <
        typename KeyFwd, typename Visitor, typename U = hook_map,
        std::enable_if_t<std::is_same_v<U, hook_map> &&
                             std::is_invocable_v<Visitor&, const_reference> &&
                             U::flags::can_adapt_element_visitor_method(),
                         size_t> = 0>
    size_type visit(KeyFwd&& key, Visitor&& visitor) const
    {
      return visit_impl<helpers::visit_const>(
          std::forward_as_tuple(std::forward<KeyFwd>(key)), visitor);
    }

    template <
        typename KeyFwd, typename Visitor, typename U = hook_map,
        std::enable_if_t<std::is_same_v<U, hook_map> &&
                             std::is_invocable_v<Visitor&, const_reference> &&
                             U::flags::can_adapt_element_visitor_method(),
                         size_t> = 0>
    size_type cvisit(KeyFwd&& key, Visitor&& visitor) const
    {
      return visit(std::forward<KeyFwd>(key), visitor);
    }

    template <typename Itr, typename Visitor, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_v<Visitor&, const_reference> &&
                      U::flags::template can_adapt_range_visitor_method<Itr>(),
                  size_t> = 0>
    size_type visit(Itr first, Itr last, Visitor&& visitor) const
    {
      return visit_impl(std::tuple{ first, last }, visitor);
    }

    template <typename Visitor, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_v<Visitor&, const_reference> &&
                      U::flags::can_adapt_whole_container_visitor_method(),
                  size_t> = 0>
    size_type visit_all(Visitor&& visitor) const
    {
      return visit_impl(visitor);
    }

    template <typename Visitor, typename U = hook_map,
              std::enable_if_t<
                  std::is_same_v<U, hook_map> &&
                      std::is_invocable_r_v<bool, Visitor&, const_reference> &&
                      U::flags::can_adapt_conditional_visitor_method(),
                  size_t> = 0>
    size_type visit_while(Visitor&& visitor) const
    {
      return visit_impl<helpers::visit_conditional>(visitor);
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_iterators(),
                               size_t> = 0>
    typename U::iterator begin()
    {
      return typename hook_map::iterator(map.begin());
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_iterators(),
                               size_t> = 0>
    typename U::iterator end()
    {
      return typename hook_map::iterator(map.end());
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_iterators(),
                               size_t> = 0>
    typename U::const_iterator begin() const
    {
      return typename hook_map::const_iterator(map.begin());
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_iterators(),
                               size_t> = 0>
    typename U::const_iterator end() const
    {
      return typename hook_map::const_iterator(map.end());
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_iterators(),
                               size_t> = 0>
    typename U::const_iterator cbegin() const
    {
      return begin();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_iterators(),
                               size_t> = 0>
    typename U::const_iterator cend() const
    {
      return end();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_reverse_iterators(),
                               size_t> = 0>
    typename U::reverse_iterator rbegin()
    {
      return typename hook_map::reverse_iterator(end());
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_reverse_iterators(),
                               size_t> = 0>
    typename U::reverse_iterator rend()
    {
      return typename hook_map::reverse_iterator(begin());
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_reverse_iterators(),
                               size_t> = 0>
    typename U::const_reverse_iterator rbegin() const
    {
      return typename hook_map::const_reverse_iterator(end());
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_reverse_iterators(),
                               size_t> = 0>
    typename U::const_reverse_iterator rend() const
    {
      return typename hook_map::const_reverse_iterator(begin());
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_reverse_iterators(),
                               size_t> = 0>
    typename U::const_reverse_iterator crbegin() const
    {
      return rbegin();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_reverse_iterators(),
                               size_t> = 0>
    typename U::const_reverse_iterator crend() const
    {
      return rend();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_map_bucket_api(),
                               size_t> = 0>
    size_type bucket_count() const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.bucket_count();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_map_bucket_api(),
                               size_t> = 0>
    size_type max_bucket_count() const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.max_bucket_count();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_map_bucket_api(),
                               size_t> = 0>
    size_type bucket_size(size_type n) const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.bucket_size(n);
    }

    template <typename KeyFwd, typename U = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_map_bucket_api(),
                               size_t> = 0>
    size_type bucket(KeyFwd&& key) const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.bucket(std::forward<KeyFwd>(key));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_bucket_iteration(),
                               size_t> = 0>
    typename U::local_iterator begin(size_type n)
    {
      return typename hook_map::local_iterator(map.begin(n));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_bucket_iteration(),
                               size_t> = 0>
    typename U::local_iterator end(size_type n)
    {
      return typename hook_map::local_iterator(map.end(n));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_bucket_iteration(),
                               size_t> = 0>
    typename U::const_local_iterator begin(size_type n) const
    {
      return typename hook_map::const_local_iterator(map.begin(n));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_bucket_iteration(),
                               size_t> = 0>
    typename U::const_local_iterator end(size_type n) const
    {
      return typename hook_map::const_local_iterator(map.end(n));
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_bucket_iteration(),
                               size_t> = 0>
    typename U::const_local_iterator cbegin(size_type n) const
    {
      return begin(n);
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::can_adapt_bucket_iteration(),
                               size_t> = 0>
    typename U::const_local_iterator cend(size_type n) const
    {
      return end(n);
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_hash_map_capacity_api(),
                               size_t> = 0>
    float load_factor() const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.load_factor();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_hash_map_capacity_api(),
                               size_t> = 0>
    float max_load_factor() const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.max_load_factor();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_hash_map_capacity_api(),
                               size_t> = 0>
    decltype(auto) max_load_factor(float ml)
    {
      std::unique_lock lock{ get_map_mutex() };
      return map.max_load_factor(ml);
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_hash_map_capacity_api(),
                               size_t> = 0>
    decltype(auto) rehash(size_type count)
    {
      std::unique_lock lock{ get_map_mutex() };
      return map.rehash(count);
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::has_hash_map_capacity_api(),
                               size_t> = 0>
    decltype(auto) reserve(size_type count)
    {
      std::unique_lock lock{ get_map_mutex() };
      return map.reserve(count);
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::is_hasher_aware(),
                               size_t> = 0>
    typename U::hasher hash_function() const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.hash_function();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::provides_equality_comparator(),
                               size_t> = 0>
    typename U::key_equal key_eq() const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.key_eq();
    }

    template <typename U               = hook_map,
              std::enable_if_t<std::is_same_v<U, hook_map> &&
                                   U::flags::is_allocator_aware(),
                               size_t> = 0>
    typename U::allocator_type get_allocator() const
    {
      std::shared_lock lock{ get_map_mutex() };
      return map.get_allocator();
    }

  private:
    hook_chain  chain;
    adapted_map map;

    template <typename U>
    using erase_iterator_t =
        std::conditional_t<U::flags::has_map_const_iterator_erasure(),
                           typename U::const_iterator, typename U::iterator>;
    template <typename Target, size_t N>
    using chain_init_array_t =
        std::array<hook_chain::init_type<utils::remove_cvref_t<Target>>, N>;
    template <typename Self>
    using elem_ref_t =
        std::conditional_t<std::is_const_v<std::remove_reference_t<Self>>,
                           const_reference, reference>;
    template <typename Callable>
    using or_visitor_flag_t = std::conditional_t<
        std::is_same_v<utils::remove_cvref_t<Callable>, utils::nothing>,
        utils::nothing, helpers::insert_uses_or_visitation>;
    template <typename Adapted>
    using adapted_iterator_t = std::conditional_t<
        std::is_const_v<std::remove_reference_t<Adapted>>,
        typename utils::remove_cvref_t<Adapted>::const_iterator,
        typename utils::remove_cvref_t<Adapted>::iterator>;

    template <typename Itr>
    struct chain_init_iterator;
    template <typename Itr>
    struct map_init_iterator;

    template <typename RawProxy>
    class erase_return_proxy;

    template <typename Func>
    erase_return_proxy(Func&& func) -> erase_return_proxy<decltype(func())>;

    using bases::get_chain_mutex;
    using bases::get_map_mutex;
    using map_mutex_t       = typename bases::map_mutex_t;
    using chain_mutex_t     = typename bases::chain_mutex_t;
    using bulk_process_type = helpers::bulk_process_type;
    using adapted_reference = utils::reference_optional_type_member_of<
        adapted_map, typename adapted_map::value_type&>;
    using adapted_const_reference =
        utils::const_reference_optional_type_member_of<
            adapted_map, const typename adapted_map::value_type&>;

    template <bulk_process_type type>
    class bulk_process;

    using bulk_cleanup = bulk_process<bulk_process_type::erase>;

    template <typename... Tuples>
    void init_map(Tuples&&... tuples);

    hook_map(hook_map&& other, std::unique_lock<map_mutex_t>);

    template <bool state, typename... Types, typename Callable = utils::nothing>
    size_type set_status_if(std::tuple<Types...> args,
                            Callable&&           pred = Callable{});

    template <bool state, typename Callable>
    size_type set_status_if(Callable&& pred)
    {
      return set_status_if<state>(std::tuple{}, pred);
    }

    template <bool must_return_iterator = false, typename Key,
              typename OptionalHint     = utils::nothing>
    decltype(auto) raw_standard_map_insert(Key&& key, adapted_mapped_type val,
                                           OptionalHint hint = OptionalHint{});

    template <typename FlagsSeq, typename... OptionalTypes, typename Key,
              typename... Types>
    auto regular_single_insert_impl(
        const std::tuple<OptionalTypes...>& optional_args, Key&& key,
        Types&&... hook_args);

    template <typename FlagsSeq, typename... OptionalTypes,
              typename LoopFunctor>
    auto regular_insert_impl(const std::tuple<OptionalTypes...>& optional_args,
                             LoopFunctor&&                       loop);

    template <typename FlagsSeq, typename... OptionalTypes,
              typename LoopFunctor>
    size_type visit_based_insert_impl(
        const std::tuple<OptionalTypes...>& optional_args, LoopFunctor&& loop);

    template <typename... Flags, typename... OptionalTypes, typename... Tuples>
    auto insert_impl(const std::tuple<OptionalTypes...>& optional_args,
                     Tuples&&... entries);

    template <typename... Flags, typename... OptionalTypes, typename Itr>
    size_type
        insert_range_impl(const std::tuple<OptionalTypes...>& optional_args,
                          Itr first, Itr last);

    template <typename Target, typename... Tuples>
    static constexpr chain_init_array_t<Target, sizeof...(Tuples)>
        chain_init_array_from_tuples(Tuples&&... tuples);

    template <typename Target, typename... Tuples>
    static hook_chain chain_from_map_tuples(Target&& target, Tuples&&... tuples)
    {
      using target_t = std::conditional_t<
          std::is_same_v<utils::remove_cvref_t<Target>, std::byte*>, void,
          Target>;
      const auto init_array = chain_init_array_from_tuples<target_t>(
          std::forward<Tuples>(tuples)...);
      return { std::forward<Target>(target), init_array };
    }

    template <typename T>
    static constexpr auto extract_key_value(T&& item) noexcept
    {
      return helpers::extract_key_value(std::forward<T>(item));
    }

    template <typename Func>
    static auto erase_return_wrap(Func&& func);

    template <typename InvokeRef, typename Func, typename... Types>
    static auto unwrap_visitors_and_invoke(Func&& func, Types&&... args);

    template <typename Callable1, typename Callable2>
    static auto pack_visitors(Callable1&& and_visitor, Callable2&& or_visitor);

    template <typename Key1, typename Key2>
    bool rekey_impl(Key1&& old_key, Key2&& new_key);

    template <typename Adapted, typename KeyFwd>
    static auto& at_impl(Adapted&& map, KeyFwd&& key);

    template <typename Adapted, typename KeyFwd>
    static auto find_raw(Adapted&& map, KeyFwd&& key)
        -> std::pair<adapted_iterator_t<Adapted>, bool>;

    template <typename Adapted, typename KeyFwd>
    static auto find_impl(Adapted&& map, KeyFwd&& key);

    template <typename Adapted, typename KeyFwd>
    static auto equal_range_impl(Adapted&& map, KeyFwd&& key);

    template <typename KeyFwd>
    size_type count_impl(KeyFwd&& key) const;

    template <bool grab_lock = false, typename KeyFwd>
    bool contains_impl(KeyFwd&& key) const;

    template <typename... Flags, typename... Types, typename Callable>
    size_type visit_impl(std::tuple<Types...> args, Callable&& visitor) const;

    template <typename... Flags, typename Callable>
    size_type visit_impl(Callable&& visitor) const
    {
      return visit_impl<Flags...>(std::tuple{}, visitor);
    }

    template <typename... types, typename Pred = utils::nothing>
    auto erase_impl(std::tuple<types...> args, Pred&& pred = Pred{});

    template <typename Pred = utils::nothing>
    auto erase_impl(Pred&& pred = Pred{})
    {
      return erase_impl(std::tuple{}, pred);
    }
  };

  template <typename adapted>
  struct hook_map_shared_mutex_of
  {
    using type = std::shared_mutex;
  };

  template <typename adapted>
  using hook_map_shared_mutex_of_t =
      typename hook_map_shared_mutex_of<adapted>::type;

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename KeyFwd>
  class hook_map<K, Map, safety, map_type_args...>::lazy_hook_proxy
  {
  public:
    using init_type = hook_chain::init_type<>;

    lazy_hook_proxy(hook_map& parent, KeyFwd&& key) noexcept
        : parent(parent), key(std::forward<KeyFwd>(key))
    {
    }

    lazy_hook_proxy(const lazy_hook_proxy&) = delete;

    lazy_hook_proxy& operator=(const init_type& hook)
    {
      parent.insert(std::forward_as_tuple(std::forward<KeyFwd>(key), hook));
      return *this;
    }

    operator mapped_type&() { return parent.at(std::forward<KeyFwd>(key)); }

    mapped_type* operator->() { return &static_cast<mapped_type&>(*this); }

  private:
    hook_map& parent;
    KeyFwd&&  key;
  };

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  utils_consteval bool hook_map<K, Map, safety, map_type_args...>::is_multimap()
  {
    if constexpr (!flags::can_use_equal_range())
      return false;
    else if constexpr (flags::can_insert_regularly())
      return std::is_same_v<
          decltype(std::declval<hook_map&>().raw_standard_map_insert<true>(
              std::declval<key_type>(), adapted_mapped_type{})),
          typename adapted_map::iterator>;
    else if constexpr (flags::can_use_standard_node_relocation())
      return std::is_same_v<decltype(std::declval<adapted_map&>().insert(
                                std::declval<adapted_map&>().extract(
                                    std::declval<key_type>()))),
                            typename adapted_map::iterator>;
    else
      return false;
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <
      typename... MapInitTypes, typename Itr,
      std::enable_if_t<
          std::is_constructible_v<
              typename hook_map<K, Map, safety, map_type_args...>::adapted_map,
              MapInitTypes&&...> &&
              helpers::map_valid_init_iterator<Itr>,
          size_t>>
  hook_map<K, Map, safety, map_type_args...>::hook_map(
      map_init_args<MapInitTypes...> map_args, std::byte* target, Itr first,
      Itr last)
      : chain(target),
        map(std::make_from_tuple<adapted_map>(std::move(map_args.args)))
  {
    chain.insert(chain.end(), chain_init_iterator{ first },
                 chain_init_iterator{ last });

    if constexpr (flags::has_hash_map_capacity_api())
      map.reserve(chain.size());

    if constexpr (flags::template has_map_range_insertion<
                      map_init_iterator<Itr>>())
      map.insert(map_init_iterator{ first, chain.begin() },
                 map_init_iterator{ last, chain.end() });
    else
    {
      for (auto itr      = map_init_iterator{ first, chain.begin() },
                sentinel = map_init_iterator{ last, chain.end() };
           itr != sentinel; ++itr)
      {
        auto [key, val] = *itr;
        raw_standard_map_insert(std::forward<decltype(key)>(key), val);
      }
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename... Tuples>
  void hook_map<K, Map, safety, map_type_args...>::init_map(Tuples&&... tuples)
  {
    if constexpr (flags::has_hash_map_capacity_api())
      map.reserve(sizeof...(tuples));

    auto itr           = chain.begin();
    using init_elem_t  = std::pair<key_type, adapted_mapped_type>;
    using init_array_t = std::array<init_elem_t, sizeof...(tuples)>;

    if constexpr (flags::template has_map_range_insertion<
                      std::move_iterator<typename init_array_t::iterator>>() &&
                  sizeof...(tuples) > 1)
    {
      init_array_t init_array = { utils::apply(
          [&itr](auto&& key, auto&&...) -> init_elem_t
          {
            static_assert(std::is_constructible_v<key_type, decltype(key)>,
                          "hook_map: no known way of constructing a key_type "
                          "instance with the initial value given");
            return { static_cast<key_type>(std::forward<decltype(key)>(key)),
                     itr++ };
          },
          std::forward<Tuples>(tuples))... };
      map.insert(std::move_iterator(init_array.begin()),
                 std::move_iterator(init_array.end()));
    }
    else
    {
      (raw_standard_map_insert(utils::get<0>(std::forward<Tuples>(tuples)),
                               itr++),
       ...);
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  hook_map<K, Map, safety, map_type_args...>::hook_map(
      hook_map&& other, std::unique_lock<map_mutex_t>)
      : map(std::move(other.map))
  {
    if constexpr (adapts_concurrent_map())
    {
      std::unique_lock lock{ other.get_chain_mutex() };
      chain = std::move(other.chain);
    }
    else
      chain = std::move(other.chain);
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  auto hook_map<K, Map, safety, map_type_args...>::operator=(
      hook_map&& other) noexcept(std::is_nothrow_move_assignable_v<adapted_map>)
      -> hook_map&
  {
    if (this == &other)
      return *this;
    std::scoped_lock map_lock{ get_map_mutex(), other.get_map_mutex() };
    map = std::move(other.map);

    if constexpr (adapts_concurrent_map())
    {
      std::scoped_lock chain_lock{ get_chain_mutex(), other.get_chain_mutex() };
      chain = std::move(other.chain);
    }
    else
      chain = std::move(other.chain);
    return *this;
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <bool state, typename... Types, typename Callable>
  auto hook_map<K, Map, safety, map_type_args...>::set_status_if(
      std::tuple<Types...> args, Callable&& pred) -> size_type
  {
    constexpr bool has_pred =
        !std::is_same_v<utils::remove_cvref_t<Callable>, utils::nothing>;
    constexpr bool range_mode = []
    {
      if constexpr (sizeof...(Types) == 2)
      {
        static_assert(
            (std::is_convertible_v<Types,
                                   typename adapted_map::const_iterator> &&
             ...),
            "hook_map: range mode requested, with invalid iterators");
        return true;
      }
      else
        return false;
    }();
    constexpr bool key_mode  = sizeof...(Types) == 1;
    constexpr bool full_mode = sizeof...(Types) == 0;
    static_assert(range_mode || key_mode || full_mode,
                  "hook_map::set_status_if: invalid mode used");
    constexpr bool use_key_based_strategy = []
    {
      if constexpr (!key_mode)
        return false;
      else if constexpr (adapts_concurrent_map())
        return true;
      else
        return !is_multimap();
    }();
    constexpr bool use_range_based_strategy = []
    {
      if constexpr (use_key_based_strategy)
        return false;
      else if constexpr (range_mode || key_mode)
        return true;
      else if constexpr (adapts_concurrent_map())
        return false;
      else if constexpr (!has_pred)
        return false;
      else
        return flags::fully_iterable();
    }();
    constexpr bool use_full_visit_strategy = []
    {
      if constexpr (use_range_based_strategy || !full_mode || !has_pred)
        return false;
      else
        return flags::has_map_whole_container_visitation_api();
    }();

    std::shared_lock map_lock{ get_map_mutex() };
    if constexpr (use_key_based_strategy)
    {
      auto&&    key          = std::get<0>(std::move(args));
      size_type update_count = 0;
      auto      visitor      = [&](reference item)
      {
        if constexpr (has_pred)
        {
          if (!pred(static_cast<const_reference>(item)))
            return;
        }
        mapped_type& hook        = item.second;
        const bool   was_enabled = hook.is_enabled();
        if constexpr (state)
          hook.enable();
        else
          hook.disable();
        if (was_enabled != hook.is_enabled())
          ++update_count;
      };

      if constexpr (!adapts_concurrent_map())
      {
        auto [itr, found] = find_raw(map, std::forward<decltype(key)>(key));
        if (!found)
          return 0;
        std::unique_lock chain_lock{ get_chain_mutex() };
        auto [k, v] = extract_key_value(*itr);
        visitor({ k, *v });
      }
      else
      {
        visit_impl<helpers::visit_no_map_lock>(
            std::forward_as_tuple(std::forward<decltype(key)>(key)), visitor);
        return update_count;
      }
      return update_count;
    }
    else if constexpr (use_range_based_strategy || use_full_visit_strategy)
    {
      constexpr bulk_process_type process_type =
          state ? bulk_process_type::enable : bulk_process_type::disable;
      bulk_process<process_type> process_handler;
      auto                       visitor = [&](adapted_const_reference item)
      {
        auto [k, v] = extract_key_value(item);
        if constexpr (adapts_concurrent_map())
        {
          if (!v.is_valid())
            return;
        }
        if constexpr (has_pred)
        {
          using lock_t = std::conditional_t<adapts_concurrent_map(),
                                            std::shared_lock<chain_mutex_t>,
                                            utils::nothing>;
          lock_t chain_lock;
          if constexpr (adapts_concurrent_map())
            chain_lock = std::shared_lock{ get_chain_mutex() };

          const_reference ref = { k, *v };
          if (!pred(ref))
            return;
        }
        process_handler.add(v);
      };

      if constexpr (use_range_based_strategy)
      {
        typename adapted_map::const_iterator first{}, last{};

        if constexpr (key_mode)
        {
          auto [first_found, last_found] =
              map.equal_range(std::get<0>(std::move(args)));
          first = first_found;
          last  = last_found;
        }
        else if constexpr (full_mode)
        {
          first = map.begin();
          last  = map.end();
        }
        else
          std::tie(first, last) = args;

        if (first == last)
          return 0;

        using lock_t =
            std::conditional_t<has_pred, std::shared_lock<chain_mutex_t>,
                               utils::nothing>;
        lock_t chain_lock;
        if constexpr (has_pred)
          chain_lock = std::shared_lock{ get_chain_mutex() };

        for (auto itr = first; itr != last; ++itr)
          visitor(*itr);
      }
      else
        static_cast<const adapted_map&>(map).visit_all(visitor);

      std::unique_lock chain_lock{ get_chain_mutex() };
      return process_handler.process();
    }
    else if constexpr (full_mode)
    {
      std::unique_lock chain_lock{ get_chain_mutex() };
      size_t           count = 0;
      if constexpr (state)
        count = chain.enable_all();
      else
        count = chain.disable_all();
      return static_cast<size_type>(count);
    }
    else
      static_assert(utils::always_false<Types...>,
                    "hook_map::set_status_if: no known strategy");
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <bool must_return_iterator, typename Key, typename OptionalHint>
  decltype(auto)
      hook_map<K, Map, safety, map_type_args...>::raw_standard_map_insert(
          Key&& key, adapted_mapped_type val, OptionalHint hint)
  {
    constexpr bool has_hint = !std::is_same_v<OptionalHint, utils::nothing>;
    static_assert(std::is_convertible_v<Key&&, key_type>,
                  "hook_map: no known way of converting the key passed to the "
                  "map's key_type");

    if constexpr (has_hint)
    {
      static_assert(
          std::is_same_v<OptionalHint, typename adapted_map::const_iterator>,
          "hook_map: improper hint passed to insertor");
      if constexpr (flags::has_map_hint_try_emplace())
        return map.try_emplace(hint, std::forward<Key>(key), val);
      else if constexpr (flags::has_map_hint_emplace())
        return map.emplace_hint(hint, std::forward<Key>(key), val);
      else if constexpr (flags::has_map_hint_insert())
        return map.insert(hint, { std::forward<Key>(key), val });
      else
        static_assert(utils::always_false<Key>,
                      "hook_map: no hint insertion api supported");
    }
    else
    {
      if constexpr (flags::has_map_standard_try_emplace_method() ||
                    (flags::has_map_try_emplace_method() &&
                     !must_return_iterator))
        return map.try_emplace(std::forward<Key>(key), val);
      else if constexpr (flags::has_map_standard_emplace_method() ||
                         (flags::has_map_emplace_method() &&
                          !must_return_iterator))
        return map.emplace(std::forward<Key>(key), val);
      else if constexpr (flags::has_map_standard_insert_method() ||
                         (flags::has_map_insert_method() &&
                          !must_return_iterator))
        return map.insert({ std::forward<Key>(key), val });
      else
        static_assert(utils::always_false<Key>,
                      "hook_map: no known way of inserting an element");
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename FlagsSeq, typename... OptionalTypes, typename Key,
            typename... Types>
  auto hook_map<K, Map, safety, map_type_args...>::regular_single_insert_impl(
      const std::tuple<OptionalTypes...>& optional_args, Key&& key,
      Types&&... hook_args)
  {
    constexpr bool bulk_inserting =
        FlagsSeq::template has<helpers::insert_bulk>;
    constexpr bool has_hint = FlagsSeq::template has<helpers::insert_has_hint>;
    constexpr bool uses_or_visit =
        FlagsSeq::template has<helpers::insert_uses_or_visitation>;
    constexpr bool uses_and_visit =
        FlagsSeq::template has<helpers::insert_uses_and_visitation>;
    constexpr bool   must_return_iterator = !bulk_inserting && !is_concurrent();
    constexpr size_t callback_count       = uses_or_visit && uses_and_visit ? 2
                                            : uses_or_visit || uses_and_visit ? 1
                                                                              : 0;

    using opt_hint_t =
        std::conditional_t<has_hint, typename adapted_map::const_iterator,
                           utils::nothing>;
    opt_hint_t hint{};
    if constexpr (has_hint)
      hint = std::get<0>(optional_args);

    auto insert_ret = raw_standard_map_insert<true>(
        std::forward<decltype(key)>(key), adapted_mapped_type{}, hint);
    constexpr bool uses_const_visit = []
    {
      if constexpr (!uses_or_visit && !uses_and_visit)
        return false;
      else if constexpr (bulk_inserting)
        return true;
      else
        return FlagsSeq::template has<helpers::insert_const_visit>;
    }();
    using ref_t =
        std::conditional_t<uses_const_visit, const_reference, reference>;
    typename adapted_map::iterator pos{};

    if constexpr ((uses_or_visit || !is_multimap()) && !has_hint)
    {
      static_assert(!is_multimap(),
                    "hook_map: OR visitation not allowed for multimaps");
      pos = utils::get<0>(insert_ret);

      if (!utils::get<1>(insert_ret))
      {
        if constexpr (uses_or_visit)
        {
          auto [k, v] = extract_key_value(*pos);
          ref_t ref   = { k, *v };
          auto& or_visitor_callback =
              std::get<sizeof...(OptionalTypes) - 1>(optional_args);

          or_visitor_callback(ref);
        }

        if constexpr (!must_return_iterator)
          return;
        else
          return std::pair{ typename hook_map::iterator{ pos }, false };
      }
    }
    else if constexpr (has_hint || is_multimap())
    {
      auto [_, v] = extract_key_value(*insert_ret);
      if (v.is_valid())
        return typename hook_map::iterator{ insert_ret };
      pos = insert_ret;
    }

    auto [k, v] = extract_key_value(*pos);

    try
    {
      v = chain.push_back({ std::forward<decltype(hook_args)>(hook_args)... })
              .get_iterator();
    }
    catch (...)
    {
      map.erase(pos);
      throw;
    }

    if constexpr (uses_and_visit)
    {
      ref_t ref = { k, *v };
      auto& and_visitor_callback =
          std::get<sizeof...(OptionalTypes) - callback_count>(optional_args);

      and_visitor_callback(ref);
    }

    if constexpr (!must_return_iterator)
      return;
    else if constexpr (!is_multimap() && !has_hint)
      return std::pair{ typename hook_map::iterator{ pos }, true };
    else
      return typename hook_map::iterator{ pos };
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename FlagsSeq, typename... OptionalTypes, typename LoopFunctor>
  auto hook_map<K, Map, safety, map_type_args...>::regular_insert_impl(
      const std::tuple<OptionalTypes...>& optional_args, LoopFunctor&& loop)
  {
    constexpr bool bulk_inserting =
        FlagsSeq::template has<helpers::insert_bulk>;
    constexpr bool must_return_iterator = !bulk_inserting && !is_concurrent();

    std::unique_lock lock{ get_map_mutex() };
    const size_type  prev_size = map.size();
    auto             single_insertor =
        [this, &optional_args](auto&& key, auto&&... hook_args)
    {
      return regular_single_insert_impl<FlagsSeq>(
          optional_args, std::forward<decltype(key)>(key),
          std::forward<decltype(hook_args)>(hook_args)...);
    };

    if constexpr (!must_return_iterator)
    {
      loop(single_insertor);
      return map.size() - prev_size;
    }
    else
      return loop(single_insertor);
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename FlagsSeq, typename... OptionalTypes, typename LoopFunctor>
  auto hook_map<K, Map, safety, map_type_args...>::visit_based_insert_impl(
      const std::tuple<OptionalTypes...>& optional_args, LoopFunctor&& loop)
      -> size_type
  {
    constexpr bool can_cleanup_on_exception = std::conjunction_v<
        std::bool_constant<flags::has_map_key_based_erase_if()>,
        std::is_default_constructible<key_type>,
        std::is_copy_assignable<key_type>>;
    constexpr bool uses_and_visit =
        FlagsSeq::template has<helpers::insert_uses_and_visitation>;
    constexpr bool uses_or_visit =
        FlagsSeq::template has<helpers::insert_uses_or_visitation>;
    constexpr bool uses_const_visit = []
    {
      if constexpr (!uses_and_visit && !uses_or_visit)
        return false;
      else if constexpr (FlagsSeq::template has<helpers::insert_bulk>)
        return true;
      else
        return FlagsSeq::template has<helpers::insert_const_visit>;
    }();
    constexpr size_t callback_count = uses_and_visit && uses_or_visit   ? 2
                                      : uses_and_visit || uses_or_visit ? 1
                                                                        : 0;
    using ref_t =
        std::conditional_t<uses_const_visit, const_reference, reference>;
    using failed_key_t =
        std::conditional_t<can_cleanup_on_exception, key_type, utils::nothing>;

    size_type    inserted_count         = 0;
    bool         failed_chain_insertion = false;
    failed_key_t failed_key{};

    auto and_visitor = [&](adapted_reference item, auto&&... hook_args)
    {
      auto [k, v] = extract_key_value(item);
      std::unique_lock lock{ get_chain_mutex() };

      if constexpr (can_cleanup_on_exception)
      {
        try
        {
          v = chain
                  .push_back(
                      { std::forward<decltype(hook_args)>(hook_args)... })
                  .get_iterator();
        }
        catch (...)
        {
          failed_key             = k;
          failed_chain_insertion = true;
          throw;
        }
      }
      else
        v = chain.push_back({ std::forward<decltype(hook_args)>(hook_args)... })
                .get_iterator();

      if constexpr (uses_and_visit)
      {
        ref_t ref = { k, *v };
        auto& and_visitor_callback =
            std::get<sizeof...(OptionalTypes) - callback_count>(optional_args);

        and_visitor_callback(ref);
      }
      ++inserted_count;
    };
    auto or_visitor = [&](adapted_reference elem, auto&&... hook_args)
    {
      auto [k, v] = extract_key_value(elem);
      if (!v.is_valid())
      {
        and_visitor(elem, std::forward<decltype(hook_args)>(hook_args)...);
        return;
      }

      if constexpr (uses_or_visit)
      {
        using lock_t = std::conditional_t<uses_const_visit,
                                          std::shared_lock<chain_mutex_t>,
                                          std::unique_lock<chain_mutex_t>>;

        lock_t lock{ get_chain_mutex() };
        ref_t  ref = { k, *v };
        auto&  or_visitor_callback =
            std::get<sizeof...(OptionalTypes) - 1>(optional_args);

        or_visitor_callback(ref);
      }
    };
    auto inserter = [this, &inserted_count, &and_visitor,
                     &or_visitor](auto&& key, auto&&... hook_args)
    {
      auto make_wrapper = [&hook_args...](auto& func)
      {
        return [&func, &hook_args...](adapted_reference item)
        { return func(item, std::forward<decltype(hook_args)>(hook_args)...); };
      };
      auto and_visitor_wrapper = make_wrapper(and_visitor);
      auto or_visitor_wrapper  = make_wrapper(or_visitor);

      if constexpr (flags::has_map_try_emplace_and_visit_method())
        map.try_emplace_and_visit(std::forward<decltype(key)>(key),
                                  adapted_mapped_type{}, and_visitor_wrapper,
                                  or_visitor_wrapper);
      else if constexpr (flags::has_map_emplace_and_visit_method())
        map.emplace_and_visit(std::forward<decltype(key)>(key),
                              adapted_mapped_type{}, and_visitor_wrapper,
                              or_visitor_wrapper);
      else if constexpr (flags::has_map_insert_and_visit_method())
        map.insert_and_visit(
            { std::forward<decltype(key)>(key), adapted_mapped_type{} },
            and_visitor_wrapper, or_visitor_wrapper);
      else
        static_assert(utils::always_false<decltype(key)>,
                      "hook_map: no suitable implementation of insertion and "
                      "visitation found in the adapted map");
    };

    if constexpr (can_cleanup_on_exception)
    {
      try
      {
        loop(inserter);
      }
      catch (...)
      {
        if (!failed_chain_insertion)
          throw;
        map.erase_if(std::move(failed_key),
                     [](adapted_const_reference item)
                     {
                       auto [k, v] = extract_key_value(item);
                       return !v.is_valid();
                     });
        throw;
      }
    }
    else
      loop(inserter);

    return inserted_count;
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename... Flags, typename... OptionalTypes, typename... Tuples>
  auto hook_map<K, Map, safety, map_type_args...>::insert_impl(
      const std::tuple<OptionalTypes...>& optional_args, Tuples&&... entries)
  {
    using FlagsSeq      = utils::type_sequence<Flags...>;
    using FlagsSeqFinal = std::conditional_t<
        (sizeof...(entries) > 1),
        typename FlagsSeq::template push_back<helpers::insert_bulk>, FlagsSeq>;
    constexpr bool use_regular_insert = []
    {
      constexpr bool has_hint =
          FlagsSeq::template has<helpers::insert_has_hint>;

      if constexpr (has_hint)
        return true;
      else
        return flags::can_use_regular_insertion_strategy();
    }();
    auto loop = [&entries...](auto& inserter)
    { return (utils::apply(inserter, std::forward<Tuples>(entries)), ...); };

    if constexpr (use_regular_insert)
      return regular_insert_impl<FlagsSeqFinal>(optional_args, loop);
    else
      return visit_based_insert_impl<FlagsSeqFinal>(optional_args, loop);
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename... Flags, typename... OptionalTypes, typename Itr>
  auto hook_map<K, Map, safety, map_type_args...>::insert_range_impl(
      const std::tuple<OptionalTypes...>& optional_args, Itr first, Itr last)
      -> size_type
  {
    using FlagsSeq = utils::type_sequence<Flags..., helpers::insert_bulk>;

    if (first == last)
      return 0;
    auto loop = [first, last](auto& inserter)
    {
      for (Itr itr = first; itr != last; ++itr)
        utils::apply(inserter, *itr);
    };

    if constexpr (flags::can_use_regular_insertion_strategy())
      return regular_insert_impl<FlagsSeq>(optional_args, loop);
    else
      return visit_based_insert_impl<FlagsSeq>(optional_args, loop);
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename Target, typename... Tuples>
  constexpr auto
      hook_map<K, Map, safety, map_type_args...>::chain_init_array_from_tuples(
          Tuples&&... tuples) -> chain_init_array_t<Target, sizeof...(Tuples)>
  {
    return { utils::apply(
        [](auto&&, auto&&... hook_args)
            -> hook_chain::init_type<utils::remove_cvref_t<Target>>
        { return { std::forward<decltype(hook_args)>(hook_args)... }; },
        std::forward<Tuples>(tuples))... };
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename Func>
  auto
      hook_map<K, Map, safety, map_type_args...>::erase_return_wrap(Func&& func)
  {
    using ret_t = decltype(func());

    if constexpr (std::disjunction_v<
                      std::is_same<ret_t, typename adapted_map::iterator>,
                      std::is_same<ret_t,
                                   typename adapted_map::const_iterator>>)
    {
      using itr_t = std::conditional_t<
          std::is_same_v<ret_t, typename adapted_map::iterator>,
          typename hook_map::iterator, typename hook_map::const_iterator>;
      return itr_t{ func() };
    }
    else
      return erase_return_proxy{ std::forward<Func>(func) };
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename InvokeRef, typename Func, typename... Types>
  auto hook_map<K, Map, safety, map_type_args...>::unwrap_visitors_and_invoke(
      Func&& func, Types&&... args)
  {
    constexpr size_t callable_count =
        utils::type_sequence<Types...>::template reversed<>::
            template take_while<helpers::map_callable_requirement_enclosure<
                InvokeRef>::template check>::size;
    auto args_tuple = std::forward_as_tuple(std::forward<Types>(args)...);
    auto tuples     = utils::tuple_slice<0, sizeof...(args) - callable_count>(
        std::move(args_tuple));
    auto visitors =
        utils::tuple_slice<sizeof...(args) - callable_count, sizeof...(args)>(
            std::move(args_tuple));
    return std::apply(
        [&func, &visitors](auto&&... tuples_unwrapped)
        {
          return func(
              std::integral_constant<size_t, callable_count>{},
              std::move(visitors),
              std::forward<decltype(tuples_unwrapped)>(tuples_unwrapped)...);
        },
        std::move(tuples));
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename Callable1, typename Callable2>
  auto hook_map<K, Map, safety, map_type_args...>::pack_visitors(
      Callable1&& and_visitor, Callable2&& or_visitor)
  {
    if constexpr (std::is_same_v<utils::remove_cvref_t<Callable2>,
                                 utils::nothing>)
      return std::tie(and_visitor);
    else
      return std::tie(and_visitor, or_visitor);
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename Key1, typename Key2>
  bool hook_map<K, Map, safety, map_type_args...>::rekey_impl(Key1&& old_key,
                                                              Key2&& new_key)
  {
    std::unique_lock lock{ get_map_mutex() };
    auto             equal_keys = [&]
    {
      if constexpr (flags::provides_equality_comparator())
        return map.key_eq()(old_key, new_key);
      else if constexpr (flags::has_ordered_map_key_comparison())
        return !map.key_comp()(old_key, new_key) &&
               !map.key_comp()(new_key, old_key);
      else
        return old_key == new_key;
    };

    if (equal_keys())
      return contains_impl(new_key);

    if constexpr (flags::has_map_node_relocation())
    {
      auto extract_insert_one = [this, &old_key](auto&& key)
      {
        auto node = map.extract(old_key);
        if (node.empty())
          return false;
        try
        {
          node.key() = std::forward<decltype(key)>(key);
        }
        catch (...)
        {
          map.insert(std::move(node));
          throw;
        }
        map.insert(std::move(node));
        return true;
      };

      if constexpr (!is_multimap())
      {
        if (contains_impl(new_key))
          return false;

        return extract_insert_one(std::forward<Key2>(new_key));
      }
      else
      {
        bool success = false;

        while (extract_insert_one(new_key))
        {
          success = true;
        }

        return success;
      }
    }
    else
    {
      if constexpr (!is_multimap())
      {
        if constexpr (!flags::can_insert_regularly())
        {
          if (contains_impl(new_key))
            return false;
        }
        auto oldpos = find_impl(map, old_key).unwrap();
        if (oldpos == map.end())
          return false;
        adapted_mapped_type val = extract_key_value(*oldpos).second;

        if constexpr (flags::can_insert_regularly())
        {
          auto [pos, inserted] =
              raw_standard_map_insert<true>(std::forward<Key2>(new_key), val);
          if (!inserted)
            return false;
        }
        else
          raw_standard_map_insert(std::forward<Key2>(new_key), val);
        map.erase(old_key);
        return true;
      }
      else
      {
        auto [first, last] = map.equal_range(old_key);
        if (first == last)
          return false;

        size_t                           inserted_count = 0;
        std::vector<adapted_mapped_type> vals;
        vals.reserve(detail::constants::max_reserve < map.size()
                         ? detail::constants::max_reserve
                         : map.size());

        for (auto itr = first; itr != last; ++itr)
          vals.push_back(extract_key_value(*itr).second);

        try
        {
          for (auto val : vals)
          {
            raw_standard_map_insert(new_key, val);
            ++inserted_count;
          }
        }
        catch (...)
        {
          if (!inserted_count)
            throw;

          for (size_t i = 0; i != inserted_count; ++i)
          {
            auto [current, end] = map.equal_range(new_key);
            auto result =
                std::find_if(current, end, [val = vals[i]](auto& item)
                             { return extract_key_value(item).second == val; });
            if (result != end)
              map.erase(result);
          }
          throw;
        }

        map.erase(old_key);
        return true;
      }
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename Adapted, typename KeyFwd>
  auto& hook_map<K, Map, safety, map_type_args...>::at_impl(Adapted&& map,
                                                            KeyFwd&&  key)
  {
    if constexpr (flags::has_map_at_method())
      return *map.at(std::forward<KeyFwd>(key));
    else
    {
      auto itr = map.find(std::forward<KeyFwd>(key));
      if (itr == map.end())
        throw std::out_of_range(
            "hook_map: read access to a non-existing element");
      return *(extract_key_value(*itr).second);
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename Adapted, typename KeyFwd>
  auto hook_map<K, Map, safety, map_type_args...>::find_raw(Adapted&& map,
                                                            KeyFwd&&  key)
      -> std::pair<adapted_iterator_t<Adapted>, bool>
  {
    if constexpr (flags::can_use_standard_find())
    {
      auto result = map.find(std::forward<KeyFwd>(key));
      return { result, result != map.end() };
    }
    else
    {
      auto [first, last] = map.equal_range(std::forward<KeyFwd>(key));
      return { first, first != last };
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename Adapted, typename KeyFwd>
  auto hook_map<K, Map, safety, map_type_args...>::find_impl(Adapted&& map,
                                                             KeyFwd&&  key)
  {
    using adapted_raw = std::remove_reference_t<Adapted>;
    using itr_t       = std::conditional_t<std::is_const_v<adapted_raw>,
                                           typename hook_map::const_iterator,
                                           typename hook_map::iterator>;

    if constexpr (flags::can_use_standard_find())
      return itr_t{ map.find(std::forward<KeyFwd>(key)) };
    else
    {
      auto [first, last] = map.equal_range(std::forward<KeyFwd>(key));
      if (first == last)
        return itr_t{ map.end() };
      return itr_t{ first };
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename Adapted, typename KeyFwd>
  auto hook_map<K, Map, safety, map_type_args...>::equal_range_impl(
      Adapted&& map, KeyFwd&& key)
  {
    using adapted_raw  = std::remove_reference_t<Adapted>;
    using itr_t        = std::conditional_t<std::is_const_v<adapted_raw>,
                                            typename hook_map::const_iterator,
                                            typename hook_map::iterator>;
    using ret_t        = std::pair<itr_t, itr_t>;
    auto [first, last] = map.equal_range(std::forward<KeyFwd>(key));
    return ret_t{ itr_t{ first }, itr_t{ last } };
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename KeyFwd>
  auto
      hook_map<K, Map, safety, map_type_args...>::count_impl(KeyFwd&& key) const
      -> size_type
  {
    std::shared_lock lock{ get_map_mutex() };
    if constexpr (adapts_concurrent_map())
    {
      size_type count = 0;
      if constexpr (flags::has_map_basic_visitation_api())
        map.visit(std::forward<KeyFwd>(key),
                  [&count](adapted_const_reference item)
                  {
                    auto [_, v] = extract_key_value(item);
                    if (v.is_valid())
                      ++count;
                  });
      else
        map.find_fn(std::forward<KeyFwd>(key),
                    [&count](const adapted_mapped_type& v)
                    {
                      if (v.is_valid())
                        ++count;
                    });
      return count;
    }
    else if constexpr (flags::has_map_count_method())
      return map.count(std::forward<KeyFwd>(key));
    else if constexpr (flags::can_use_equal_range())
    {
      auto [first, last] = map.equal_range(std::forward<KeyFwd>(key));
      return static_cast<size_type>(utils::iter::distance(first, last));
    }
    else
      return map.find(std::forward<KeyFwd>(key)) != map.end() ? 1 : 0;
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <bool grab_lock, typename KeyFwd>
  bool hook_map<K, Map, safety, map_type_args...>::contains_impl(
      KeyFwd&& key) const
  {
    std::shared_lock<map_mutex_t> lock;
    if constexpr (grab_lock)
      lock = std::shared_lock{ get_map_mutex() };

    if constexpr (adapts_concurrent_map())
    {
      bool found = false;

      if constexpr (flags::has_map_basic_visitation_api())
        map.visit(std::forward<KeyFwd>(key),
                  [&found](adapted_const_reference item)
                  {
                    auto [_, v] = extract_key_value(item);
                    found       = v.is_valid();
                  });
      else
        map.find_fn(std::forward<KeyFwd>(key),
                    [&found](const adapted_mapped_type& v)
                    { found = v.is_valid(); });
      return found;
    }
    else if constexpr (flags::has_map_contains_method())
      return map.contains(std::forward<KeyFwd>(key));
    else if constexpr (flags::can_use_standard_find())
      return map.find(std::forward<KeyFwd>(key)) != map.end();
    else
    {
      auto [first, last] = map.equal_range(std::forward<KeyFwd>(key));
      return first != last;
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename... Flags, typename... Types, typename Callable>
  auto hook_map<K, Map, safety, map_type_args...>::visit_impl(
      std::tuple<Types...> args, Callable&& visitor) const -> size_type
  {
    using FlagsSeq            = utils::type_sequence<Flags...>;
    constexpr bool key_mode   = sizeof...(Types) == 1;
    constexpr bool range_mode = sizeof...(Types) == 2;
    constexpr bool conditional_mode =
        FlagsSeq::template has<helpers::visit_conditional>;
    constexpr bool full_mode = sizeof...(Types) == 0 && !conditional_mode;
    static_assert(
        !(key_mode && conditional_mode),
        "hook_map::visit: cannot select both key mode and conditional");
    constexpr bool use_lock =
        !FlagsSeq::template has<helpers::visit_no_map_lock>;
    constexpr bool use_const_visitation =
        FlagsSeq::template has<helpers::visit_const> || !key_mode;

    constexpr bool use_cuckoo_visit = []
    {
      if constexpr (!key_mode && !range_mode)
        return false;
      else
        return flags::has_cuckoo_map_visitation_api();
    }();
    constexpr bool use_single_visit = []
    {
      if constexpr (!key_mode && !range_mode)
        return false;
      else if constexpr (adapts_concurrent_map())
        return true;
      else
        return !is_multimap();
    }();
    constexpr bool use_range_visitor_api = []
    {
      if constexpr (!range_mode || !adapts_concurrent_map() || use_cuckoo_visit)
        return false;
      else
        return flags::template has_map_range_visitation_api<
            std::tuple_element_t<0, decltype(args)>>();
    }();

    using map_lock_t =
        std::conditional_t<use_lock, std::shared_lock<map_mutex_t>,
                           utils::nothing>;
    using chain_lock_t = std::conditional_t<use_const_visitation,
                                            std::shared_lock<chain_mutex_t>,
                                            std::unique_lock<chain_mutex_t>>;
    using ref_t =
        std::conditional_t<use_const_visitation, const_reference, reference>;

    size_type  count = 0;
    map_lock_t map_lock;
    if constexpr (use_lock)
      map_lock = std::shared_lock{ get_map_mutex() };

    if constexpr (use_cuckoo_visit)
    {
      auto invoker = [&](const key_type& key)
      {
        map.find_fn(key,
                    [&](adapted_mapped_type val)
                    {
                      if (!val.is_valid())
                        return;
                      chain_lock_t chain_lock{ get_chain_mutex() };
                      ref_t        ref = { key, *val };
                      visitor(ref);
                      ++count;
                    });
      };

      if constexpr (key_mode)
        invoker(std::get<0>(std::move(args)));
      else
      {
        auto [first, last] = args;
        for (auto itr = first; itr != last; ++itr)
          invoker(*itr);
      }
    }
    else
    {
      constexpr bool use_inner_lock =
          use_single_visit || adapts_concurrent_map();
      constexpr bool increment_counter = adapts_concurrent_map() || !full_mode;

      auto visitor_wrapper = [&](adapted_const_reference item)
      {
        using inner_chain_lock_t =
            std::conditional_t<use_inner_lock, chain_lock_t, utils::nothing>;
        auto [k, v] = extract_key_value(item);
        if constexpr (adapts_concurrent_map())
        {
          if (!v.is_valid())
          {
            if constexpr (conditional_mode)
              return true;
            else
              return;
          }
        }
        inner_chain_lock_t chain_lock;
        if constexpr (use_inner_lock)
          chain_lock = chain_lock_t{ get_chain_mutex() };

        ref_t ref = { k, *v };
        if constexpr (conditional_mode)
        {
          bool result = visitor(ref);
          if constexpr (increment_counter)
            ++count;
          return result;
        }
        else
        {
          visitor(ref);
          if constexpr (increment_counter)
            ++count;
        }
      };

      if constexpr (use_range_visitor_api)
      {
        auto [first, last] = args;
        map.visit(first, last, visitor_wrapper);
      }
      else if constexpr (use_single_visit)
      {
        auto single_visit = [&](auto&& key)
        {
          if constexpr (adapts_concurrent_map())
            map.visit(std::forward<decltype(key)>(key), visitor_wrapper);
          else
          {
            auto [itr, found] = find_raw(map, std::forward<decltype(key)>(key));
            if (!found)
              return;
            visitor_wrapper(*itr);
          }
        };

        if constexpr (range_mode)
        {
          using outer_lock_t =
              std::conditional_t<!use_inner_lock, chain_lock_t, utils::nothing>;
          outer_lock_t chain_lock;
          if constexpr (!use_inner_lock)
            chain_lock = chain_lock_t{ get_chain_mutex() };

          auto [first, last] = args;
          for (auto itr = first; itr != last; ++itr)
            single_visit(*itr);
        }
        else
          single_visit(std::get<0>(std::move(args)));
      }
      else if constexpr (adapts_concurrent_map())
      {
        if constexpr (conditional_mode)
          map.visit_while(visitor_wrapper);
        else
          map.visit_all(visitor_wrapper);
      }
      else
      {
        auto bulk_visit = [&](typename adapted_map::const_iterator first,
                              typename adapted_map::const_iterator last)
        {
          for (auto itr = first; itr != last; ++itr)
          {
            if constexpr (conditional_mode)
            {
              if (!visitor_wrapper(*itr))
                break;
            }
            else
              visitor_wrapper(*itr);
          }
        };

        std::shared_lock chain_lock{ get_chain_mutex() };

        if constexpr (!range_mode)
        {
          typename adapted_map::const_iterator first{}, last{};

          if constexpr (key_mode)
          {
            auto [first_found, last_found] =
                map.equal_range(std::get<0>(std::move(args)));
            first = first_found;
            last  = last_found;
          }
          else
          {
            first = map.begin();
            last  = map.end();
          }

          bulk_visit(first, last);

          if constexpr (!increment_counter)
            count = map.size();
        }
        else
        {
          auto [first, last] = args;
          for (auto itr = first; itr != last; ++itr)
          {
            auto [first_found, last_found] = map.equal_range(*itr);
            bulk_visit(first_found, last_found);
          }
        }
      }
    }
    return count;
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename... types, typename Pred>
  auto hook_map<K, Map, safety, map_type_args...>::erase_impl(
      std::tuple<types...> args, Pred&& pred)
  {
    constexpr bool uses_pred =
        !std::is_same_v<utils::remove_cvref_t<Pred>, utils::nothing>;
    constexpr bool iterator_mode = []
    {
      if constexpr (sizeof...(types) == 1 || sizeof...(types) == 2)
        return std::conjunction_v<std::is_convertible<
            types, typename adapted_map::const_iterator>...>;
      else
        return false;
    }();
    constexpr bool key_mode  = sizeof...(types) == 1 && !iterator_mode;
    constexpr bool full_mode = sizeof...(types) == 0;
    static_assert(
        iterator_mode || key_mode || full_mode,
        "hook_map::erase: cannot determine mode from the arguments used");
    constexpr bool use_clear_path = []
    {
      if constexpr (!full_mode || uses_pred)
        return false;
      else if constexpr (adapts_concurrent_map())
        return false;
      else if constexpr (flags::has_map_basic_erasure())
        return true;
      else
        return flags::can_use_iterator_based_clear_strategy();
    }();
    constexpr bool use_iterator_erasure_path = []
    {
      if constexpr (use_clear_path)
        return false;
      else if constexpr (full_mode)
        return !adapts_concurrent_map();
      else if constexpr (iterator_mode)
        return true;
      else if constexpr (key_mode)
        return flags::can_use_lookup_and_erase_strategy();
      else
        return false;
    }();

    std::unique_lock lock{ get_map_mutex() };
    if constexpr (use_clear_path)
    {
      chain.clear();
      if constexpr (flags::has_map_basic_erasure())
        map.clear();
      else
        map.erase(map.begin(), map.end());
    }
    else if constexpr (use_iterator_erasure_path)
    {
      constexpr bool use_single_iterator_erasure = []
      {
        if constexpr (key_mode)
          return !is_multimap();
        else
          return iterator_mode && sizeof...(types) == 1;
      }();
      using adapted_itr_t =
          std::conditional_t<flags::has_map_const_iterator_erasure(),
                             typename adapted_map::const_iterator,
                             typename adapted_map::iterator>;

      auto erase_single = [this, &pred](adapted_itr_t itr)
      {
        auto [k, v] = extract_key_value(*itr);
        if constexpr (uses_pred)
        {
          const_reference ref = { k, *v };
          if (!pred(ref))
            return size_type{ 0 };
        }

        chain.erase(v);
        if constexpr (iterator_mode && !uses_pred)
          return erase_return_wrap([this, itr]() -> decltype(auto)
                                   { return map.erase(itr); });
        else
        {
          map.erase(itr);
          return size_type{ 1 };
        }
      };

      if constexpr (use_single_iterator_erasure)
      {
        adapted_itr_t itr{};
        if constexpr (key_mode)
        {
          auto [iterator, found] = find_raw(map, std::get<0>(std::move(args)));
          if (!found)
            return size_type{ 0 };
          itr = iterator;
        }
        else
          itr = std::get<0>(args);

        return erase_single(itr);
      }
      else
      {
        constexpr bool return_count = uses_pred || key_mode;
        using itrs_t = std::conditional_t<!uses_pred, std::monostate,
                                          std::vector<adapted_itr_t>>;

        adapted_itr_t first{};
        adapted_itr_t last{};

        if constexpr (full_mode)
        {
          first = map.begin();
          last  = map.end();
        }
        else if constexpr (key_mode)
        {
          auto [first_found, last_found] =
              map.equal_range(std::get<0>(std::move(args)));
          first = first_found;
          last  = last_found;
        }
        else
          std::tie(first, last) = args;

        if (first == last)
        {
          if constexpr (return_count)
            return size_type{ 0 };
          else
            return erase_return_wrap([this, last]() -> decltype(auto)
                                     { return map.erase(last, last); });
        }
        if (std::next(first) == last)
          return erase_single(first);

        itrs_t       itrs{};
        size_type    count = 0;
        bulk_cleanup cleanup_handler;

        if constexpr (uses_pred)
          itrs.reserve(detail::constants::max_reserve < chain.size()
                           ? detail::constants::max_reserve
                           : chain.size());

        for (auto itr = first; itr != last; ++itr)
        {
          auto [k, v] = extract_key_value(*itr);
          if constexpr (return_count)
            ++count;
          if constexpr (uses_pred)
          {
            const_reference ref = { k, *v };
            if (!pred(ref))
              continue;
            itrs.push_back(itr);
          }
          cleanup_handler.add(v);
        }
        cleanup_handler.process();

        if constexpr (!uses_pred)
        {
          if constexpr (return_count)
          {
            map.erase(first, last);
            return count;
          }
          else
            return erase_return_wrap([this, first, last]() -> decltype(auto)
                                     { return map.erase(first, last); });
        }
        else
        {
          if (count == itrs.size())
            map.erase(first, last);
          else
          {
            for (auto itr = itrs.rbegin(); itr != itrs.rend(); ++itr)
              map.erase(*itr);
          }
          return size_type{ itrs.size() };
        }
      }
    }
    else
    {
      using unique_chain_lock_t =
          std::conditional_t<key_mode, std::unique_lock<chain_mutex_t>,
                             utils::nothing>;
      using shared_chain_lock_t =
          std::conditional_t<full_mode, std::shared_lock<chain_mutex_t>,
                             utils::nothing>;
      using cleanup_t =
          std::conditional_t<full_mode, bulk_cleanup, utils::nothing>;

      size_type count = 0;
      cleanup_t cleanup_handler;

      auto erase_pred = [&](adapted_const_reference item)
      {
        auto [k, v] = extract_key_value(item);
        if (!v.is_valid())
          return true;
        unique_chain_lock_t chain_lock1;
        if constexpr (key_mode)
          chain_lock1 = std::unique_lock{ get_chain_mutex() };

        if constexpr (uses_pred)
        {
          shared_chain_lock_t chain_lock2;
          if constexpr (full_mode)
            chain_lock2 = std::shared_lock{ get_chain_mutex() };
          const_reference ref = { k, *v };
          if (!pred(ref))
            return false;
        }

        if constexpr (key_mode)
        {
          chain.erase(v);
          ++count;
        }
        else
          cleanup_handler.add(v);
        return true;
      };

      if constexpr (key_mode)
      {
        map.erase_if(std::get<0>(std::move(args)), erase_pred);
        return count;
      }
      else if constexpr (full_mode)
      {
        map.erase_if(erase_pred);

        std::unique_lock chain_lock{ get_chain_mutex() };
        count = cleanup_handler.process();
        if constexpr (uses_pred)
          return count;
      }
      else
        static_assert(utils::always_false<types...>,
                      "hook_map: no known way of erasing the element(s) given "
                      "the parameters");
    }
  }

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_args>
  struct hook_map<K, Map, safety, map_args...>::flags
      : detail::hook_map_basic_flags<adapted_map>
  {
    using immutable = detail::hook_map_basic_flags<const adapted_map>;

    template <bool const_iterators = false>
    static utils_consteval bool has_iterators()
    {
      return utils::iter::has_valid_forward_iterators<
          adapted_t<const_iterators>>;
    }

    template <bool const_iterators = false>
    static utils_consteval bool has_bidirectional_iterators()
    {
      return utils::iter::has_valid_bidirectional_iterators<
          adapted_t<const_iterators>>;
    }

    template <bool const_iterators = false>
    static utils_consteval bool has_local_iterators()
    {
      return utils::iter::has_valid_forward_local_iterators<
          adapted_t<const_iterators>>;
    }

    template <bool const_iterators = false>
    static utils_consteval bool can_adapt_iterators()
    {
      if constexpr (is_concurrent())
        return false;
      else
        return has_iterators<const_iterators>();
    }

    template <bool const_iterators = false>
    static utils_consteval bool can_adapt_reverse_iterators()
    {
      if constexpr (is_concurrent())
        return false;
      else
        return has_bidirectional_iterators<const_iterators>();
    }

    template <bool const_iterators = false>
    static utils_consteval bool can_adapt_bucket_iteration()
    {
      if constexpr (is_concurrent())
        return false;
      else
        return has_local_iterators<const_iterators>();
    }

    static utils_consteval bool can_adapt_single_state_update()
    {
      if constexpr (adapts_concurrent_map())
        return base::has_map_basic_visit_method();
      else if constexpr (is_multimap())
        return true;
      else
        return can_use_single_standard_lookup();
    }

    static utils_consteval bool can_adapt_range_state_update()
    {
      if constexpr (is_concurrent())
        return false;
      else
        return has_iterators();
    }

    static utils_consteval bool can_adapt_conditional_full_state_update()
    {
      if constexpr (adapts_concurrent_map())
        return base::has_map_visit_all_method();
      else
        return has_iterators();
    }

    template <bool const_lookup = false>
    static utils_consteval bool can_adapt_at_method()
    {
      if constexpr (is_concurrent())
        return false;
      else if constexpr (flags_t<const_lookup>::has_map_at_method())
        return true;
      else
        return can_use_single_standard_lookup<const_lookup>();
    }

    static utils_consteval bool can_adapt_access_operator()
    {
      if constexpr (!can_adapt_at_method())
        return false;
      else
        return can_adapt_element_insertion();
    }

    template <bool const_lookup = false>
    static utils_consteval bool can_adapt_find_method()
    {
      if constexpr (is_concurrent())
        return false;
      else
        return can_use_single_standard_lookup<const_lookup>();
    }

    template <bool const_lookup = false>
    static utils_consteval bool can_adapt_equal_range()
    {
      if constexpr (is_concurrent())
        return false;
      else
        return can_use_equal_range<const_lookup>();
    }

    static utils_consteval bool can_adapt_count_method()
    {
      if constexpr (adapts_concurrent_map())
        return true;
      else if constexpr (immutable::has_map_count_method())
        return true;
      else
        return can_use_standard_lookup<true>();
    }

    static utils_consteval bool can_adapt_contains_method()
    {
      if constexpr (adapts_concurrent_map())
        return true;
      else if constexpr (immutable::has_map_contains_method())
        return true;
      else
        return can_use_single_standard_lookup<true>();
    }

    template <bool const_visit = false>
    static utils_consteval bool can_adapt_element_visitor_method()
    {
      if constexpr (!is_concurrent())
        return false;
      else if constexpr (adapts_concurrent_map())
        return flags_t<const_visit>::has_map_basic_visit_method();
      else
        return can_use_standard_lookup<const_visit>();
    }

    template <typename Itr, bool const_visit = false>
    static utils_consteval bool can_adapt_range_visitor_method()
    {
      if constexpr (!is_concurrent())
        return false;
      else if constexpr (!utils::iter::is_iterator_yielding<Itr, key_type,
                                                            const key_type&>)
        return false;
      else if constexpr (flags_t<const_visit>::
                             template has_map_range_visit_method<Itr>())
        return true;
      else
        return can_adapt_element_visitor_method<const_visit>();
    }

    template <bool const_visit = false>
    static utils_consteval bool can_adapt_full_visitor_method()
    {
      if constexpr (!is_concurrent())
        return false;
      else if constexpr (adapts_concurrent_map())
        return flags_t<const_visit>::has_map_visit_all_method();
      else
        return has_iterators<const_visit>();
    }

    template <bool const_visit = false>
    static utils_consteval bool can_adapt_conditional_visitor_method()
    {
      if constexpr (!is_concurrent())
        return false;
      else if constexpr (adapts_concurrent_map())
        return flags_t<const_visit>::has_map_visit_while_method();
      else
        return has_iterators<const_visit>();
    }

    static utils_consteval bool can_adapt_key_erasure()
    {
      if constexpr (adapts_concurrent_map())
        return base::has_map_key_erase_if_method();
      else
        return can_use_lookup_and_erase_strategy();
    }

    static utils_consteval bool can_adapt_iterator_erasure()
    {
      if constexpr (is_concurrent())
        return false;
      else if constexpr (!base::has_map_iterator_erase_method())
        return false;
      else
        return has_iterators();
    }

    static utils_consteval bool can_adapt_range_erasure()
    {
      if constexpr (is_concurrent())
        return false;
      else if constexpr (!base::has_map_range_erase_method())
        return false;
      else
        return has_iterators();
    }

    static utils_consteval bool can_adapt_clear()
    {
      if constexpr (adapts_concurrent_map())
        return base::has_map_full_erase_if_method();
      else if constexpr (base::has_map_clear_method())
        return true;
      else
        return can_use_iterator_based_clear_strategy();
    }

    static utils_consteval bool can_adapt_conditional_full_erasure()
    {
      if constexpr (adapts_concurrent_map())
        return base::has_map_full_erase_if_method();
      else
        return can_use_iterator_based_clear_strategy();
    }

    static utils_consteval bool can_adapt_element_insertion()
    {
      if constexpr (adapts_concurrent_map())
        return can_use_visit_based_insertion_strategy();
      else
        return can_use_regular_insertion_strategy();
    }

    static utils_consteval bool can_adapt_insertion_with_visitation()
    {
      if constexpr (!is_concurrent())
        return false;
      else
        return can_adapt_element_insertion();
    }

    static utils_consteval bool can_adapt_hint_insertion()
    {
      if constexpr (is_concurrent())
        return false;
      else if constexpr (!can_use_hint_insertion())
        return false;
      else if constexpr (!base::has_map_iterator_erase_method())
        return false;
      else
        return has_iterators();
    }

    static utils_consteval bool can_adapt_rekey()
    {
      if constexpr (adapts_concurrent_map())
        return false;
      else if constexpr (!can_adapt_contains_method())
        return false;
      else if constexpr (base::has_map_node_relocation())
        return true;
      else if constexpr (!can_use_standard_lookup())
        return false;
      else if constexpr (!can_insert_regularly())
        return false;
      else
        return base::has_map_iterator_erase_method();
    }

  private:
    using base = detail::hook_map_basic_flags<adapted_map>;
    template <bool const_version>
    using flags_t = std::conditional_t<const_version, immutable, base>;
    template <bool const_version>
    using adapted_t =
        std::conditional_t<const_version, const adapted_map, adapted_map>;
    friend class hook_map;

    template <bool const_lookup = false>
    static utils_consteval bool can_use_standard_find()
    {
      if constexpr (!flags_t<const_lookup>::has_map_basic_find_method())
        return false;
      else
        return has_iterators<const_lookup>();
    }

    template <bool const_lookup = false>
    static utils_consteval bool can_use_equal_range()
    {
      if constexpr (!flags_t<const_lookup>::has_map_basic_equal_range_method())
        return false;
      else
        return has_iterators<const_lookup>();
    }

    template <bool const_lookup = false>
    static utils_consteval bool can_use_standard_lookup()
    {
      if constexpr (can_use_equal_range<const_lookup>())
        return true;
      else
        return can_use_standard_find<const_lookup>();
    }

    template <bool const_lookup = false>
    static utils_consteval bool can_use_single_standard_lookup()
    {
      if constexpr (can_use_standard_find<const_lookup>())
        return true;
      else
        return can_use_equal_range<const_lookup>();
    }

    static utils_consteval bool can_use_lookup_and_erase_strategy()
    {
      if constexpr (!base::has_map_iterator_erase_method())
        return false;
      else
        return can_use_standard_lookup();
    }

    static utils_consteval bool can_use_iterator_based_clear_strategy()
    {
      if constexpr (!base::has_map_range_erase_method())
        return false;
      else
        return has_iterators();
    }

    static utils_consteval bool can_insert_raw()
    {
      if constexpr (base::has_map_try_emplace_method())
        return true;
      else if constexpr (base::has_map_emplace_method())
        return true;
      else
        return base::has_map_insert_method();
    }

    static utils_consteval bool can_insert_regularly()
    {
      if constexpr (base::has_map_standard_try_emplace_method())
        return true;
      else if constexpr (base::has_map_standard_emplace_method())
        return true;
      else
        return base::has_map_standard_insert_method();
    }

    static utils_consteval bool can_use_regular_insertion_strategy()
    {
      if constexpr (!can_insert_regularly())
        return false;
      else if constexpr (!base::has_map_iterator_erase_method())
        return false;
      else
        return has_iterators();
    }

    static utils_consteval bool
        can_use_visit_based_insertion_strategy() noexcept
    {
      if constexpr (base::has_map_try_emplace_and_visit_method())
        return true;
      else if constexpr (base::has_map_emplace_and_visit_method())
        return true;
      else
        return base::has_map_insert_and_visit_method();
    }

    static utils_consteval bool can_use_hint_insertion()
    {
      if constexpr (base::has_map_hint_try_emplace())
        return true;
      else if constexpr (base::has_map_hint_emplace())
        return true;
      else
        return base::has_map_hint_insert();
    }
  };

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <typename RawProxy>
  class hook_map<K, Map, safety, map_type_args...>::erase_return_proxy
  {
  public:
    operator typename hook_map::iterator()
    {
      return typename hook_map::iterator(
          static_cast<typename adapted_map::iterator>(proxy));
    }

  private:
    RawProxy proxy;

    friend class hook_map;

    template <typename Func>
    erase_return_proxy(Func&& func) : proxy(func())
    {
    }

    erase_return_proxy(const erase_return_proxy&)            = delete;
    erase_return_proxy& operator=(const erase_return_proxy&) = delete;
  };

  template <typename K, template <typename...> typename Map,
            thread_safety safety, typename... map_type_args>
  template <helpers::bulk_process_type type>
  class hook_map<K, Map, safety, map_type_args...>::bulk_process
  {
  public:
    using process_type = bulk_process_type;

    void add(adapted_mapped_type itr)
    {
      done_process = false;
      if (set.empty() && !psingle_elem)
      {
        psingle_elem = &(*itr);
        pchain       = &itr->get_chain();
        return;
      }

      if (psingle_elem)
      {
        set.reserve(detail::constants::max_reserve);
        set.insert(std::exchange(psingle_elem, nullptr));
      }

      set.insert(&(*itr));
    }

    size_type process()
    {
      if (done_process)
        return 0;
      if (set.empty() && !psingle_elem)
      {
        done_process = true;
        return 0;
      }

      if (psingle_elem)
      {
        size_type count = 0;
        if constexpr (type == process_type::erase)
        {
          pchain->erase(psingle_elem->get_iterator());
          count = 1;
        }
        else
        {
          const bool was_enabled = psingle_elem->is_enabled();
          if constexpr (type == process_type::enable)
            psingle_elem->enable();
          else
            psingle_elem->disable();

          if (was_enabled != psingle_elem->is_enabled())
            count = 1;
        }
        done_process = true;
        return count;
      }

      auto lookup = [this](const mapped_type& h)
      { return set.find(const_cast<mapped_type*>(&h)) != set.end(); };

      size_t result = 0;
      if constexpr (type == process_type::erase)
        result = pchain->erase_if(lookup);
      else if constexpr (type == process_type::enable)
        result = pchain->enable_if(lookup);
      else
        result = pchain->disable_if(lookup);

      done_process = true;
      return static_cast<size_type>(result);
    }

    bool should_process() const { return !done_process; }

  private:
    std::unordered_set<mapped_type*> set;
    mapped_type*                     psingle_elem = nullptr;
    hook_chain*                      pchain       = nullptr;
    bool                             done_process = false;
  };

  namespace helpers
  {
    template <typename adapted, thread_safety safety>
    struct utils_empty_bases map_bases
        : map_optional_aliases<adapted>,
          protected map_mutex_wrapper<adapted, safety>
    {
    };

    template <typename T>
    struct has_valid_forward_iterators_s
        : std::bool_constant<utils::iter::has_valid_forward_iterators<T>>
    {
    };

    template <typename T>
    struct has_valid_bidirectional_iterators_s
        : std::bool_constant<utils::iter::has_valid_bidirectional_iterators<T>>
    {
    };

    template <typename T>
    struct has_valid_forward_local_iterators_s
        : std::bool_constant<utils::iter::has_valid_forward_local_iterators<T>>
    {
    };

    template <typename adapted, typename = void>
    struct optional_alias_iterators
    {
    };

    template <typename Adapted>
    struct iterator_alias
    {
      using iterator =
          map_iterator_wrapper<Adapted, utils::iter::range_iterator_t<Adapted>>;
    };

    template <typename Adapted>
    struct const_iterator_alias
    {
      using const_iterator =
          map_iterator_wrapper<const Adapted,
                               utils::iter::range_iterator_t<const Adapted>>;
    };

    template <typename adapted>
    struct utils_empty_bases optional_alias_iterators<
        adapted, std::enable_if_t<std::conjunction_v<
                     has_valid_forward_iterators_s<adapted>,
                     has_valid_forward_iterators_s<const adapted>>>>
        : iterator_alias<adapted>,
          const_iterator_alias<adapted>
    {
    };

    template <typename adapted>
    struct optional_alias_iterators<
        adapted,
        std::enable_if_t<std::conjunction_v<
            has_valid_forward_iterators_s<adapted>,
            std::negation<has_valid_forward_iterators_s<const adapted>>>>>
        : iterator_alias<adapted>
    {
    };

    template <typename adapted>
    struct optional_alias_iterators<
        adapted, std::enable_if_t<std::conjunction_v<
                     std::negation<has_valid_forward_iterators_s<adapted>>,
                     has_valid_forward_iterators_s<const adapted>>>>
        : const_iterator_alias<adapted>
    {
    };

    template <typename adapted, typename = void>
    struct optional_alias_reverse_iterators
    {
    };

    template <typename Adapted>
    struct reverse_iterator_alias
    {
      using reverse_iterator =
          std::reverse_iterator<typename iterator_alias<Adapted>::iterator>;
    };

    template <typename Adapted>
    struct const_reverse_iterator_alias
    {
      using const_reverse_iterator = std::reverse_iterator<
          typename const_iterator_alias<Adapted>::const_iterator>;
    };

    template <typename adapted>
    struct utils_empty_bases optional_alias_reverse_iterators<
        adapted, std::enable_if_t<std::conjunction_v<
                     has_valid_bidirectional_iterators_s<adapted>,
                     has_valid_bidirectional_iterators_s<const adapted>>>>
        : reverse_iterator_alias<adapted>,
          const_reverse_iterator_alias<adapted>
    {
    };

    template <typename Adapted>
    struct optional_alias_reverse_iterators<
        Adapted,
        std::enable_if_t<std::conjunction_v<
            has_valid_bidirectional_iterators_s<Adapted>,
            std::negation<has_valid_bidirectional_iterators_s<const Adapted>>>>>
        : reverse_iterator_alias<Adapted>
    {
    };

    template <typename Adapted>
    struct optional_alias_reverse_iterators<
        Adapted,
        std::enable_if_t<std::conjunction_v<
            std::negation<has_valid_bidirectional_iterators_s<Adapted>>,
            has_valid_bidirectional_iterators_s<const Adapted>>>>
        : const_reverse_iterator_alias<Adapted>
    {
    };

    template <typename T>
    using range_local_iterator_t = decltype(std::declval<T&>().begin(
        std::declval<utils::size_type_member_or_size_t<T>>()));

    template <typename Adapted, typename = void>
    struct optional_alias_local_iterators
    {
    };

    template <typename Adapted>
    struct local_iterator_alias
    {
      using local_iterator =
          map_iterator_wrapper<Adapted, range_local_iterator_t<Adapted>>;
    };

    template <typename Adapted>
    struct const_local_iterator_alias
    {
      using const_local_iterator =
          map_iterator_wrapper<const Adapted,
                               range_local_iterator_t<const Adapted>>;
    };

    template <typename Adapted>
    struct utils_empty_bases optional_alias_local_iterators<
        Adapted, std::enable_if_t<std::conjunction_v<
                     has_valid_forward_local_iterators_s<Adapted>,
                     has_valid_forward_local_iterators_s<const Adapted>>>>
        : local_iterator_alias<Adapted>,
          const_local_iterator_alias<Adapted>
    {
    };

    template <typename Adapted>
    struct optional_alias_local_iterators<
        Adapted,
        std::enable_if_t<std::conjunction_v<
            has_valid_forward_local_iterators_s<Adapted>,
            std::negation<has_valid_forward_local_iterators_s<const Adapted>>>>>
        : local_iterator_alias<Adapted>
    {
    };

    template <typename Adapted>
    struct optional_alias_local_iterators<
        Adapted,
        std::enable_if_t<std::conjunction_v<
            std::negation<has_valid_forward_local_iterators_s<Adapted>>,
            has_valid_forward_local_iterators_s<const Adapted>>>>
        : const_local_iterator_alias<Adapted>
    {
    };

#define __alterhook_define_optional_alias_accessor(name)                       \
  template <typename adapted, typename = void>                                 \
  struct utils_concat(optional_alias_, name)                                   \
  {                                                                            \
  };                                                                           \
  template <typename adapted>                                                  \
  struct utils_concat(optional_alias_,                                         \
                      name)<adapted, std::void_t<typename adapted::name>>      \
  {                                                                            \
    using name = typename adapted::name;                                       \
  };

#define __alterhook_specialize_optional_alias_accessor(name, template_arg)     \
  utils_concat(optional_alias_, name)<template_arg>

#define __alterhook_implement_optional_aliases_exposure(...)                   \
  utils_map(__alterhook_define_optional_alias_accessor,                        \
            __VA_ARGS__) template <typename adapted>                           \
  struct utils_empty_bases map_optional_aliases                                \
      : utils_map_list_ud(__alterhook_specialize_optional_alias_accessor,      \
                          adapted, __VA_ARGS__),                               \
        optional_alias_iterators<adapted>,                                     \
        optional_alias_reverse_iterators<adapted>,                             \
        optional_alias_local_iterators<adapted>                                \
  {                                                                            \
  }

    __alterhook_implement_optional_aliases_exposure(allocator_type, hasher,
                                                    key_equal, key_compare,
                                                    value_compare, node_type,
                                                    insert_return_type,
                                                    init_type);

    struct dummy_shared_mutex
    {
      void lock() const noexcept {}

      bool try_lock() const noexcept { return true; }

      void unlock() const noexcept {}

      void lock_shared() const noexcept {}

      bool try_lock_shared() const noexcept { return true; }

      void unlock_shared() const noexcept {}
    };

    template <typename mtx, typename = void>
    struct mutex_check
    {
      static_assert(utils::always_false<mtx>,
                    "hook_map: mutex provided doesn't meet the criteria of a "
                    "shared mutex");
    };

    template <typename mtx>
    struct mutex_check<
        mtx, std::void_t<decltype(std::declval<mtx&>().lock()),
                         decltype(std::declval<mtx&>().unlock()),
                         decltype(std::declval<mtx&>().lock_shared()),
                         decltype(std::declval<mtx&>().unlock_shared())>>
    {
      using type = mtx;
    };

    template <typename mtx>
    using mutex_check_t = typename mutex_check<mtx>::type;

    template <typename adapted, thread_safety safety, typename>
    class map_mutex_wrapper : dummy_shared_mutex
    {
    public:
      using map_mutex_t   = dummy_shared_mutex;
      using chain_mutex_t = dummy_shared_mutex;

      static utils_consteval bool is_concurrent() { return false; }

      static utils_consteval bool adapts_concurrent_map() { return false; }

      map_mutex_t& get_map_mutex() const noexcept
      {
        return const_cast<dummy_shared_mutex&>(
            static_cast<const dummy_shared_mutex&>(*this));
      }

      chain_mutex_t& get_chain_mutex() const noexcept
      {
        return const_cast<dummy_shared_mutex&>(
            static_cast<const dummy_shared_mutex&>(*this));
      }
    };

    template <typename Adapted, thread_safety safety>
    class map_mutex_wrapper<Adapted, safety,
                            std::enable_if_t<is_concurrent_map<Adapted>>>
        : dummy_shared_mutex
    {
    public:
      using map_mutex_t   = dummy_shared_mutex;
      using chain_mutex_t = mutex_check_t<hook_map_shared_mutex_of_t<Adapted>>;

      static_assert(
          safety != thread_safety::single_threaded,
          "hook_map: single threaded mode not allowed for concurrent maps");

      static utils_consteval bool is_concurrent() { return true; }

      static utils_consteval bool adapts_concurrent_map() { return true; }

      map_mutex_t& get_map_mutex() const noexcept
      {
        return const_cast<dummy_shared_mutex&>(
            static_cast<const dummy_shared_mutex&>(*this));
      }

      chain_mutex_t& get_chain_mutex() const noexcept { return chain_mutex; }

    private:
      mutable chain_mutex_t chain_mutex;
    };

    template <typename adapted>
    class map_mutex_wrapper<adapted, thread_safety::concurrent,
                            std::enable_if_t<!is_concurrent_map<adapted>>>
        : dummy_shared_mutex
    {
    public:
      using map_mutex_t   = mutex_check_t<hook_map_shared_mutex_of_t<adapted>>;
      using chain_mutex_t = mutex_check_t<hook_map_shared_mutex_of_t<adapted>>;

      static utils_consteval bool is_concurrent() { return true; }

      static utils_consteval bool adapts_concurrent_map() { return false; }

      map_mutex_t& get_map_mutex() const noexcept { return map_mutex; }

      chain_mutex_t& get_chain_mutex() const noexcept { return chain_mutex; }

    private:
      mutable map_mutex_t   map_mutex;
      mutable chain_mutex_t chain_mutex;
    };

    template <typename Adapted, typename Itr>
    class map_iterator_wrapper
        : public utils::iter::basic_iterator_wrapper<
              Itr, map_iterator_wrapper<Adapted, Itr>,
              typename Adapted::value_type,
              utils::iter::range_possible_reference_t<Adapted>>
    {
      using base = utils::iter::basic_iterator_wrapper<
          Itr, map_iterator_wrapper, typename Adapted::value_type,
          utils::iter::range_possible_reference_t<Adapted>>;

    public:
      using key_type    = typename Adapted::key_type;
      using mapped_type = typename Adapted::mapped_type;
      using reference =
          std::pair<const key_type&,
                    std::conditional_t<std::is_const_v<Adapted>,
                                       const mapped_type, mapped_type>&>;
      using pointer           = utils::iter::pointer_wrapper<reference>;
      using iterator_category = std::input_iterator_tag;

      using base::base;

      reference operator*() const
      {
        auto [key, val] = extract_key_value(*base::itr);
        return { key, *val };
      }

    private:
      Itr unwrap() const { return base::itr; }

      template <typename, template <typename...> typename, thread_safety,
                typename...>
      friend class hook_map;
    };

    template <typename AdaptedMappedType>
    class mapped_iterator_wrapper
        : public utils::iter::basic_iterator_wrapper<
              AdaptedMappedType, mapped_iterator_wrapper<AdaptedMappedType>>
    {
      using base = utils::iter::basic_iterator_wrapper<AdaptedMappedType,
                                                       mapped_iterator_wrapper>;

    public:
      mapped_iterator_wrapper() = default;

      mapped_iterator_wrapper(AdaptedMappedType itr) : base(itr), valid(true) {}

      decltype(auto) operator*() const
      {
        utils_assert(
            is_valid(),
            "hook_map: attempted to dereference an invalid hook iterator");
        return base::operator*();
      }

      mapped_iterator_wrapper& operator++()
      {
        utils_assert(
            is_valid(),
            "hook_map: attempted to increment an invalid hook iterator");
        return base::operator++();
      }

      using base::operator++;

      mapped_iterator_wrapper& operator--()
      {
        utils_assert(
            is_valid(),
            "hook_map: attempted to decrement an invalid hook iterator");
        return base::operator--();
      }

      using base::operator--;

      bool is_valid() const { return valid; }

      operator AdaptedMappedType() const { return base::itr; }

      bool operator==(const mapped_iterator_wrapper& other) const
      {
        utils_assert(
            is_valid() == other.is_valid(),
            "hook_map: comparing an invalid iterator with a valid one");
        if (!is_valid())
          return true;
        return base::operator==(other);
      }

    private:
      bool valid = false;
    };

    template <typename T>
    constexpr auto extract_key_value(T&& item) noexcept
    {
      auto&& [key, val] = std::forward<T>(item);
      static_assert(
          std::conjunction_v<std::is_same<utils::remove_cvref_t<decltype(key)>,
                                          typename T::key_type>,
                             std::is_same<utils::remove_cvref_t<decltype(val)>,
                                          typename T::mapped_type>>,
          "hook_map: can't unwrap value_type to key-mapped pair");
      return std::pair<utils::make_const_reference_t<decltype(key)>,
                       decltype(val)>{ std::forward<decltype(key)>(key),
                                       std::forward<decltype(val)>(val) };
    }

    template <typename Adapted>
    constexpr bool map_modifiable_range<
        Adapted,
        std::void_t<
            decltype(std::declval<utils::iter::iter_reference_t<
                         utils::iter::range_iterator_t<Adapted>>>() = std::
                         declval<const typename Adapted::mapped_type&>())>> =
        true;

    template <typename Tuple, typename = void>
    constexpr bool map_elem_init_tuple_size_requirement = false;
    template <typename Tuple>
    constexpr bool map_elem_init_tuple_size_requirement<
        Tuple,
        std::enable_if_t<(
            2 <= std::tuple_size<utils::remove_cvref_t<Tuple>>::value &&
            std::tuple_size<utils::remove_cvref_t<Tuple>>::value <= 4)>> = true;

    template <typename Tuple>
    struct map_elem_init_tuple_size_requirement_s
        : std::bool_constant<map_elem_init_tuple_size_requirement<Tuple>>
    {
    };

    template <typename Tuple>
    constexpr bool map_elem_init_tuple =
        std::conjunction_v<std::bool_constant<utils::tuple_like<Tuple>>,
                           map_elem_init_tuple_size_requirement_s<Tuple>>;

    template <typename Tuple>
    struct map_elem_init_tuple_s
        : std::bool_constant<map_elem_init_tuple<Tuple>>
    {
    };

    template <typename Itr>
    constexpr bool map_valid_init_iterator<
        Itr, std::enable_if_t<utils::iter::is_valid_forward_iterator<Itr>>> =
        map_elem_init_tuple<
            decltype(*std::declval<const std::remove_reference_t<Itr>&>())>;

    template <typename Itr>
    struct map_valid_init_iterator_s
        : std::bool_constant<map_valid_init_iterator<Itr>>
    {
    };

    template <typename Range>
    constexpr bool map_valid_init_range<
        Range,
        std::enable_if_t<std::conjunction_v<
            map_valid_init_iterator_s<utils::iter::range_begin_t<Range>>,
            map_valid_init_iterator_s<utils::iter::range_end_t<Range>>>>> =
        true;

    template <typename reference>
    struct map_callable_requirement_enclosure
    {
      template <size_t, typename Callable>
      struct check : std::is_invocable<Callable&, reference>
      {
      };
    };

    template <typename... Tuples, typename... Callables, size_t max_callables>
    constexpr bool map_insertion_and_visitation_layout_requirements_impl<
        utils::type_sequence<Tuples...>, utils::type_sequence<Callables...>,
        max_callables,
        std::enable_if_t<(sizeof...(Tuples) >= 1) &&
                         (sizeof...(Callables) >= 1 &&
                          sizeof...(Callables) <= max_callables)>> =
        std::conjunction_v<map_elem_init_tuple_s<Tuples>...>;
  } // namespace helpers
} // namespace alterhook
