/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <list>
#include "hook.h"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4251 4715)
#elif utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wreturn-type"
#endif

namespace alterhook
{
  class ALTERHOOK_API hook_chain : trampoline
  {
  public:
    // member types
    class ALTERHOOK_API hook;
    class const_iterator;
    class iterator;
    enum class transfer
    {
      disabled,
      enabled,
      both
    };
    typedef transfer                                include;
    typedef std::list<hook>::const_iterator         const_list_iterator;
    typedef std::list<hook>::iterator               list_iterator;
    typedef std::list<hook>::const_reverse_iterator const_reverse_list_iterator;
    typedef std::list<hook>::reverse_iterator       reverse_list_iterator;
    typedef hook                                    value_type;
    typedef size_t                                  size_type;
    typedef ptrdiff_t                               difference_type;
    typedef hook*                                   pointer;
    typedef const hook*                             const_pointer;
    typedef hook&                                   reference;
    typedef const hook&                             const_reference;

    // constructors/destructors/assignment operators
    template <__alterhook_are_detour_and_original_pairs(dtr, orig, types)>
    hook_chain(std::byte* target, dtr&& detour, orig& original, types&&... rest)
        __alterhook_requires(utils::detour_and_storage_pairs<types...>);

    template <__alterhook_are_target_detour_and_original_pairs(trg, dtr, orig,
                                                               types)>
    hook_chain(trg&& target, dtr&& detour, orig& original, types&&... rest)
        __alterhook_requires(utils::detour_and_storage_pairs<types...>);

    template <__alterhook_are_detour_and_original_stl_pairs(pair, types)>
    hook_chain(std::byte* target, pair&& first, types&&... rest)
        __alterhook_requires(utils::detour_and_storage_stl_pairs<types...>);

    template <__alterhook_are_target_detour_and_original_stl_pairs(trg, pair,
                                                                   types)>
    hook_chain(trg&& target, pair&& first, types&&... rest)
        __alterhook_requires(utils::detour_and_storage_stl_pairs<types...>);

    hook_chain(std::byte* target);

    template <__alterhook_is_target(trg)>
    hook_chain(trg&& target)
        : hook_chain(get_target_address(std::forward<trg>(target)))
    {
    }

    template <__alterhook_is_original(orig)>
    hook_chain(const alterhook::hook& other, orig& original);
    hook_chain(alterhook::hook&& other);

    hook_chain(const trampoline& other) : trampoline(other)
    {
      __alterhook_make_backup();
    }

    hook_chain(trampoline&& other) noexcept : trampoline(std::move(other))
    {
      __alterhook_make_backup();
    }

    hook_chain(const hook_chain& other);
    hook_chain(hook_chain&& other) noexcept;

    hook_chain() noexcept {}

    ~hook_chain() noexcept;

    hook_chain& operator=(const hook_chain& other);
    hook_chain& operator=(hook_chain&& other) noexcept;
    hook_chain& operator=(const trampoline& other);
    hook_chain& operator=(trampoline&& other);

    // status update
    void enable_all();
    void disable_all();

    // container modifiers
    void          clear(include trg = include::both);
    void          pop_back(include trg = include::both);
    void          pop_front(include trg = include::both);
    list_iterator erase(list_iterator position);
    list_iterator erase(list_iterator first, list_iterator last);
    iterator      erase(iterator position);
    iterator      erase(iterator first, iterator last);

    template <__alterhook_are_detour_and_original_pairs(dtr, orig, types)>
    void append(transfer to, dtr&& detour, orig& original, types&&... rest)
        __alterhook_requires(utils::detour_and_storage_pairs<types...>);
    template <__alterhook_are_detour_and_original_pairs(dtr, orig, types)>
    void append(dtr&& detour, orig& original, types&&... rest)
        __alterhook_requires(utils::detour_and_storage_pairs<types...>);
    template <__alterhook_are_detour_and_original_stl_pairs(pair, types)>
    void append(transfer to, pair&& first, types&&... rest)
        __alterhook_requires(utils::detour_and_storage_stl_pairs<types...>);
    template <__alterhook_are_detour_and_original_stl_pairs(pair, types)>
    void append(pair&& first, types&&... rest)
        __alterhook_requires(utils::detour_and_storage_stl_pairs<types...>);
    template <__alterhook_is_detour_and_original(dtr, orig)>
    void push_back(dtr&& detour, orig& original, bool enable_hook = true);
    template <__alterhook_is_detour_and_original(dtr, orig)>
    void push_front(dtr&& detour, orig& original, bool enable_hook = true);
    template <__alterhook_is_detour_and_original(dtr, orig)>
    hook& insert(list_iterator position, dtr&& detour, orig& original,
                 include trg);
    template <__alterhook_is_detour_and_original(dtr, orig)>
    hook& insert(iterator position, dtr&& detour, orig& original);
    void  swap(list_iterator left, hook_chain& other, list_iterator right);

    void swap(list_iterator left, list_iterator right)
    {
      swap(left, *this, right);
    }

    void swap(hook_chain& other);
    void merge(hook_chain& other, bool at_back = true);

    void merge(hook_chain&& other, bool at_back = true)
    {
      merge(other, at_back);
    }

    void splice(list_iterator newpos, hook_chain& other, transfer to,
                transfer from = transfer::both);

    void splice(list_iterator newpos, hook_chain&& other, transfer to,
                transfer from = transfer::both)
    {
      splice(newpos, other, to, from);
    }

    void splice(iterator newpos, hook_chain& other,
                transfer from = transfer::both);

    void splice(iterator newpos, hook_chain&& other,
                transfer from = transfer::both);

    void splice(list_iterator newpos, hook_chain& other, list_iterator oldpos,
                transfer to);

    void splice(list_iterator newpos, hook_chain&& other, list_iterator oldpos,
                transfer to)
    {
      splice(newpos, other, oldpos, to);
    }

    void splice(iterator newpos, hook_chain& other, list_iterator oldpos);

    void splice(iterator newpos, hook_chain&& other, list_iterator oldpos);

    void splice(list_iterator newpos, hook_chain& other, list_iterator first,
                list_iterator last, transfer to);

    void splice(list_iterator newpos, hook_chain&& other, list_iterator first,
                list_iterator last, transfer to)
    {
      splice(newpos, other, first, last, to);
    }

    void splice(iterator newpos, hook_chain& other, list_iterator first,
                list_iterator last);

    void splice(iterator newpos, hook_chain&& other, list_iterator first,
                list_iterator last);

    void splice(list_iterator newpos, hook_chain& other, iterator first,
                iterator last, transfer to);

    void splice(list_iterator newpos, hook_chain&& other, iterator first,
                iterator last, transfer to);

    void splice(iterator newpos, hook_chain& other, iterator first,
                iterator last);

    void splice(iterator newpos, hook_chain&& other, iterator first,
                iterator last);

    void splice(list_iterator newpos, list_iterator oldpos, transfer to)
    {
      splice(newpos, *this, oldpos, to);
    }

    void splice(iterator newpos, list_iterator oldpos);

    void splice(list_iterator newpos, list_iterator first, list_iterator last,
                transfer to)
    {
      splice(newpos, *this, first, last, to);
    }

    void splice(iterator newpos, list_iterator first, list_iterator last);

    void splice(list_iterator newpos, iterator first, iterator last,
                transfer to);

    void splice(iterator newpos, iterator first, iterator last);

    // element access
    reference       operator[](size_t n) noexcept;
    const_reference operator[](size_t n) const noexcept;
    reference       at(size_t n);
    const_reference at(size_t n) const;
    reference       front() noexcept;
    const_reference front() const noexcept;
    const_reference cfront() const noexcept;
    reference       efront() noexcept;
    const_reference efront() const noexcept;
    const_reference cefront() const noexcept;
    reference       dfront() noexcept;
    const_reference dfront() const noexcept;
    const_reference cdfront() const noexcept;
    reference       back() noexcept;
    const_reference back() const noexcept;
    const_reference cback() const noexcept;
    reference       eback() noexcept;
    const_reference eback() const noexcept;
    const_reference ceback() const noexcept;
    reference       dback() noexcept;
    const_reference dback() const noexcept;
    const_reference cdback() const noexcept;

    // setters
    void set_target(std::byte* target);

    template <__alterhook_is_target(trg)>
    void set_target(trg&& target)
    {
      set_target(get_target_address(std::forward<trg>(target)));
    }

    // getters
    bool empty() const noexcept { return enabled.empty() && disabled.empty(); }

    bool empty_enabled() const noexcept { return enabled.empty(); }

    bool empty_disabled() const noexcept { return disabled.empty(); }

    explicit operator bool() const noexcept { return !empty(); }

    size_t size() const noexcept { return enabled.size() + disabled.size(); }

    size_t enabled_size() const noexcept { return enabled.size(); }

    size_t disabled_size() const noexcept { return disabled.size(); }

    using trampoline::get_target;

    // iterators
    iterator                    begin() noexcept;
    iterator                    end() noexcept;
    const_iterator              begin() const noexcept;
    const_iterator              end() const noexcept;
    const_iterator              cbegin() const noexcept;
    const_iterator              cend() const noexcept;
    list_iterator               ebegin() noexcept;
    list_iterator               eend() noexcept;
    const_list_iterator         ebegin() const noexcept;
    const_list_iterator         eend() const noexcept;
    reverse_list_iterator       rebegin() noexcept;
    reverse_list_iterator       reend() noexcept;
    const_reverse_list_iterator rebegin() const noexcept;
    const_reverse_list_iterator reend() const noexcept;
    const_list_iterator         cebegin() const noexcept;
    const_list_iterator         ceend() const noexcept;
    const_reverse_list_iterator crebegin() const noexcept;
    const_reverse_list_iterator creend() const noexcept;
    list_iterator               dbegin() noexcept;
    list_iterator               dend() noexcept;
    const_list_iterator         dbegin() const noexcept;
    const_list_iterator         dend() const noexcept;
    reverse_list_iterator       rdbegin() noexcept;
    reverse_list_iterator       rdend() noexcept;
    const_reverse_list_iterator rdbegin() const noexcept;
    const_reverse_list_iterator rdend() const noexcept;
    const_list_iterator         cdbegin() const noexcept;
    const_list_iterator         cdend() const noexcept;
    const_reverse_list_iterator crdbegin() const noexcept;
    const_reverse_list_iterator crdend() const noexcept;

    // comparison
    bool operator==(const hook_chain& other) const noexcept;
    bool operator!=(const hook_chain& other) const noexcept;

  private:
#ifdef __alterhook_expose_impl
    friend struct injectors;
#endif

    typedef std::array<std::byte, detail::constants::backup_size> backup_t;
    typedef std::list<hook>                                       hook_list;

    backup_t  backup{};
    hook_list disabled{};
    hook_list enabled{};
    bool      starts_enabled = false;

    struct unbind_range_callback
    {
      virtual void operator()(list_iterator itr, bool forward = true) = 0;

      static void set_pchain(list_iterator itr, hook_chain* pchain);
      static void set_enabled(list_iterator itr, bool status);
      static void set_has_other(list_iterator itr, bool status);
      static void set_other(list_iterator itr, list_iterator other);
    };

    template <typename detour_t, typename original_t, size_t... d_indexes,
              size_t... o_indexes, typename... types>
    void init_chain(std::index_sequence<d_indexes...>,
                    std::index_sequence<o_indexes...>,
                    std::tuple<detour_t, original_t, types...>&& args);
    template <typename dfirst, typename... detours, typename ofirst,
              typename... originals, size_t... indexes>
    void  init_chain(std::index_sequence<indexes...>,
                     std::pair<std::tuple<dfirst, detours...>,
                              std::tuple<ofirst, originals...>>&& args);
    void  assert_len(size_t n) const;
    void  verify_len(size_t n) const;
    void  init_chain();
    void  join_last_unchecked(size_t enabled_count = 1);
    void  join_last();
    void  join_first();
    void  join(list_iterator itr);
    void  unbind_range(list_iterator first, list_iterator last,
                       unbind_range_callback& callback);
    void  unbind(list_iterator position);
    void  uninject_all();
    void  uninject_range(list_iterator first, list_iterator last);
    void  uninject(list_iterator position);
    void  bind(list_iterator pos, list_iterator oldpos, bool to_enabled);
    void  inject_range(list_iterator pos, list_iterator first,
                       list_iterator last);
    void  inject_back(list_iterator first, list_iterator last);
    void  toggle_status(list_iterator first, list_iterator last);
    void  toggle_status(list_iterator position);
    void  toggle_status_all(include src);
    void  push_back_impl(const std::byte*            detour,
                         const helpers::orig_buff_t& buffer, bool enable_hook);
    void  push_front_impl(const std::byte*            detour,
                          const helpers::orig_buff_t& buffer, bool enable_hook);
    hook& insert_impl(list_iterator pos, const std::byte* detour,
                      const helpers::orig_buff_t& buffer, include trg);
    template <typename detour_t, typename original_t, size_t... d_indexes,
              size_t... o_indexes, typename... types>
    void append_impl(transfer to, std::index_sequence<d_indexes...>,
                     std::index_sequence<o_indexes...>,
                     std::tuple<detour_t, original_t, types...>&& args);
    template <typename dfirst, typename... detours, typename ofirst,
              typename... originals, size_t... indexes>
    void append_impl(transfer to, std::index_sequence<indexes...>,
                     std::pair<std::tuple<dfirst, detours...>,
                               std::tuple<ofirst, originals...>>&& args);

  protected:
    trampoline& get_trampoline() { return *this; }

    const trampoline& get_trampoline() const { return *this; }

    void set_trampoline(const hook_chain& other)
    {
      trampoline::operator=(other);
      memcpy(backup.data(), other.backup.data(), backup.size());
    }

    list_iterator append_hook(const hook& h, transfer trg = transfer::disabled);
    template <typename itr>
    void append_items(itr first, itr last, transfer trg = transfer::enabled);
    template <typename dtr, typename orig>
    static hook                         hook_from(dtr&& detour, orig& original);
    static void                         set_item(hook& left, const hook& right);
    static std::reference_wrapper<hook> empty_ref_wrap();
  };

  class ALTERHOOK_API hook_chain::hook
  {
  public:
    hook() noexcept {}

    void enable();
    void disable();

    iterator       get_iterator() noexcept;
    const_iterator get_iterator() const noexcept;
    const_iterator get_const_iterator() const noexcept;

    list_iterator get_list_iterator() noexcept { return current; }

    const_list_iterator get_list_iterator() const noexcept { return current; }

    const_list_iterator get_const_list_iterator() const noexcept
    {
      return current;
    }

    hook_chain& get_chain() const noexcept { return *pchain; }

    std::byte* get_target() const noexcept { return pchain->ptarget; }

    const std::byte* get_detour() const noexcept { return pdetour; }

    bool is_enabled() const noexcept { return enabled; }

    explicit operator bool() const noexcept { return enabled; }

    template <__alterhook_is_detour(dtr)>
    void set_detour(dtr&& detour)
    {
      set_detour(get_target_address(std::forward<dtr>(detour)));
    }

    template <__alterhook_is_original(orig)>
    void set_original(orig& original);

    bool operator==(const hook& other) const noexcept;
    bool operator!=(const hook& other) const noexcept;

  private:
    friend class hook_chain;
    friend struct hook_chain::unbind_range_callback;
    template <typename T, size_t N>
    friend class utils::static_vector;
    list_iterator        current{};
    list_iterator        other{};
    hook_chain*          pchain    = nullptr;
    const std::byte*     pdetour   = nullptr;
    const std::byte*     poriginal = nullptr;
    helpers::orig_buff_t origbuff{};
    helpers::original*   origwrap  = nullptr;
    bool                 enabled   = false;
    bool                 has_other = false;

    template <__alterhook_is_original(orig)>
    void init(hook_chain& chain, list_iterator curr, const std::byte* detour,
              const std::byte* original, orig& origref, bool should_enable);
    template <__alterhook_is_original(orig)>
    void init(hook_chain& chain, list_iterator curr, const std::byte* detour,
              orig& origref);
    void init(hook_chain& chain, list_iterator curr, const std::byte* detour,
              const std::byte* original, const helpers::orig_buff_t& buffer,
              bool enable_hook = true);
    void init(hook_chain& chain, list_iterator curr, const std::byte* detour,
              const helpers::orig_buff_t& buffer);
    void set_detour(std::byte* detour);
    void set_original(helpers::orig_buff_t& original);
    hook(const hook&) = default;
  };

  class hook_chain::iterator
  {
  public:
#if utils_cpp20
    typedef std::forward_iterator_tag iterator_concept;
#endif
    typedef std::forward_iterator_tag iterator_category;
    typedef hook                      value_type;
    typedef ptrdiff_t                 difference_type;
    typedef hook*                     pointer;
    typedef hook&                     reference;

    iterator() noexcept = default;

    reference operator*() const noexcept { return *itrs[enabled]; }

    pointer operator->() const noexcept { return itrs[enabled].operator->(); }

    iterator& operator++() noexcept;
    iterator  operator++(int) noexcept;

    bool operator==(const iterator& other) const noexcept
    {
      return enabled == other.enabled && itrs[enabled] == other.itrs[enabled];
    }

    bool operator!=(const iterator& other) const noexcept
    {
      return enabled != other.enabled || itrs[enabled] != other.itrs[enabled];
    }

    operator list_iterator() const noexcept { return itrs[enabled]; }

    operator const_list_iterator() const noexcept { return itrs[enabled]; }

  private:
    friend class hook_chain;
    std::array<list_iterator, 2> itrs{};
    bool                         enabled = false;

    explicit iterator(list_iterator ditr, list_iterator eitr,
                      bool enabled) noexcept
        : itrs({ ditr, eitr }), enabled(enabled)
    {
    }
  };

  class hook_chain::const_iterator
  {
  public:
#if utils_cpp20
    typedef std::forward_iterator_tag iterator_concept;
#endif
    typedef std::forward_iterator_tag iterator_category;
    typedef hook                      value_type;
    typedef ptrdiff_t                 difference_type;
    typedef const hook*               pointer;
    typedef const hook&               reference;

    const_iterator() noexcept = default;

    reference operator*() const noexcept { return *itrs[enabled]; }

    pointer operator->() const noexcept { return itrs[enabled].operator->(); }

    const_iterator& operator++() noexcept;
    const_iterator  operator++(int) noexcept;

    bool operator==(const const_iterator& other) const noexcept
    {
      return enabled == other.enabled && itrs[enabled] == other.itrs[enabled];
    }

    bool operator!=(const const_iterator& other) const noexcept
    {
      return enabled != other.enabled || itrs[enabled] != other.itrs[enabled];
    }

    operator const_list_iterator() const noexcept { return itrs[enabled]; }

  private:
    friend class hook_chain;
    friend class iterator;
    std::array<const_list_iterator, 2> itrs{};
    bool                               enabled = false;

    explicit const_iterator(const_list_iterator ditr, const_list_iterator eitr,
                            bool enabled) noexcept
        : itrs({ ditr, eitr }), enabled(enabled)
    {
    }
  };

  /*
   * TEMPLATE DEFINITIONS
   */
  template <__alterhook_are_detour_and_original_pairs_impl(dtr, orig, types)>
  hook_chain::hook_chain(std::byte* target, dtr&& detour, orig& original,
                         types&&... rest)
      __alterhook_requires(utils::detour_and_storage_pairs<types...>)
      : trampoline(target)
  {
    init_chain(utils::make_index_sequence_with_step<sizeof...(types) + 2, 2>(),
               utils::make_index_sequence_with_step<sizeof...(types) + 2, 3>(),
               std::forward_as_tuple(std::forward<dtr>(detour), original,
                                     std::forward<types>(rest)...));
  }

  template <__alterhook_are_target_detour_and_original_pairs_impl(trg, dtr,
                                                                  orig, types)>
  hook_chain::hook_chain(trg&& target, dtr&& detour, orig& original,
                         types&&... rest)
      __alterhook_requires(utils::detour_and_storage_pairs<types...>)
      : hook_chain(get_target_address(std::forward<trg>(target)),
                   std::forward<dtr>(detour), original,
                   std::forward<types>(rest)...)
  {
    helpers::assert_valid_target_and_detours<trg>(
        helpers::extract_detour_sequence_t<dtr, orig, types...>());
  }

  template <__alterhook_are_detour_and_original_stl_pairs_impl(pair, types)>
  hook_chain::hook_chain(std::byte* target, pair&& first, types&&... rest)
      __alterhook_requires(utils::detour_and_storage_stl_pairs<types...>)
      : trampoline(target)
  {
    init_chain(
        std::make_index_sequence<sizeof...(types)>(),
        std::pair(
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<pair>>>(
                    std::get<0>(first)),
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
                    std::get<0>(rest))...),
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<pair>>>(
                    std::get<1>(first)),
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<types>>>(
                    std::get<1>(rest))...)));
  }

  template <__alterhook_are_target_detour_and_original_stl_pairs_impl(trg, pair,
                                                                      types)>
  hook_chain::hook_chain(trg&& target, pair&& first, types&&... rest)
      __alterhook_requires(utils::detour_and_storage_stl_pairs<types...>)
      : hook_chain(get_target_address(std::forward<trg>(target)),
                   std::forward<pair>(first), std::forward<types>(rest)...)
  {
    helpers::assert_valid_target_and_detours<trg>(
        helpers::extract_detour_sequence_from_tuples_t<pair, types...>());
  }

  template <__alterhook_is_original_impl(orig)>
  hook_chain::hook_chain(const alterhook::hook& other, orig& original)
      : trampoline(other)
  {
    memcpy(backup.data(), other.backup.data(), backup.size());
    __alterhook_def_thumb_var(ptarget);
    list_iterator itr = disabled.emplace(disabled.end());
    itr->init(*this, itr, __alterhook_get_other_dtr(other),
              __alterhook_add_thumb_bit(ptrampoline.get()), original, false);
  }

  template <typename detour_t, typename original_t, size_t... d_indexes,
            size_t... o_indexes, typename... types>
  void hook_chain::init_chain(std::index_sequence<d_indexes...>,
                              std::index_sequence<o_indexes...>,
                              std::tuple<detour_t, original_t, types...>&& args)
  {
    typedef utils::type_sequence<detour_t, original_t, types...> seq;
    init_chain(std::make_index_sequence<sizeof...(d_indexes)>(),
               std::pair(std::forward_as_tuple(
                             std::forward<detour_t>(std::get<0>(args)),
                             std::forward<utils::type_at_t<d_indexes, seq>>(
                                 std::get<d_indexes>(args))...),
                         std::forward_as_tuple(
                             std::forward<original_t>(std::get<1>(args)),
                             std::forward<utils::type_at_t<o_indexes, seq>>(
                                 std::get<o_indexes>(args))...)));
  }

  template <typename dfirst, typename... detours, typename ofirst,
            typename... originals, size_t... indexes>
  void
      hook_chain::init_chain(std::index_sequence<indexes...>,
                             std::pair<std::tuple<dfirst, detours...>,
                                       std::tuple<ofirst, originals...>>&& args)
  {
    helpers::assert_valid_detour_and_original_pairs(
        utils::type_sequence<dfirst, detours...>(),
        utils::type_sequence<ofirst, originals...>());

    __alterhook_def_thumb_var(ptarget);
    __alterhook_make_backup();
    hook& fentry = enabled.emplace_back();
    fentry.init(
        *this, enabled.begin(),
        get_target_address(std::forward<dfirst>(std::get<0>(args.first))),
        __alterhook_add_thumb_bit(ptrampoline.get()), std::get<0>(args.second),
        true);
    starts_enabled = true;

    if constexpr (sizeof...(detours) > 0)
    {
      list_iterator    iter    = enabled.begin();
      hook*            entry   = &fentry;
      const std::byte* pdetour = entry->pdetour;
      ((entry = &enabled.emplace_back(),
        entry->init(*this, ++iter,
                    get_target_address(std::forward<detours>(
                        std::get<indexes + 1>(args.first))),
                    pdetour, std::get<indexes + 1>(args.second), true),
        pdetour = entry->pdetour),
       ...);
    }
    init_chain();
  }

  template <typename detour_t, typename original_t, size_t... d_indexes,
            size_t... o_indexes, typename... types>
  void
      hook_chain::append_impl(transfer to, std::index_sequence<d_indexes...>,
                              std::index_sequence<o_indexes...>,
                              std::tuple<detour_t, original_t, types...>&& args)
  {
    typedef utils::type_sequence<detour_t, original_t, types...> seq;
    append_impl(to, std::make_index_sequence<sizeof...(d_indexes)>(),
                std::pair(std::forward_as_tuple(
                              std::forward<detour_t>(std::get<0>(args)),
                              std::forward<utils::type_at_t<d_indexes, seq>>(
                                  std::get<d_indexes>(args))...),
                          std::forward_as_tuple(
                              std::forward<original_t>(std::get<1>(args)),
                              std::forward<utils::type_at_t<o_indexes, seq>>(
                                  std::get<o_indexes>(args))...)));
  }

  template <typename dfirst, typename... detours, typename ofirst,
            typename... originals, size_t... indexes>
  void hook_chain::append_impl(
      transfer to, std::index_sequence<indexes...>,
      std::pair<std::tuple<dfirst, detours...>,
                std::tuple<ofirst, originals...>>&& args)
  {
    helpers::assert_valid_detour_and_original_pairs(
        utils::type_sequence<dfirst, detours...>(),
        utils::type_sequence<ofirst, originals...>());
    auto [trg, other] = to == transfer::enabled ? std::tie(enabled, disabled)
                                                : std::tie(disabled, enabled);
    hook&         first_entry = trg.emplace_back();
    list_iterator itr         = std::prev(trg.end());
    list_iterator itrcurrent  = itr;
    size_t        count       = 1;

    try
    {
      if (to == transfer::enabled)
      {
        __alterhook_def_thumb_var(ptarget);
        const std::byte* original =
            itr == enabled.begin()
                ? __alterhook_add_thumb_bit(ptrampoline.get())
                : std::prev(itr)->pdetour;
        hook* entry = nullptr;
        first_entry.init(
            *this, itr,
            get_target_address(std::forward<dfirst>(std::get<0>(args.first))),
            original, std::get<0>(args.second), true);
        original = first_entry.pdetour;

        ((entry = &enabled.emplace_back(),
          entry->init(*this, ++itrcurrent,
                      get_target_address(std::forward<detours>(
                          std::get<indexes + 1>(args.first))),
                      original, std::get<indexes + 1>(args.second), true),
          original = entry->pdetour, ++count),
         ...);
        join_last_unchecked(count);
      }
      else
      {
        hook* entry = nullptr;
        first_entry.init(
            *this, itr,
            get_target_address(std::forward<dfirst>(std::get<0>(args.first))),
            std::get<0>(args.second));

        ((entry = &disabled.emplace_back(),
          entry->init(*this, ++itrcurrent,
                      get_target_address(std::forward<detours>(
                          std::get<indexes + 1>(args.first))),
                      std::get<indexes + 1>(args.second)),
          ++count),
         ...);
      }
    }
    catch (...)
    {
      trg.resize(trg.size() - count);
      throw;
    }

    bool touch_back = false;
    if (itr == trg.begin())
    {
      if (other.empty())
        starts_enabled = static_cast<bool>(to);
      else
        touch_back = true;
    }
    else if (std::prev(itr)->has_other)
      touch_back = true;

    if (!touch_back)
      return;
    hook& otherback     = other.back();
    otherback.has_other = true;
    otherback.other     = itr;
  }

  template <__alterhook_is_original_impl(orig)>
  void hook_chain::hook::init(hook_chain& chain, list_iterator curr,
                              const std::byte* detour,
                              const std::byte* original, orig& origref,
                              bool should_enable)
  {
    new (&origbuff) helpers::original_wrapper(origref);
    pchain    = &chain;
    current   = curr;
    pdetour   = detour;
    poriginal = original;
    enabled   = should_enable;
    origwrap  = std::launder(reinterpret_cast<helpers::original*>(&origbuff));
    origref   = function_cast<orig>(original);
  }

  template <__alterhook_is_original_impl(orig)>
  void hook_chain::hook::init(hook_chain& chain, list_iterator curr,
                              const std::byte* detour, orig& origref)
  {
    new (&origbuff) helpers::original_wrapper(origref);
    pchain   = &chain;
    current  = curr;
    pdetour  = detour;
    origwrap = std::launder(reinterpret_cast<helpers::original*>(&origbuff));
    origref  = nullptr;
  }

  template <__alterhook_is_original_impl(orig)>
  void hook_chain::hook::set_original(orig& original)
  {
    if (origwrap->contains_ref(original))
      return;
    helpers::orig_buff_t tmp{};
    new (&tmp) helpers::original_wrapper(original);
    set_original(tmp);
  }

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  hook_chain::hook& hook_chain::insert(list_iterator position, dtr&& detour,
                                       orig& original, include trg)
  {
    helpers::assert_valid_detour_original_pair<dtr, orig>();
    utils_assert(trg != include::both,
                 "hook_chain::insert: base cannot be the both flag");
    helpers::orig_buff_t buffer{};
    new (&buffer) helpers::original_wrapper(original);
    return insert_impl(position, get_target_address(std::forward<dtr>(detour)),
                       buffer, trg);
  }

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  hook_chain::hook& hook_chain::insert(iterator position, dtr&& detour,
                                       orig& original)
  {
    return insert(static_cast<list_iterator>(position),
                  std::forward<dtr>(detour), original,
                  position.enabled ? include::enabled : include::disabled);
  }

  template <__alterhook_are_detour_and_original_pairs_impl(dtr, orig, types)>
  void hook_chain::append(transfer to, dtr&& detour, orig& original,
                          types&&... rest)
      __alterhook_requires(utils::detour_and_storage_pairs<types...>)
  {
    if constexpr (sizeof...(rest) == 0)
      push_back(std::forward<dtr>(detour), original, static_cast<bool>(to));
    else
      append_impl(
          to, utils::make_index_sequence_with_step<sizeof...(rest) + 2, 2>(),
          utils::make_index_sequence_with_step<sizeof...(rest) + 2, 3>(),
          std::forward_as_tuple(std::forward<dtr>(detour), original,
                                std::forward<types>(rest)...));
  }

  template <__alterhook_are_detour_and_original_pairs_impl(dtr, orig, types)>
  void hook_chain::append(dtr&& detour, orig& original, types&&... rest)
      __alterhook_requires(utils::detour_and_storage_pairs<types...>)
  {
    append(transfer::enabled, std::forward<dtr>(detour), original,
           std::forward<types>(rest)...);
  }

  template <__alterhook_are_detour_and_original_stl_pairs_impl(pair, types)>
  void hook_chain::append(transfer to, pair&& first, types&&... rest)
      __alterhook_requires(utils::detour_and_storage_stl_pairs<types...>)
  {
    if constexpr (sizeof...(rest) == 0)
      push_back(
          std::forward<std::tuple_element_t<0, utils::remove_cvref_t<pair>>>(
              std::get<0>(first)),
          std::forward<std::tuple_element_t<1, utils::remove_cvref_t<pair>>>(
              std::get<1>(first)),
          static_cast<bool>(to));
    else
      append_impl(
          to, std::make_index_sequence<sizeof...(rest)>(),
          std::pair(
              std::forward_as_tuple(
                  std::forward<
                      std::tuple_element_t<0, utils::remove_cvref_t<pair>>>(
                      std::get<0>(first)),
                  std::forward<
                      std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
                      std::get<0>(rest))...),
              std::forward_as_tuple(
                  std::forward<
                      std::tuple_element_t<1, utils::remove_cvref_t<pair>>>(
                      std::get<1>(first)),
                  std::forward<
                      std::tuple_element_t<1, utils::remove_cvref_t<types>>>(
                      std::get<1>(rest))...)));
  }

  template <__alterhook_are_detour_and_original_stl_pairs_impl(pair, types)>
  void hook_chain::append(pair&& first, types&&... rest)
      __alterhook_requires(utils::detour_and_storage_stl_pairs<types...>)
  {
    append(transfer::enabled, std::forward<pair>(first),
           std::forward<types>(rest)...);
  }

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  void hook_chain::push_back(dtr&& detour, orig& original, bool enable_hook)
  {
    helpers::orig_buff_t buffer{};
    new (&buffer) helpers::original_wrapper(original);
    push_back_impl(get_target_address(std::forward<dtr>(detour)), buffer,
                   enable_hook);
  }

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  void hook_chain::push_front(dtr&& detour, orig& original, bool enable_hook)
  {
    helpers::orig_buff_t buffer{};
    new (&buffer) helpers::original_wrapper(original);
    push_front_impl(get_target_address(std::forward<dtr>(detour)), buffer,
                    enable_hook);
  }

  template <typename itr>
  void hook_chain::append_items(itr first, itr last, transfer trg)
  {
    if (first == last)
      return;
    auto [to, other] = trg == transfer::enabled ? std::tie(enabled, disabled)
                                                : std::tie(disabled, enabled);
    hook&         first_entry = to.emplace_back();
    size_t        count       = 1;
    list_iterator hitr        = std::prev(to.end());
    list_iterator hitrcurrent = hitr;

    try
    {
      if (trg == transfer::enabled)
      {
        __alterhook_def_thumb_var(ptarget);
        const std::byte* original =
            enabled.empty() ? __alterhook_add_thumb_bit(ptrampoline.get())
                            : std::prev(hitr)->pdetour;
        hook* entry = nullptr;
        first_entry.init(*this, hitr, first->pdetour, original,
                         first->origbuff);
        original = first_entry.pdetour;
        ++first;

        for (; first != last; ++first, ++count, original = entry->pdetour)
        {
          entry = &enabled.emplace_back();
          entry->init(*this, ++hitrcurrent, first->pdetour, original,
                      first->origbuff);
        }
        join_last_unchecked(count);
      }
      else
      {
        first_entry.init(*this, hitrcurrent, first->pdetour, first->origbuff);
        ++first;

        for (; first != last; ++first, ++count)
          disabled.emplace_back().init(*this, ++hitrcurrent, first->pdetour,
                                       first->origbuff);
      }
    }
    catch (...)
    {
      to.resize(to.size() - count);
      throw;
    }

    bool touch_back = false;
    if (hitr == to.begin())
    {
      if (other.empty())
        starts_enabled = static_cast<bool>(trg);
      else
        touch_back = true;
    }
    else if (std::prev(hitr)->has_other)
      touch_back = true;

    if (!touch_back)
      return;
    hook& otherback     = other.back();
    otherback.has_other = true;
    otherback.other     = hitr;
  }

  template <typename dtr, typename orig>
  typename hook_chain::hook hook_chain::hook_from(dtr&& detour, orig& original)
  {
    hook h{};
    h.pdetour = get_target_address(std::forward<dtr>(detour));
    new (&h.origbuff) helpers::original_wrapper(original);
    return h;
  }

  /*
   * NON-TEMPLATE DEFINITIONS
   */
  inline hook_chain::hook_chain(std::byte* target) : trampoline(target)
  {
    __alterhook_make_backup();
  }

  inline hook_chain::iterator hook_chain::erase(iterator position)
  {
    iterator next = std::next(position);
    erase(static_cast<list_iterator>(position));
    return next;
  }

  inline void hook_chain::merge(hook_chain& other, bool at_back)
  {
    iterator where = at_back ? end() : begin();
    splice(where, other, other.begin(), other.end());
  }

  inline void hook_chain::splice(iterator newpos, hook_chain& other,
                                 transfer from)
  {
    splice(static_cast<list_iterator>(newpos), other,
           newpos.enabled ? transfer::enabled : transfer::disabled, from);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain&& other,
                                 transfer from)
  {
    splice(newpos, other, from);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain& other,
                                 list_iterator oldpos)
  {
    splice(static_cast<list_iterator>(newpos), other, oldpos,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain&& other,
                                 list_iterator oldpos)
  {
    splice(newpos, other, oldpos);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain& other,
                                 list_iterator first, list_iterator last)
  {
    splice(static_cast<list_iterator>(newpos), other, first, last,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain&& other,
                                 list_iterator first, list_iterator last)
  {
    splice(newpos, other, first, last);
  }

  inline void hook_chain::splice(list_iterator newpos, hook_chain&& other,
                                 iterator first, iterator last, transfer to)
  {
    splice(newpos, other, first, last, to);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain& other,
                                 iterator first, iterator last)
  {
    splice(static_cast<list_iterator>(newpos), other, first, last,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain&& other,
                                 iterator first, iterator last)
  {
    splice(newpos, other, first, last);
  }

  inline void hook_chain::splice(iterator newpos, list_iterator oldpos)
  {
    splice(static_cast<list_iterator>(newpos), oldpos,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(iterator newpos, list_iterator first,
                                 list_iterator last)
  {
    splice(static_cast<list_iterator>(newpos), first, last,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(list_iterator newpos, iterator first,
                                 iterator last, transfer to)
  {
    splice(newpos, *this, first, last, to);
  }

  inline void hook_chain::splice(iterator newpos, iterator first, iterator last)
  {
    splice(static_cast<list_iterator>(newpos), first, last,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline typename hook_chain::iterator hook_chain::begin() noexcept
  {
    return iterator(disabled.begin(), enabled.begin(), starts_enabled);
  }

  inline typename hook_chain::iterator hook_chain::end() noexcept
  {
    return iterator(disabled.end(), enabled.end(),
                    disabled.empty() ? starts_enabled
                                     : disabled.back().has_other);
  }

  inline typename hook_chain::const_iterator hook_chain::begin() const noexcept
  {
    return const_iterator(disabled.begin(), enabled.begin(), starts_enabled);
  }

  inline typename hook_chain::const_iterator hook_chain::end() const noexcept
  {
    return const_iterator(disabled.end(), enabled.end(),
                          disabled.empty() ? starts_enabled
                                           : disabled.back().has_other);
  }

  inline typename hook_chain::const_iterator hook_chain::cbegin() const noexcept
  {
    return begin();
  }

  inline typename hook_chain::const_iterator hook_chain::cend() const noexcept
  {
    return end();
  }

#define __alterhook_def_getter_impl(type, name, func, list, cv)                \
  inline typename hook_chain::type hook_chain::name() cv noexcept              \
  {                                                                            \
    return list.func();                                                        \
  }

#define __alterhook_const_layer_getter_impl(type, name, func, list)            \
  __alterhook_def_getter_impl(const_##type, c##name, func, list, const)        \
      __alterhook_def_getter_impl(const_##type, name, func, list, const)       \
          __alterhook_def_getter_impl(type, name, func, list, )

#define __alterhook_reverse_layer_getter_impl(type, name, func, list)          \
  __alterhook_const_layer_getter_impl(reverse_##type, r##name, r##func, list)  \
      __alterhook_const_layer_getter_impl(type, name, func, list)

#define __alterhook_range_layer_getter_impl(prefix, list)                      \
  __alterhook_reverse_layer_getter_impl(list_iterator, prefix##begin, begin,   \
                                        list)                                  \
      __alterhook_reverse_layer_getter_impl(list_iterator, prefix##end, end,   \
                                            list)

#define __alterhook_state_layer_itr_getter_impl()                              \
  __alterhook_range_layer_getter_impl(e, enabled)                              \
      __alterhook_range_layer_getter_impl(d, disabled)

#define __alterhook_gen_itr_getter_definitions()                               \
  __alterhook_state_layer_itr_getter_impl()

  __alterhook_gen_itr_getter_definitions();

  inline void hook_chain::assert_len(size_t n) const
  {
    (void)n;
    utils_assert(
        n < size(),
        "hook_chain::operator[]: element at index specified is out of range");
  }

  inline void hook_chain::verify_len(size_t n) const
  {
    if (n < size())
      return;
    std::stringstream stream{};
    stream << "Element at index " << n
           << " of the hook_chain instance is out of range because: n >= "
              "size() <=> "
           << n << " >= " << size();
    throw(std::out_of_range(stream.str()));
  }

  inline typename hook_chain::reference
      hook_chain::operator[](size_t n) noexcept
  {
    assert_len(n);
    return *std::next(begin(), n);
  }

  inline typename hook_chain::const_reference
      hook_chain::operator[](size_t n) const noexcept
  {
    assert_len(n);
    return *std::next(begin(), n);
  }

  inline typename hook_chain::reference hook_chain::at(size_t n)
  {
    verify_len(n);
    return *std::next(begin(), n);
  }

  inline typename hook_chain::const_reference hook_chain::at(size_t n) const
  {
    verify_len(n);
    return *std::next(begin(), n);
  }

  inline typename hook_chain::reference hook_chain::front() noexcept
  {
    return *begin();
  }

  inline typename hook_chain::const_reference hook_chain::front() const noexcept
  {
    return *begin();
  }

  inline typename hook_chain::const_reference
      hook_chain::cfront() const noexcept
  {
    return front();
  }

  inline typename hook_chain::reference hook_chain::back() noexcept
  {
    if (disabled.empty() || disabled.back().has_other)
      return enabled.back();
    return disabled.back();
  }

  inline typename hook_chain::const_reference hook_chain::back() const noexcept
  {
    if (disabled.empty() || disabled.back().has_other)
      return enabled.back();
    return disabled.back();
  }

  inline typename hook_chain::const_reference hook_chain::cback() const noexcept
  {
    return back();
  }

#define __alterhook_side_layer_getter_impl(prefix, list)                       \
  __alterhook_const_layer_getter_impl(reference, prefix##front, front, list)   \
      __alterhook_const_layer_getter_impl(reference, prefix##back, back, list)

#define __alterhook_gen_elem_access_definitions()                              \
  __alterhook_side_layer_getter_impl(e, enabled)                               \
      __alterhook_side_layer_getter_impl(d, disabled)

  __alterhook_gen_elem_access_definitions();

  inline hook_chain::list_iterator hook_chain::append_hook(const hook& h,
                                                           transfer    trg)
  {
    utils_assert(trg != transfer::both,
                 "hook_chain::append_hook: to can't be the both flag");
    auto [currentitr, enable_hook] =
        trg == transfer::enabled ? std::pair(std::prev(enabled.end()), true)
                                 : std::pair(std::prev(disabled.end()), false);
    push_back_impl(h.pdetour, h.origbuff, enable_hook);
    return ++currentitr;
  }

  inline void hook_chain::set_item(hook& left, const hook& right)
  {
    left.origbuff = right.origbuff;
    left.pdetour  = right.pdetour;
  }

  inline void hook_chain::unbind_range_callback::set_pchain(list_iterator itr,
                                                            hook_chain* pchain)
  {
    itr->pchain = pchain;
  }

  inline void hook_chain::unbind_range_callback::set_enabled(list_iterator itr,
                                                             bool status)
  {
    itr->enabled = status;
  }

  inline void
      hook_chain::unbind_range_callback::set_has_other(list_iterator itr,
                                                       bool          status)
  {
    itr->has_other = status;
  }

  inline void hook_chain::unbind_range_callback::set_other(list_iterator itr,
                                                           list_iterator other)
  {
    itr->other = other;
  }

  inline hook_chain::const_iterator&
      hook_chain::const_iterator::operator++() noexcept
  {
    if (itrs[enabled]->has_other)
    {
      itrs[!enabled] = itrs[enabled]->other;
      enabled        = !enabled;
    }
    else
      ++itrs[enabled];
    return *this;
  }

  inline hook_chain::const_iterator
      hook_chain::const_iterator::operator++(int) noexcept
  {
    const_iterator tmp = *this;
    operator++();
    return tmp;
  }

  inline hook_chain::iterator& hook_chain::iterator::operator++() noexcept
  {
    if (itrs[enabled]->has_other)
    {
      itrs[!enabled] = itrs[enabled]->other;
      enabled        = !enabled;
    }
    else
      ++itrs[enabled];
    return *this;
  }

  inline hook_chain::iterator hook_chain::iterator::operator++(int) noexcept
  {
    iterator tmp = *this;
    operator++();
    return tmp;
  }

  inline hook_chain::iterator hook_chain::hook::get_iterator() noexcept
  {
    return iterator(current, current, enabled);
  }

  inline hook_chain::const_iterator
      hook_chain::hook::get_iterator() const noexcept
  {
    return const_iterator(current, current, enabled);
  }

  inline hook_chain::const_iterator
      hook_chain::hook::get_const_iterator() const noexcept
  {
    return get_iterator();
  }

  inline void hook_chain::hook::init(hook_chain& chain, list_iterator curr,
                                     const std::byte*            detour,
                                     const std::byte*            original,
                                     const helpers::orig_buff_t& buffer,
                                     bool                        enable_hook)
  {
    pchain    = &chain;
    current   = curr;
    pdetour   = detour;
    poriginal = original;
    origbuff  = buffer;
    origwrap  = std::launder(reinterpret_cast<helpers::original*>(&origbuff));
    *origwrap = original;
    enabled   = enable_hook;
  }

  inline void hook_chain::hook::init(hook_chain& chain, list_iterator curr,
                                     const std::byte*            detour,
                                     const helpers::orig_buff_t& buffer)
  {
    pchain   = &chain;
    current  = curr;
    pdetour  = detour;
    origbuff = buffer;
    origwrap = std::launder(reinterpret_cast<helpers::original*>(&origbuff));
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#elif utils_clang
  #pragma clang diagnostic pop
#endif