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

    template <__alterhook_is_detour_and_original(dtr, orig)>
    void push_back(dtr&& detour, orig& original, bool enable_hook = true);
    template <__alterhook_is_detour_and_original(dtr, orig)>
    void push_front(dtr&& detour, orig& original, bool enable_hook = true);
    template <__alterhook_is_detour_and_original(dtr, orig)>
    hook& insert(list_iterator position, dtr&& detour, orig& original,
                 include trg = include::enabled);
    template <__alterhook_is_detour_and_original(dtr, orig)>
    hook& insert(iterator position, dtr&& detour, orig& original);
    void  swap(list_iterator left, hook_chain& other, list_iterator right);

    void swap(list_iterator left, list_iterator right)
    {
      swap(left, *this, right);
    }

    void swap(hook_chain& other);
    void merge(hook_chain& other, bool at_back = false);

    void merge(hook_chain&& other, bool at_back = false)
    {
      merge(other, at_back);
    }

    void splice(list_iterator newpos, hook_chain& other,
                transfer to   = transfer::enabled,
                transfer from = transfer::both);

    void splice(list_iterator newpos, hook_chain&& other,
                transfer to = transfer::enabled, transfer from = transfer::both)
    {
      splice(newpos, other, to, from);
    }

    void splice(iterator newpos, hook_chain& other,
                transfer from = transfer::both);

    void splice(iterator newpos, hook_chain&& other,
                transfer from = transfer::both);

    void splice(list_iterator newpos, hook_chain& other, list_iterator oldpos,
                transfer to = transfer::enabled);

    void splice(list_iterator newpos, hook_chain&& other, list_iterator oldpos,
                transfer to = transfer::enabled)
    {
      splice(newpos, other, oldpos, to);
    }

    void splice(iterator newpos, hook_chain& other, list_iterator oldpos);

    void splice(iterator newpos, hook_chain&& other, list_iterator oldpos);

    void splice(list_iterator newpos, hook_chain& other, list_iterator first,
                list_iterator last, transfer to = transfer::enabled);

    void splice(list_iterator newpos, hook_chain&& other, list_iterator first,
                list_iterator last, transfer to = transfer::enabled)
    {
      splice(newpos, other, first, last, to);
    }

    void splice(iterator newpos, hook_chain& other, list_iterator first,
                list_iterator last);

    void splice(iterator newpos, hook_chain&& other, list_iterator first,
                list_iterator last);

    void splice(list_iterator newpos, hook_chain& other, iterator first,
                iterator last, transfer to = transfer::enabled);

    void splice(list_iterator newpos, hook_chain&& other, iterator first,
                iterator last, transfer to = transfer::enabled);

    void splice(iterator newpos, hook_chain& other, iterator first,
                iterator last);

    void splice(iterator newpos, hook_chain&& other, iterator first,
                iterator last);

    void splice(list_iterator newpos, list_iterator oldpos,
                transfer to = transfer::enabled)
    {
      splice(newpos, *this, oldpos, to);
    }

    void splice(iterator newpos, list_iterator oldpos);

    void splice(list_iterator newpos, list_iterator first, list_iterator last,
                transfer to = transfer::enabled)
    {
      splice(newpos, *this, first, last, to);
    }

    void splice(iterator newpos, list_iterator first, list_iterator last);

    void splice(list_iterator newpos, iterator first, iterator last,
                transfer to = transfer::enabled);

    void splice(iterator newpos, iterator first, iterator last);

    // element access
    reference       operator[](size_t n) noexcept;
    const_reference operator[](size_t n) const noexcept;
    reference       at(size_t n);
    const_reference at(size_t n) const;
    reference       front() noexcept;
    const_reference front() const noexcept;
    reference       efront() noexcept;
    const_reference efront() const noexcept;
    reference       dfront() noexcept;
    const_reference dfront() const noexcept;
    reference       back() noexcept;
    const_reference back() const noexcept;
    reference       eback() noexcept;
    const_reference eback() const noexcept;
    reference       dback() noexcept;
    const_reference dback() const noexcept;

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

  private:
    std::array<std::byte, __backup_size> backup{};
    std::list<hook>                      disabled{};
    std::list<hook>                      enabled{};
    bool                                 starts_enabled = false;

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
    void init_chain(std::index_sequence<indexes...>,
                    std::pair<std::tuple<dfirst, detours...>,
                              std::tuple<ofirst, originals...>>&& args);
    void init_chain();
    void join_last();
    void join_first();
    void join(list_iterator itr);
    void unbind_range(list_iterator first, list_iterator last,
                      unbind_range_callback& callback);
    void unbind(list_iterator position);
    void uninject_all();
    void uninject_range(list_iterator first, list_iterator last);
    void uninject(list_iterator position);
    void bind(list_iterator pos, list_iterator oldpos, bool to_enabled);
    void inject_range(list_iterator pos, list_iterator first,
                      list_iterator last);
    void inject_back(list_iterator first, list_iterator last);
    void toggle_status(list_iterator first, list_iterator last);
    void toggle_status(list_iterator position);
    void toggle_status_all(include src);

  protected:
    trampoline& get_trampoline() { return *this; }

    const trampoline& get_trampoline() const { return *this; }

    void set_trampoline(const hook_chain& other)
    {
      trampoline::operator=(other);
      memcpy(backup.data(), other.backup.data(), backup.size());
    }

    list_iterator append_item(const hook& h, transfer to = transfer::disabled);
    static void   set_item(hook& left, const hook& right);
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

  private:
    friend class hook_chain;
    friend struct hook_chain::unbind_range_callback;
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

    iterator() noexcept {}

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

    const_iterator() noexcept {}

    const_iterator(const iterator& other)
        : itrs({ other.itrs[0], other.itrs[1] }), enabled(other.enabled)
    {
    }

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
    typedef utils::clean_type_t<detour_t>                        cdetour_t;
    typedef utils::clean_type_t<original_t>                      coriginal_t;
    static_assert(
        ((std::is_same_v<utils::fn_return_t<cdetour_t>,
                         utils::fn_return_t<utils::clean_type_t<
                             utils::type_at_t<d_indexes, seq>>>> &&
          std::is_same_v<utils::fn_return_t<coriginal_t>,
                         utils::fn_return_t<utils::clean_type_t<
                             utils::type_at_t<o_indexes, seq>>>>)&&...) &&
            std::is_same_v<utils::fn_return_t<cdetour_t>,
                           utils::fn_return_t<coriginal_t>>,
        "The return types of the detours and the original function need to be "
        "the same");
#if utils_cc_assertions
    static_assert(
        ((utils::compatible_calling_convention_with<
              utils::clean_type_t<utils::type_at_t<d_indexes, seq>>,
              utils::clean_type_t<utils::type_at_t<o_indexes, seq>>> &&
          utils::compatible_calling_convention_with<
              utils::clean_type_t<utils::type_at_t<d_indexes, seq>>,
              coriginal_t> &&
          utils::compatible_calling_convention_with<
              cdetour_t,
              utils::clean_type_t<utils::type_at_t<o_indexes, seq>>>)&&...) &&
            utils::compatible_calling_convention_with<cdetour_t, coriginal_t>,
        "The calling conventions of the detours and the original function "
        "aren't compatible");
#endif
    static_assert(
        ((utils::compatible_function_arguments_with<
              utils::clean_type_t<utils::type_at_t<d_indexes, seq>>,
              utils::clean_type_t<utils::type_at_t<o_indexes, seq>>> &&
          utils::compatible_function_arguments_with<
              utils::clean_type_t<utils::type_at_t<d_indexes, seq>>,
              coriginal_t>)&&...) &&
            utils::compatible_function_arguments_with<cdetour_t, coriginal_t>,
        "The arguments of the detours and the original function aren't "
        "compatible");
    __alterhook_def_thumb_var(ptarget);
    __alterhook_make_backup();
    hook& fentry = enabled.emplace_back();
    fentry.init(*this, enabled.begin(),
                get_target_address(std::forward<detour_t>(std::get<0>(args))),
                __alterhook_add_thumb_bit(ptrampoline.get()), std::get<1>(args),
                true);
    starts_enabled = true;
    if constexpr (sizeof...(types) > 0)
    {
      list_iterator    iter    = enabled.begin();
      hook*            entry   = &fentry;
      const std::byte* pdetour = entry->pdetour;
      ((entry = &enabled.emplace_back(),
        entry->init(*this, ++iter,
                    get_target_address(std::get<d_indexes>(args)), pdetour,
                    std::get<o_indexes>(args), true),
        pdetour = entry->pdetour),
       ...);
    }
    init_chain();
  }

  template <typename dfirst, typename... detours, typename ofirst,
            typename... originals, size_t... indexes>
  void
      hook_chain::init_chain(std::index_sequence<indexes...>,
                             std::pair<std::tuple<dfirst, detours...>,
                                       std::tuple<ofirst, originals...>>&& args)
  {
    typedef utils::clean_type_t<dfirst> cdfirst;
    typedef utils::clean_type_t<ofirst> cofirst;
    static_assert(
        ((std::is_same_v<utils::fn_return_t<cdfirst>,
                         utils::fn_return_t<utils::clean_type_t<detours>>> &&
          std::is_same_v<
              utils::fn_return_t<cofirst>,
              utils::fn_return_t<utils::clean_type_t<originals>>>)&&...) &&
            std::is_same_v<utils::fn_return_t<cdfirst>,
                           utils::fn_return_t<cofirst>>,
        "The return types of the detours and the original function need to be "
        "the same");
#if utils_cc_assertions
    static_assert(
        ((utils::compatible_calling_convention_with<
              utils::clean_type_t<detours>, utils::clean_type_t<originals>> &&
          utils::compatible_calling_convention_with<
              cdfirst, utils::clean_type_t<originals>> &&
          utils::compatible_calling_convention_with<
              utils::clean_type_t<detours>, cofirst>)&&...) &&
            utils::compatible_calling_convention_with<cdfirst, cofirst>,
        "The calling conventions of the detours and the original function "
        "aren't compatible");
#endif
    static_assert(
        ((utils::compatible_function_arguments_with<
              utils::clean_type_t<detours>, utils::clean_type_t<originals>> &&
          utils::compatible_function_arguments_with<
              utils::clean_type_t<detours>, cofirst>)&&...) &&
            utils::compatible_function_arguments_with<cdfirst, cofirst>,
        "The arguments of the detours and the original function aren't "
        "compatible");

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
    helpers::orig_buff_t tmp = origbuff;
    new (&origbuff) helpers::original_wrapper(original);
    original = function_cast<orig>(poriginal);
    *std::launder(reinterpret_cast<helpers::original*>(&tmp)) = nullptr;
  }

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  hook_chain::hook& hook_chain::insert(list_iterator position, dtr&& detour,
                                       orig& original, include trg)
  {
    utils_assert(trg != include::both,
                 "hook_chain::insert: base cannot be the both flag");
    std::list<hook>* to    = nullptr;
    std::list<hook>* other = nullptr;
    list_iterator    itr{};
    list_iterator    itrprev{};

    if (trg == include::enabled)
    {
      to    = &enabled;
      other = &disabled;
      itr   = enabled.emplace(position);

      if (itr == enabled.begin())
      {
        __alterhook_def_thumb_var(ptarget);
        itr->init(*this, itr, get_target_address(std::forward<dtr>(detour)),
                  __alterhook_add_thumb_bit(ptrampoline.get()), original, true);
      }
      else
      {
        itrprev = std::prev(itr);
        itr->init(*this, itr, get_target_address(std::forward<dtr>(detour)),
                  itrprev->pdetour, original, true);
      }
      join(itr);
    }
    else
    {
      to    = &disabled;
      other = &enabled;
      itr   = disabled.emplace(position);
      itr->init(*this, itr, get_target_address(std::forward<dtr>(detour)),
                original);
    }

    if (itr == to->begin())
    {
      if (starts_enabled != itr->enabled)
      {
        list_iterator i = other->begin();
        while (!i->has_other)
          ++i;
        i->other = itr;
      }
    }
    else
    {
      itrprev = std::prev(itr);
      if (itrprev->has_other)
      {
        list_iterator i = itrprev->other;
        while (!i->has_other)
          ++i;
        i->other = itr;
      }
    }

    return *itr;
  }

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  hook_chain::hook& hook_chain::insert(iterator position, dtr&& detour,
                                       orig& original)
  {
    return insert(static_cast<list_iterator>(position),
                  std::forward<dtr>(detour), original,
                  position.enabled ? include::enabled : include::disabled);
  }

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  void hook_chain::push_back(dtr&& detour, orig& original, bool enable_hook)
  {
    hook& newentry =
        enable_hook ? enabled.emplace_back() : disabled.emplace_back();
    list_iterator    itr{};
    list_iterator    itrprev{};
    std::list<hook>* to    = nullptr;
    std::list<hook>* other = nullptr;

    if (enable_hook)
    {
      itr   = std::prev(enabled.end());
      to    = &enabled;
      other = &disabled;

      if (itr == enabled.begin())
      {
        __alterhook_def_thumb_var(ptarget);
        newentry.init(*this, itr, get_target_address(std::forward<dtr>(detour)),
                      __alterhook_add_thumb_bit(ptrampoline.get()), original,
                      true);
      }
      else
      {
        itrprev = std::prev(itr);
        newentry.init(*this, itr, get_target_address(std::forward<dtr>(detour)),
                      itrprev->pdetour, original, true);
      }
      join_last();
    }
    else
    {
      itr   = std::prev(disabled.end());
      to    = &disabled;
      other = &enabled;
      newentry.init(*this, itr, get_target_address(std::forward<dtr>(detour)),
                    original);
    }

    bool touch_back = false;

    if (itr == to->begin())
    {
      if (other->empty())
        starts_enabled = enable_hook;
      else
        touch_back = true;
    }
    else
    {
      itrprev = std::prev(itr);
      if (itrprev->has_other)
        touch_back = true;
    }

    if (touch_back)
    {
      hook& otherback     = other->back();
      otherback.has_other = true;
      otherback.other     = itr;
    }
  }

  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  void hook_chain::push_front(dtr&& detour, orig& original, bool enable_hook)
  {
    hook& newentry =
        enable_hook ? enabled.emplace_front() : disabled.emplace_front();
    std::list<hook>* other = nullptr;
    list_iterator    itr{};
    list_iterator    itrnext{};

    if (enable_hook)
    {
      itr     = enabled.begin();
      itrnext = std::next(itr);
      other   = &disabled;
      __alterhook_def_thumb_var(ptarget);
      newentry.init(*this, itr, get_target_address(std::forward<dtr>(detour)),
                    __alterhook_add_thumb_bit(ptrampoline.get()), original,
                    true);
      join_first();
    }
    else
    {
      itr     = disabled.begin();
      itrnext = std::next(itr);
      other   = &enabled;
    }

    if (starts_enabled != enable_hook && !other->empty())
    {
      newentry.has_other = true;
      newentry.other     = other->begin();
    }
    starts_enabled = enable_hook;
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

  inline hook_chain::iterator hook_chain::begin() noexcept
  {
    return iterator(disabled.begin(), enabled.begin(), starts_enabled);
  }

  inline hook_chain::iterator hook_chain::end() noexcept
  {
    return iterator(disabled.end(), enabled.end(),
                    disabled.empty() ? starts_enabled
                                     : disabled.back().has_other);
  }

  inline hook_chain::const_iterator hook_chain::begin() const noexcept
  {
    return const_iterator(disabled.begin(), enabled.begin(), starts_enabled);
  }

  inline hook_chain::const_iterator hook_chain::end() const noexcept
  {
    return const_iterator(disabled.end(), enabled.end(),
                          disabled.empty() ? starts_enabled
                                           : disabled.back().has_other);
  }

  inline hook_chain::const_iterator hook_chain::cbegin() const noexcept
  {
    return begin();
  }

  inline hook_chain::const_iterator hook_chain::cend() const noexcept
  {
    return end();
  }

  inline hook_chain::list_iterator hook_chain::ebegin() noexcept
  {
    return enabled.begin();
  }

  inline hook_chain::list_iterator hook_chain::eend() noexcept
  {
    return enabled.end();
  }

  inline hook_chain::const_list_iterator hook_chain::ebegin() const noexcept
  {
    return enabled.begin();
  }

  inline hook_chain::const_list_iterator hook_chain::eend() const noexcept
  {
    return enabled.end();
  }

  inline hook_chain::reverse_list_iterator hook_chain::rebegin() noexcept
  {
    return enabled.rbegin();
  }

  inline hook_chain::reverse_list_iterator hook_chain::reend() noexcept
  {
    return enabled.rend();
  }

  inline hook_chain::const_reverse_list_iterator
      hook_chain::rebegin() const noexcept
  {
    return enabled.rbegin();
  }

  inline hook_chain::const_reverse_list_iterator
      hook_chain::reend() const noexcept
  {
    return enabled.rend();
  }

  inline hook_chain::const_list_iterator hook_chain::cebegin() const noexcept
  {
    return enabled.begin();
  }

  inline hook_chain::const_list_iterator hook_chain::ceend() const noexcept
  {
    return enabled.end();
  }

  inline hook_chain::const_reverse_list_iterator
      hook_chain::crebegin() const noexcept
  {
    return enabled.rbegin();
  }

  inline hook_chain::const_reverse_list_iterator
      hook_chain::creend() const noexcept
  {
    return enabled.rend();
  }

  inline hook_chain::list_iterator hook_chain::dbegin() noexcept
  {
    return disabled.begin();
  }

  inline hook_chain::list_iterator hook_chain::dend() noexcept
  {
    return disabled.end();
  }

  inline hook_chain::const_list_iterator hook_chain::dbegin() const noexcept
  {
    return disabled.begin();
  }

  inline hook_chain::const_list_iterator hook_chain::dend() const noexcept
  {
    return disabled.end();
  }

  inline hook_chain::reverse_list_iterator hook_chain::rdbegin() noexcept
  {
    return disabled.rbegin();
  }

  inline hook_chain::reverse_list_iterator hook_chain::rdend() noexcept
  {
    return disabled.rend();
  }

  inline hook_chain::const_reverse_list_iterator
      hook_chain::rdbegin() const noexcept
  {
    return disabled.rbegin();
  }

  inline hook_chain::const_reverse_list_iterator
      hook_chain::rdend() const noexcept
  {
    return disabled.rend();
  }

  inline hook_chain::const_list_iterator hook_chain::cdbegin() const noexcept
  {
    return disabled.begin();
  }

  inline hook_chain::const_list_iterator hook_chain::cdend() const noexcept
  {
    return disabled.end();
  }

  inline hook_chain::const_reverse_list_iterator
      hook_chain::crdbegin() const noexcept
  {
    return disabled.rbegin();
  }

  inline hook_chain::const_reverse_list_iterator
      hook_chain::crdend() const noexcept
  {
    return disabled.rend();
  }

  inline hook_chain::reference hook_chain::operator[](size_t n) noexcept
  {
    size_t i = 0;
    for (reference h : *this)
    {
      if (i == n)
        return h;
      ++i;
    }
    utils_assert(false,
                 "hook_chain::operator[]: position passed is out of range");
  }

  inline hook_chain::const_reference
      hook_chain::operator[](size_t n) const noexcept
  {
    size_t i = 0;
    for (const_reference h : *this)
    {
      if (i == n)
        return h;
      ++i;
    }
    utils_assert(false,
                 "hook_chain::operator[]: position passed is out of range");
  }

  inline hook_chain::reference hook_chain::at(size_t n)
  {
    size_t i = 0;
    for (reference h : *this)
    {
      if (i == n)
        return h;
      ++i;
    }
    std::stringstream stream{};
    stream << "Couldn't find " << n << " element on hook_chain of size "
           << (enabled.size() + disabled.size());
    throw(std::out_of_range(stream.str()));
  }

  inline hook_chain::const_reference hook_chain::at(size_t n) const
  {
    size_t i = 0;
    for (const_reference h : *this)
    {
      if (i == n)
        return h;
      ++i;
    }
    std::stringstream stream{};
    stream << "Couldn't find " << n << " element on hook_chain of size "
           << (enabled.size() + disabled.size());
    throw(std::out_of_range(stream.str()));
  }

  inline hook_chain::reference hook_chain::front() noexcept { return *begin(); }

  inline hook_chain::const_reference hook_chain::front() const noexcept
  {
    return *begin();
  }

  inline hook_chain::reference hook_chain::back() noexcept
  {
    if (disabled.empty() || disabled.back().has_other)
      return enabled.back();
    return disabled.back();
  }

  inline hook_chain::const_reference hook_chain::back() const noexcept
  {
    if (disabled.empty() || disabled.back().has_other)
      return enabled.back();
    return disabled.back();
  }

  inline hook_chain::reference hook_chain::efront() noexcept
  {
    return enabled.front();
  }

  inline hook_chain::const_reference hook_chain::efront() const noexcept
  {
    return enabled.front();
  }

  inline hook_chain::reference hook_chain::eback() noexcept
  {
    return enabled.back();
  }

  inline hook_chain::const_reference hook_chain::eback() const noexcept
  {
    return enabled.back();
  }

  inline hook_chain::reference hook_chain::dfront() noexcept
  {
    return disabled.front();
  }

  inline hook_chain::const_reference hook_chain::dfront() const noexcept
  {
    return disabled.front();
  }

  inline hook_chain::reference hook_chain::dback() noexcept
  {
    return disabled.back();
  }

  inline hook_chain::const_reference hook_chain::dback() const noexcept
  {
    return disabled.back();
  }

  inline hook_chain::list_iterator hook_chain::append_item(const hook& h,
                                                           transfer    to)
  {
    utils_assert(to != transfer::both,
                 "hook_chain::append_item: to can't be the both flag");
    list_iterator    result{};
    list_iterator    itrprev{};
    std::list<hook>* trg   = nullptr;
    std::list<hook>* other = nullptr;

    if (to == transfer::enabled)
    {
      trg    = &enabled;
      other  = &disabled;
      result = (enabled.emplace_back(), std::prev(enabled.end()));

      if (result == enabled.begin())
      {
        __alterhook_def_thumb_var(ptarget);
        result->init(*this, result, h.pdetour,
                     __alterhook_add_thumb_bit(ptrampoline.get()), h.origbuff,
                     true);
      }
      else
      {
        itrprev = std::prev(result);
        result->init(*this, result, h.pdetour, itrprev->pdetour, h.origbuff,
                     true);
      }
      join_last();
    }
    else
    {
      trg    = &disabled;
      other  = &enabled;
      result = (disabled.emplace_back(), std::prev(disabled.end()));
      result->init(*this, result, h.pdetour, h.origbuff);
    }

    bool touch_back = false;

    if (result == trg->begin())
    {
      if (other->empty())
        starts_enabled = to == transfer::enabled;
      else
        touch_back = true;
    }
    else
    {
      itrprev = std::prev(result);
      if (itrprev->has_other)
        touch_back = true;
    }

    if (touch_back)
    {
      hook& otherback     = other->back();
      otherback.has_other = true;
      otherback.other     = result;
    }
    return result;
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