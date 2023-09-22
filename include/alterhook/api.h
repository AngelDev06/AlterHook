/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4251 4715)
#elif utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wreturn-type"
#endif

namespace alterhook
{
#if utils_arm
  inline constexpr size_t __patch_above_backup_size   = sizeof(uint64_t);
  inline constexpr size_t __patch_above_target_offset = sizeof(uint32_t);
  inline constexpr size_t __backup_size               = sizeof(uint64_t);
#else
  inline constexpr size_t __patch_above_backup_size   = 7;
  inline constexpr size_t __patch_above_target_offset = 5;
  inline constexpr size_t __backup_size               = 5;
#endif

  class ALTERHOOK_API trampoline
  {
  public:
    trampoline() noexcept {}

    trampoline(std::byte* target) { init(target); }

    trampoline(const trampoline& other);
    trampoline(trampoline&& other) noexcept;
    trampoline& operator=(const trampoline& other);
    trampoline& operator=(trampoline&& other) noexcept;

    ~trampoline() noexcept {}

    void init(std::byte* target);

    template <typename fn, typename... types>
    auto invoke(types&&... values) const
    {
      utils_assert(
          ptrampoline,
          "trampoline::invoke: attempt to invoke an uninitialized trampoline");
// for arm we need to add the thumb bit to the trampoline address if needed. (we
// check if the target has it)
#if utils_arm
      std::byte* func =
          reinterpret_cast<uintptr_t>(ptarget) & 1
              ? reinterpret_cast<std::byte*>(
                    reinterpret_cast<uintptr_t>(ptrampoline.get()) | 1)
              : ptrampoline.get();
#else
      std::byte* func = ptrampoline.get();
#endif
      return std::invoke(function_cast<fn>(func),
                         std::forward<types>(values)...);
    }

    std::byte* get_target() const noexcept { return ptarget; }

    size_t size() const noexcept { return tramp_size; }

    size_t count() const noexcept { return positions.size(); }

    std::string str() const;

  protected:
#ifdef __alterhook_expose_impl
  #if utils_windows
    friend void process_frozen_threads(const trampoline& tramp,
                                       bool enable_hook, HANDLE thread_handle);
  #else
    friend void process_frozen_threads(const trampoline& tramp,
                                       bool enable_hook, unsigned long& pc);
  #endif
#endif
    struct ALTERHOOK_API deleter
    {
      constexpr deleter() noexcept = default;

      constexpr deleter(const deleter&) noexcept {}

      void operator()(std::byte* ptrampoline) const noexcept;
    };

    typedef std::unique_ptr<std::byte, deleter> trampoline_ptr;
    std::byte*                                  ptarget = nullptr;
    trampoline_ptr                              ptrampoline{};
#if utils_x64
    std::byte* prelay = nullptr;
#elif utils_arm
    std::bitset<8> instruction_sets{};
#endif
    bool   patch_above = false;
    size_t tramp_size  = 0;
#if utils_arm
    std::pair<bool, uint8_t> pc_handling{};
#endif
#if !utils_windows
    int old_protect = 0;
#endif
    utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions{};
  };

  class ALTERHOOK_API hook : trampoline
  {
  public:
    template <__alterhook_is_detour_and_original(dtr, orig)>
    hook(std::byte* target, dtr&& detour, orig& original,
         bool enable_hook = true);

    template <__alterhook_is_detour(dtr)>
    hook(std::byte* target, dtr&& detour, bool enable_hook = true);

    template <__alterhook_is_target_detour_and_original(trg, dtr, orig)>
    hook(trg&& target, dtr&& detour, orig& original, bool enable_hook = true);

    template <__alterhook_is_target_and_detour(trg, dtr)>
    hook(trg&& target, dtr&& detour, bool enable_hook = true);

    hook(const hook& other);
    hook(hook&& other) noexcept;

    hook(const trampoline& tramp) : trampoline(tramp)
    {
      __alterhook_make_backup();
    }

    hook(trampoline&& tramp) noexcept : trampoline(std::move(tramp))
    {
      __alterhook_make_backup();
    }

    hook() noexcept {}

    ~hook() noexcept;

    hook& operator=(const hook& other);
    hook& operator=(hook&& other) noexcept;
    hook& operator=(const trampoline& other);
    hook& operator=(trampoline&& other);

    void enable();
    void disable();

    using trampoline::get_target;

    const std::byte* get_detour() const noexcept
    {
      return __alterhook_get_dtr();
    }

    size_t trampoline_size() const noexcept { return size(); }

    size_t trampoline_count() const noexcept { return count(); }

    std::string trampoline_str() const { return str(); }

    bool is_enabled() const noexcept { return enabled; }

    explicit operator bool() const noexcept { return enabled; }

    void set_target(std::byte* target);

    template <__alterhook_is_target(trg)>
    void set_target(trg&& target)
    {
      set_target(get_target_address(std::forward<trg>(target)));
    }

    template <__alterhook_is_detour(dtr)>
    void set_detour(dtr&& detour);
    template <__alterhook_is_original(orig)>
    void set_original(orig& original);
    void set_original(std::nullptr_t);

  private:
    friend class hook_chain;
#if !utils_windows64
    const std::byte* pdetour = nullptr;
#endif
    bool                                 enabled = false;
    std::array<std::byte, __backup_size> backup{};
    helpers::orig_buff_t                 original_buffer{};
    helpers::original*                   original_wrap = nullptr;

    void set_detour(std::byte* detour);
  };

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

  namespace helpers
  {
    template <typename T>
    class hook_map_base;
    template <typename T>
    class regular_hook_map_base;
    template <typename T>
    class regular_unique_hook_map_base;
    template <typename T>
    class concurrent_hook_map_base;
    template <typename T>
    class custom_concurrent_hook_map_base;
    template <typename T>
    class default_concurrent_hook_map_base;
    template <typename T>
    class default_unique_concurrent_hook_map_base;

    template <typename T, bool concurrent_mode>
    struct determine_adapter;
    template <typename T, bool concurrent_mode>
    using determine_adapter_t =
        typename determine_adapter<T, concurrent_mode>::type;
    template <typename T>
    using key_t = typename T::key_type;
  } // namespace helpers

  template <typename key, typename hash = std::hash<key>,
            typename keyequal  = std::equal_to<key>,
            typename allocator = std::allocator<std::pair<
                const key, std::reference_wrapper<typename hook_chain::hook>>>,
            template <typename, typename, typename, typename, typename>
            typename hash_map    = std::unordered_map,
            bool concurrent_mode = utils::concurrent_hash_map<
                hash_map<key, std::reference_wrapper<typename hook_chain::hook>,
                         hash, keyequal, allocator>>>
  class hook_map
      : public helpers::determine_adapter_t<
            hash_map<key, std::reference_wrapper<typename hook_chain::hook>,
                     hash, keyequal, allocator>,
            concurrent_mode>
  {
  public:
    typedef hash_map<key, std::reference_wrapper<typename hook_chain::hook>,
                     hash, keyequal, allocator>
                                                                   adapted;
    typedef helpers::determine_adapter_t<adapted, concurrent_mode> base;

    using base::base;
  };

  template <typename key,
            template <typename, typename, typename, typename, typename>
            typename hash_map>
  using hook_map_using = hook_map<
      key, std::hash<key>, std::equal_to<key>,
      std::allocator<std::pair<
          const key, std::reference_wrapper<typename hook_chain::hook>>>,
      hash_map>;

  template <typename key>
  using concurrent_hook_map = hook_map<
      key, std::hash<key>, std::equal_to<key>,
      std::allocator<std::pair<
          const key, std::reference_wrapper<typename hook_chain::hook>>>,
      std::unordered_map, true>;

  template <typename key,
            template <typename, typename, typename, typename, typename>
            typename hash_map>
  using concurrent_hook_map_using = hook_map<
      key, std::hash<key>, std::equal_to<key>,
      std::allocator<std::pair<
          const key, std::reference_wrapper<typename hook_chain::hook>>>,
      hash_map, true>;

  /*
   * ADAPTERS FOR HOOK MAP
   */
  template <typename T>
  class helpers::hook_map_base : protected hook_chain,
                                 protected T
  {
  public:
    typedef T                                adapter;
    typedef hook_chain                       base;
    typedef typename base::iterator          chain_iterator;
    typedef typename base::const_iterator    const_chain_iterator;
    typedef typename hook_chain::hook&       hook_reference;
    typedef const typename hook_chain::hook& const_hook_reference;

    using typename adapter::allocator_type;
    using typename adapter::const_pointer;
    using typename adapter::const_reference;
    using typename adapter::difference_type;
    using typename adapter::hasher;
    using typename adapter::key_equal;
    using typename adapter::key_type;
    using typename adapter::mapped_type;
    using typename adapter::pointer;
    using typename adapter::reference;
    using typename adapter::size_type;
    using typename adapter::value_type;
    using typename base::const_list_iterator;
    using typename base::const_reverse_list_iterator;
    using typename base::hook;
    using typename base::include;
    using typename base::list_iterator;
    using typename base::reverse_list_iterator;
    using transfer = base::transfer;

    using adapter::adapter;

    template <__alterhook_are_key_detour_and_original_triplets(fkey, dtr, orig,
                                                               types)>
    hook_map_base(std::byte* target, fkey&& first_key, dtr&& detour,
                  orig& original, types&&... rest)
        __alterhook_requires(
            utils::key_detour_and_storage_triplets<fkey, types...>);

    template <__alterhook_are_target_key_detour_and_original_triplets(
        trg, fkey, dtr, orig, types)>
    hook_map_base(trg&& target, fkey&& first_key, dtr&& detour, orig& original,
                  types&&... rest)
        __alterhook_requires(
            utils::key_detour_and_storage_triplets<fkey, types...>);

    template <__alterhook_are_key_detour_and_original_stl_triplets(tuple,
                                                                   types)>
    hook_map_base(std::byte* target, tuple&& first, types&&... rest)
        __alterhook_requires(utils::key_detour_and_storage_stl_triplets<
                             typename T::key_type, tuple, types...>);

    template <__alterhook_are_target_key_detour_and_original_stl_triplets(
        trg, tuple, types)>
    hook_map_base(trg&& target, tuple&& first, types&&... rest)
        __alterhook_requires(utils::key_detour_and_storage_stl_triplets<
                             typename T::key_type, tuple, types...>);

    hook_map_base(const hook_map_base& other);
    hook_map_base(const hook_map_base& other, const allocator_type& alloc);
    hook_map_base(hook_map_base&& other) noexcept;
    hook_map_base(hook_map_base&& other, const allocator_type& alloc) noexcept;

    ~hook_map_base() {}

    hook_map_base& operator=(const hook_map_base& other);
    hook_map_base& operator=(hook_map_base&& other) noexcept;
    hook_map_base& operator=(const alterhook::trampoline& other);
    hook_map_base& operator=(alterhook::trampoline&& other);

    // getters
    using base::disabled_size;
    using base::empty;
    using base::empty_disabled;
    using base::empty_enabled;
    using base::enabled_size;
    using base::get_target;
    using base::operator bool;
    using adapter::get_allocator;
    using adapter::max_size;
    using adapter::size;

    // setters
    using base::set_target;

    // lookup
    using adapter::count;

    // status update
    using base::disable_all;
    using base::enable_all;

    // modifiers
    using base::swap;
    void clear();
    void swap(hook_map_base& other);
    void merge(hook_map_base& other);

    // bucket interface
    using adapter::bucket_count;

    // hash policy
    using adapter::load_factor;
    using adapter::max_load_factor;
    using adapter::rehash;
    using adapter::reserve;

    // observers
    using adapter::hash_function;
    using adapter::key_eq;

  private:
    void swap(hook_chain&)                         = delete;
    void swap(list_iterator, base&, list_iterator) = delete;

    template <size_t... k_indexes, size_t... d_indexes, size_t... o_indexes,
              typename... types>
    hook_map_base(std::byte* target, std::index_sequence<k_indexes...>,
                  std::index_sequence<d_indexes...>,
                  std::index_sequence<o_indexes...>,
                  std::tuple<types...>&& args);
  };

  template <typename T>
  class helpers::regular_hook_map_base : public helpers::hook_map_base<T>
  {
  protected:
    template <typename itrbase>
    class __const_itr;
    template <typename itrbase>
    class __itr;

  public:
    typedef hook_map_base<T>                        base;
    typedef __const_itr<typename T::const_iterator> const_iterator;
    typedef __itr<typename T::const_iterator>       iterator;

    using typename base::allocator_type;
    using typename base::chain_iterator;
    using typename base::const_chain_iterator;
    using typename base::const_hook_reference;
    using typename base::const_list_iterator;
    using typename base::const_pointer;
    using typename base::const_reference;
    using typename base::const_reverse_list_iterator;
    using typename base::difference_type;
    using typename base::hasher;
    using typename base::hook;
    using typename base::hook_reference;
    using typename base::include;
    using typename base::key_equal;
    using typename base::key_type;
    using typename base::list_iterator;
    using typename base::mapped_type;
    using typename base::pointer;
    using typename base::reference;
    using typename base::reverse_list_iterator;
    using typename base::size_type;
    using typename base::value_type;
    using transfer = typename base::transfer;

    typedef std::conditional_t<utils::multi_hash_map<T>, iterator,
                               std::pair<iterator, bool>>
        insert_ret_t;

    using base::base;

    // getters
    using hook_chain::back;
    using hook_chain::dback;
    using hook_chain::dfront;
    using hook_chain::eback;
    using hook_chain::efront;
    using hook_chain::front;

    // modifiers
    template <typename K1, typename K2>
    void splice(const K1& newpos, const K2& oldpos);
    template <typename K1, typename K2>
    void swap(const K1& left, const K2& right);
    template <__alterhook_is_key_detour_and_original(K, dtr, orig)>
    insert_ret_t insert(K&& k, dtr&& detour, orig& original,
                        transfer to = transfer::enabled);
    iterator     erase(const_iterator pos);
    iterator     erase(const_iterator first, const_iterator last);
    template <typename K>
    size_type erase(const K& k);
    using hook_chain::splice;
    using hook_chain::swap;

    // lookup
    template <typename K>
    std::pair<iterator, iterator> equal_range(const K& k);
    template <typename K>
    std::pair<const_iterator, const_iterator> equal_range(const K& k) const;
    template <typename K>
    iterator find(const K& k);
    template <typename K>
    const_iterator find(const K& k) const;

    // iterators
    iterator begin() noexcept { return iterator(T::begin()); }

    const_iterator begin() const noexcept { return const_iterator(T::begin()); }

    iterator end() noexcept { return iterator(T::end()); }

    const_iterator end() const noexcept { return const_iterator(T::end()); }

    const_iterator cbegin() const noexcept
    {
      return const_iterator(T::begin());
    }

    const_iterator cend() const noexcept { return const_iterator(T::end()); }

    // clang-format off
    utils_map(__alterhook_decl_itr_func, (chain_iterator, begin),
              (chain_iterator, end), (list_iterator, ebegin),
              (list_iterator, eend), (reverse_list_iterator, rebegin),
              (reverse_list_iterator, reend), (list_iterator, dbegin),
              (list_iterator, dend), (reverse_list_iterator, rdbegin),
              (reverse_list_iterator, rdend))

  private: 
    void swap(hook_chain&)                                            = delete;
    void swap(list_iterator, hook_chain&, list_iterator)              = delete;
    void splice(list_iterator, hook_chain&, transfer, transfer)       = delete;
    void splice(list_iterator, hook_chain&&, transfer, transfer)      = delete;
    void splice(chain_iterator, hook_chain&, transfer)                = delete;
    void splice(chain_iterator, hook_chain&&, transfer)               = delete;
    void splice(list_iterator, hook_chain&, list_iterator, transfer)  = delete;
    void splice(list_iterator, hook_chain&&, list_iterator, transfer) = delete;
    void splice(chain_iterator, hook_chain&, list_iterator)           = delete;
    void splice(chain_iterator, hook_chain&&, list_iterator)          = delete;
    void splice(list_iterator, hook_chain&, list_iterator, list_iterator,
                transfer)                                             = delete;
    void splice(list_iterator, hook_chain&&, list_iterator, list_iterator,
                transfer)                                             = delete;
    void splice(chain_iterator, hook_chain&, list_iterator,
                list_iterator)                                        = delete;
    void splice(chain_iterator, hook_chain&&, list_iterator,
                list_iterator)                                        = delete;
    void splice(list_iterator, hook_chain&, chain_iterator, chain_iterator,
                transfer)                                             = delete;
    void splice(list_iterator, hook_chain&&, chain_iterator, chain_iterator,
                transfer)                                             = delete;
    void splice(chain_iterator, hook_chain&, chain_iterator,
                chain_iterator)                                       = delete;
    void splice(chain_iterator, hook_chain&&, chain_iterator,
                chain_iterator)                                       = delete;
    // clang-format on
  };

  template <typename T>
  class helpers::regular_unique_hook_map_base
      : public helpers::regular_hook_map_base<T>
  {
  public:
    typedef regular_hook_map_base<T> base;
    using typename base::allocator_type;
    using typename base::chain_iterator;
    using typename base::const_chain_iterator;
    using typename base::const_hook_reference;
    using typename base::const_list_iterator;
    using typename base::const_pointer;
    using typename base::const_reference;
    using typename base::const_reverse_list_iterator;
    using typename base::difference_type;
    using typename base::hasher;
    using typename base::hook;
    using typename base::hook_reference;
    using typename base::include;
    using typename base::insert_ret_t;
    using typename base::key_equal;
    using typename base::key_type;
    using typename base::list_iterator;
    using typename base::mapped_type;
    using typename base::pointer;
    using typename base::reference;
    using typename base::reverse_list_iterator;
    using typename base::size_type;
    using typename base::value_type;
    using transfer = typename base::transfer;

    using base::base;

    // lookup
    template <typename K>
    hook_reference operator[](const K& k);
    template <typename K>
    const_hook_reference operator[](const K& k) const;
    template <typename K>
    hook_reference at(const K& k);
    template <typename K>
    const_hook_reference at(const K& k) const;
  };

  template <typename T>
  class helpers::concurrent_hook_map_base : public helpers::hook_map_base<T>
  {
  public:
    typedef hook_map_base<T> base;
    using typename base::allocator_type;
    using typename base::chain_iterator;
    using typename base::const_chain_iterator;
    using typename base::const_hook_reference;
    using typename base::const_list_iterator;
    using typename base::const_pointer;
    using typename base::const_reference;
    using typename base::const_reverse_list_iterator;
    using typename base::difference_type;
    using typename base::hasher;
    using typename base::hook;
    using typename base::hook_reference;
    using typename base::include;
    using typename base::key_equal;
    using typename base::key_type;
    using typename base::list_iterator;
    using typename base::mapped_type;
    using typename base::pointer;
    using typename base::reference;
    using typename base::reverse_list_iterator;
    using typename base::size_type;
    using typename base::value_type;
    using transfer = typename base::transfer;

    using base::base;

    concurrent_hook_map_base(const concurrent_hook_map_base& other)
        : concurrent_hook_map_base(other, std::shared_lock(other.map_lock))
    {
    }

    concurrent_hook_map_base(concurrent_hook_map_base&& other)
        : concurrent_hook_map_base(std::move(other),
                                   std::unique_lock(other.map_lock))
    {
    }

    concurrent_hook_map_base& operator=(const concurrent_hook_map_base& other);
    concurrent_hook_map_base& operator=(concurrent_hook_map_base&& other);

    // getters
    bool       empty() const noexcept;
    bool       empty_enabled() const noexcept;
    bool       empty_disabled() const noexcept;
    size_t     enabled_size() const noexcept;
    size_t     disabled_size() const noexcept;
    std::byte* get_target() const noexcept;
    explicit operator bool() const noexcept;

    // setters
    template <typename trg>
    void set_target(trg&& target);

    // status update
    void disable_all();
    void enable_all();

    // modifiers
    void swap(concurrent_hook_map_base& other);
    void merge(concurrent_hook_map_base& other);
    void clear();

  private:
    concurrent_hook_map_base(const concurrent_hook_map_base&       other,
                             std::shared_lock<std::shared_mutex>&& lock)
        : base(other)
    {
    }

    concurrent_hook_map_base(concurrent_hook_map_base&&            other,
                             std::unique_lock<std::shared_mutex>&& lock)
        : base(std::move(other))
    {
    }

  protected:
    mutable std::shared_mutex map_lock;
  };

  template <typename T>
  class helpers::custom_concurrent_hook_map_base
      : public helpers::concurrent_hook_map_base<T>
  {
  public:
    typedef helpers::concurrent_hook_map_base<T> base;
    using typename base::allocator_type;
    using typename base::chain_iterator;
    using typename base::const_chain_iterator;
    using typename base::const_hook_reference;
    using typename base::const_list_iterator;
    using typename base::const_pointer;
    using typename base::const_reference;
    using typename base::const_reverse_list_iterator;
    using typename base::difference_type;
    using typename base::hasher;
    using typename base::hook;
    using typename base::hook_reference;
    using typename base::include;
    using typename base::key_equal;
    using typename base::key_type;
    using typename base::list_iterator;
    using typename base::mapped_type;
    using typename base::pointer;
    using typename base::reference;
    using typename base::reverse_list_iterator;
    using typename base::size_type;
    using typename base::value_type;
    using transfer = typename base::transfer;

    using base::base;

    // visitation
    template <typename K, typename callable>
    size_t visit(const K& k, callable&& func);
    template <typename K, typename callable>
    size_t visit(const K& k, callable&& func) const;
    template <typename K, typename callable>
    size_t cvisit(const K& k, callable&& func) const;

    template <typename callable>
    size_t visit_all(callable&& func);
    template <typename callable>
    size_t visit_all(callable&& func) const;
    template <typename callable>
    size_t cvisit_all(callable&& func) const;
    template <typename execution_policy, typename callable>
    void visit_all(execution_policy&& policy, callable&& func);
    template <typename execution_policy, typename callable>
    void visit_all(execution_policy&& policy, callable&& func) const;
    template <typename execution_policy, typename callable>
    void cvisit_all(execution_policy&& policy, callable&& func) const;

    // modifiers
    template <typename K>
    void splice(const K& newpos, const K& oldpos);

    template <__alterhook_is_key_detour_and_original(K, dtr, orig)>
    bool insert(K&& k, dtr&& detour, orig& original,
                transfer to = transfer::enabled);
    template <typename callable,
              __alterhook_is_key_detour_and_original(K, dtr, orig)>
    bool insert_or_visit(K&& k, dtr&& detour, orig& original, callable&& func,
                         transfer to = transfer::enabled);
    template <typename callable,
              __alterhook_is_key_detour_and_original(K, dtr, orig)>
    bool insert_or_cvisit(K&& k, dtr&& detour, orig& original, callable&& func,
                          transfer to = transfer::enabled);
    template <typename K>
    size_type erase(const K& k);
    template <typename K, typename callable>
    size_type erase_if(const K& k, callable&& func);
    template <typename callable>
    size_type erase_if(callable&& func);
    template <typename execution_policy, typename callable>
    size_type erase_if(execution_policy&& policy, callable&& func);
  };

  template <typename T>
  class helpers::default_concurrent_hook_map_base
      : public helpers::concurrent_hook_map_base<T>
  {
  public:
    typedef helpers::concurrent_hook_map_base<T> base;
    using typename base::allocator_type;
    using typename base::chain_iterator;
    using typename base::const_chain_iterator;
    using typename base::const_hook_reference;
    using typename base::const_list_iterator;
    using typename base::const_pointer;
    using typename base::const_reference;
    using typename base::const_reverse_list_iterator;
    using typename base::difference_type;
    using typename base::hasher;
    using typename base::hook;
    using typename base::hook_reference;
    using typename base::include;
    using typename base::key_equal;
    using typename base::key_type;
    using typename base::list_iterator;
    using typename base::mapped_type;
    using typename base::pointer;
    using typename base::reference;
    using typename base::reverse_list_iterator;
    using typename base::size_type;
    using typename base::value_type;
    using transfer = typename base::transfer;

    using base::base;

    // visitation
    template <typename K, typename callable>
    size_t visit(const K& k, callable&& func);
    template <typename K, typename callable>
    size_t visit(const K& k, callable&& func) const;
    template <typename K, typename callable>
    size_t cvisit(const K& k, callable&& func) const;

    template <typename callable>
    size_t visit_all(callable&& func);
    template <typename callable>
    size_t visit_all(callable&& func) const;
    template <typename callable>
    size_t cvisit_all(callable&& func) const;

    // modifiers
    template <typename K1, typename K2>
    void splice(const K1& newpos, const K2& oldpos);
    template <typename K1, typename K2>
    void swap(const K1& left, const K2& right);
    using base::swap;

    template <__alterhook_is_key_detour_and_original(K, dtr, orig)>
    bool insert(K&& k, dtr&& detour, orig& original,
                transfer to = transfer::enabled);
    template <typename K>
    size_type erase(const K& k);
    template <typename K, typename callable>
    size_type erase_if(const K& k, callable&& func);
    template <typename callable>
    size_type erase_if(callable&& func);

    // lookup
    template <typename K>
    size_type count(const K& k) const;

    // bucket interface
    size_type bucket_count() const noexcept;

    // hash policy
    float load_factor() const noexcept;
    float max_load_factor() const noexcept;
    void  max_load_factor(float z);
    void  rehash(size_type n);
    void  reserve(size_type n);
  };

  template <typename T>
  class helpers::default_unique_concurrent_hook_map_base
      : public helpers::default_concurrent_hook_map_base<T>
  {
  public:
    typedef helpers::default_concurrent_hook_map_base<T> base;
    using typename base::allocator_type;
    using typename base::chain_iterator;
    using typename base::const_chain_iterator;
    using typename base::const_hook_reference;
    using typename base::const_list_iterator;
    using typename base::const_pointer;
    using typename base::const_reference;
    using typename base::const_reverse_list_iterator;
    using typename base::difference_type;
    using typename base::hasher;
    using typename base::hook;
    using typename base::hook_reference;
    using typename base::include;
    using typename base::key_equal;
    using typename base::key_type;
    using typename base::list_iterator;
    using typename base::mapped_type;
    using typename base::pointer;
    using typename base::reference;
    using typename base::reverse_list_iterator;
    using typename base::size_type;
    using typename base::value_type;
    using transfer = typename base::transfer;

    using base::base;

    template <typename callable,
              __alterhook_is_key_detour_and_original(K, dtr, orig)>
    bool insert_or_visit(K&& k, dtr&& detour, orig& original, callable&& func,
                         transfer to = transfer::enabled);
    template <typename callable,
              __alterhook_is_key_detour_and_original(K, dtr, orig)>
    bool insert_or_cvisit(K&& k, dtr&& detour, orig& original, callable&& func,
                          transfer to = transfer::enabled);
  };

  template <typename T>
  template <typename itrbase>
  class helpers::regular_hook_map_base<T>::__const_itr : public itrbase
  {
  public:
    typedef std::pair<typename T::key_type, typename hook_chain::hook>
        value_type;
    typedef std::pair<const typename T::key_type&,
                      const typename hook_chain::hook&>
        reference;

    using typename itrbase::difference_type;
    using typename itrbase::iterator_category;
    using typename itrbase::pointer;

    __const_itr() noexcept {}

    __const_itr(itrbase itr) : itrbase(itr) {}

    reference operator*() const noexcept
    {
      auto ptr = itrbase::operator->();
      return std::make_pair(std::cref(ptr->first), std::cref(ptr->second));
    }

    __const_itr& operator++()
    {
      itrbase::operator++();
      return *this;
    }

    __const_itr operator++(int)
    {
      __const_itr tmp = *this;
      ++*this;
      return tmp;
    }
  };

  template <typename T>
  template <typename itrbase>
  class helpers::regular_hook_map_base<T>::__itr : public __const_itr<itrbase>
  {
  public:
    typedef __const_itr<itrbase> base;
    typedef std::pair<const typename T::key_type&, typename hook_chain::hook&>
        reference;
    using typename base::difference_type;
    using typename base::iterator_category;
    using typename base::pointer;
    using typename base::value_type;

    __itr() noexcept {}

    __itr(itrbase itr) : __const_itr<itrbase>(itr) {}

    reference operator*() const noexcept
    {
      auto ptr = __const_itr<itrbase>::operator->();
      return std::make_pair(std::cref(ptr->first), ptr->second);
    }

    __itr& operator++()
    {
      __const_itr<itrbase>::operator++();
      return *this;
    }

    __itr operator++(int)
    {
      __itr tmp = *this;
      ++*this;
      return tmp;
    }
  };

  /*
   * ADAPTER HANDLING
   */
  namespace helpers
  {
    enum class adapter_type
    {
      NONE,
      REGULAR_UNIQUE_HOOK_MAP,           // eg. std::unordered_map
      REGULAR_MULTI_HOOK_MAP,            // eg. std::unordered_multimap
      CUSTOM_CONCURRENT_HOOK_MAP,        // eg. boost::concurrent_flat_map
      DEFAULT_CONCURRENT_HOOK_MAP,       // eg. std::unordered_multimap with
                                         // concurrent_mode = true
      DEFAULT_UNIQUE_CONCURRENT_HOOK_MAP // eg. std::unordered_map with
                                         // concurrent_mode = true
    };

    template <typename T>
    class bucket_api_base : public T
    {
    public:
      typedef T                                   base;
      typedef utils::first_template_param_of_t<T> adapted;
      typedef
          typename base::template __itr<typename adapted::const_local_iterator>
              local_iterator;
      typedef typename base::template __const_itr<
          typename adapted::const_local_iterator>
          const_local_iterator;
      using typename base::allocator_type;
      using typename base::chain_iterator;
      using typename base::const_chain_iterator;
      using typename base::const_hook_reference;
      using typename base::const_iterator;
      using typename base::const_list_iterator;
      using typename base::const_pointer;
      using typename base::const_reference;
      using typename base::const_reverse_list_iterator;
      using typename base::difference_type;
      using typename base::hasher;
      using typename base::hook;
      using typename base::hook_reference;
      using typename base::include;
      using typename base::iterator;
      using typename base::key_equal;
      using typename base::key_type;
      using typename base::list_iterator;
      using typename base::mapped_type;
      using typename base::pointer;
      using typename base::reference;
      using typename base::reverse_list_iterator;
      using typename base::size_type;
      using typename base::value_type;
      using transfer = typename base::transfer;

      using base::base;

      using base::begin;
      using base::cbegin;
      using base::cend;
      using base::end;

      local_iterator begin(size_type n)
      {
        return static_cast<local_iterator>(adapted::begin(n));
      }

      const_local_iterator begin(size_type n) const
      {
        return static_cast<const_local_iterator>(adapted::begin(n));
      }

      const_local_iterator cbegin(size_type n) const
      {
        return static_cast<const_local_iterator>(adapted::begin(n));
      }

      local_iterator end(size_type n)
      {
        return static_cast<local_iterator>(adapted::end(n));
      }

      const_local_iterator end(size_type n) const
      {
        return static_cast<const_local_iterator>(adapted::end(n));
      }

      const_local_iterator cend(size_type n) const
      {
        return static_cast<const_local_iterator>(adapted::end(n));
      }

      using base::bucket;
      using base::bucket_size;
      using base::max_bucket_count;
    };

    template <typename T,
              bool =
                  utils::closed_addressing<utils::first_template_param_of_t<T>>>
    struct add_bucket_api
    {
      typedef T type;
    };

    template <typename T>
    struct add_bucket_api<T, true>
    {
      typedef bucket_api_base<T> type;
    };

    template <typename T>
    using add_bucket_api_t = typename add_bucket_api<T>::type;

    template <typename T, adapter_type type = adapter_type::NONE>
    struct determine_adapter_impl
    {
      static_assert(utils::always_false<T>,
                    "couldn't find a suitable adapter for given hash map");
    };

    template <typename T>
    struct determine_adapter_impl<T, adapter_type::REGULAR_UNIQUE_HOOK_MAP>
    {
      typedef add_bucket_api_t<regular_unique_hook_map_base<T>> type;
    };

    template <typename T>
    struct determine_adapter_impl<T, adapter_type::REGULAR_MULTI_HOOK_MAP>
    {
      typedef add_bucket_api_t<regular_hook_map_base<T>> type;
    };

    template <typename T>
    struct determine_adapter_impl<T, adapter_type::CUSTOM_CONCURRENT_HOOK_MAP>
    {
      typedef custom_concurrent_hook_map_base<T> type;
    };

    template <typename T>
    struct determine_adapter_impl<T, adapter_type::DEFAULT_CONCURRENT_HOOK_MAP>
    {
      typedef default_concurrent_hook_map_base<T> type;
    };

    template <typename T>
    struct determine_adapter_impl<
        T, adapter_type::DEFAULT_UNIQUE_CONCURRENT_HOOK_MAP>
    {
      typedef default_unique_concurrent_hook_map_base<T> type;
    };

    template <typename T, bool concurrent_mode>
    struct determine_adapter
        : determine_adapter_impl<T, utils::regular_hash_map<T>
                                        ? adapter_type::REGULAR_UNIQUE_HOOK_MAP
                                    : utils::multi_hash_map<T>
                                        ? adapter_type::REGULAR_MULTI_HOOK_MAP
                                        : adapter_type::NONE>
    {
    };

    template <typename T>
    struct determine_adapter<T, true>
        : determine_adapter_impl<
              T, utils::regular_hash_map<T>
                     ? adapter_type::DEFAULT_UNIQUE_CONCURRENT_HOOK_MAP
                 : utils::multi_hash_map<T>
                     ? adapter_type::DEFAULT_CONCURRENT_HOOK_MAP
                 : utils::concurrent_hash_map<T>
                     ? adapter_type::CUSTOM_CONCURRENT_HOOK_MAP
                     : adapter_type::NONE>
    {
    };
  } // namespace helpers

  /*
   * TEMPLATE DEFINITIONS (ignore them)
   */
  template <__alterhook_is_detour_and_original_impl(dtr, orig)>
  hook::hook(std::byte* target, dtr&& detour, orig& original, bool enable_hook)
      : trampoline(target)
  {
    helpers::assert_valid_detour_original_pair<dtr, orig>();
    __alterhook_def_thumb_var(target);
    new (&original_buffer) helpers::original_wrapper(original);
    original_wrap =
        std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
    __alterhook_make_backup();
    __alterhook_set_dtr(get_target_address(std::forward<dtr>(detour)));
    original =
        function_cast<orig>(__alterhook_add_thumb_bit(ptrampoline.get()));
    utils_assert(target != __alterhook_get_dtr(),
                 "hook::hook: detour & target have the same address");
    if (enable_hook)
      enable();
  }

  template <__alterhook_is_detour_impl(dtr)>
  hook::hook(std::byte* target, dtr&& detour, bool enable_hook)
      : trampoline(target)
  {
    __alterhook_make_backup();
    __alterhook_set_dtr(get_target_address(std::forward<dtr>(detour)));
    utils_assert(target != __alterhook_get_dtr(),
                 "hook::hook: detour & target have the same address");
    if (enable_hook)
      enable();
  }

  template <__alterhook_is_target_detour_and_original_impl(trg, dtr, orig)>
  hook::hook(trg&& target, dtr&& detour, orig& original, bool enable_hook)
      : hook(get_target_address(std::forward<trg>(target)),
             std::forward<dtr>(detour), original, enable_hook)
  {
  }

  template <__alterhook_is_target_and_detour_impl(trg, dtr)>
  hook::hook(trg&& target, dtr&& detour, bool enable_hook)
      : hook(get_target_address(std::forward<trg>(target)),
             std::forward<dtr>(detour), enable_hook)
  {
  }

  template <__alterhook_is_detour_impl(dtr)>
  void hook::set_detour(dtr&& detour)
  {
    set_detour(get_target_address(std::forward<dtr>(detour)));
  }

  template <__alterhook_is_original_impl(orig)>
  void hook::set_original(orig& original)
  {
    if (original_wrap->contains_ref(original))
      return;
    __alterhook_def_thumb_var(ptarget);
    bool                 has_orig_wrap = original_wrap;
    helpers::orig_buff_t tmp           = original_buffer;
    new (&original_buffer) helpers::original_wrapper(original);
    original_wrap =
        std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
    original =
        function_cast<orig>(__alterhook_add_thumb_bit(ptrampoline.get()));
    if (has_orig_wrap)
      *std::launder(reinterpret_cast<helpers::original*>(&tmp)) = nullptr;
  }

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

  template <typename T>
  template <size_t... k_indexes, size_t... d_indexes, size_t... o_indexes,
            typename... types>
  helpers::hook_map_base<T>::hook_map_base(std::byte* target,
                                           std::index_sequence<k_indexes...>,
                                           std::index_sequence<d_indexes...>,
                                           std::index_sequence<o_indexes...>,
                                           std::tuple<types...>&& args)
      : hook_chain(
            target,
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<d_indexes, std::tuple<types...>>>(
                    std::get<d_indexes>(args)),
                std::forward<
                    std::tuple_element_t<o_indexes, std::tuple<types...>>>(
                    std::get<o_indexes>(args)))...)
  {
    list_iterator itr = ebegin();

    (adapter::emplace(
         std::forward<std::tuple_element_t<k_indexes, std::tuple<types...>>>(
             std::get<k_indexes>(args)),
         std::ref(*(itr++))),
     ...);
  }

  template <typename T>
  template <__alterhook_are_key_detour_and_original_triplets_impl(fkey, dtr,
                                                                  orig, types)>
  helpers::hook_map_base<T>::hook_map_base(std::byte* target, fkey&& first_key,
                                           dtr&& detour, orig& original,
                                           types&&... rest)
      __alterhook_requires(
          utils::key_detour_and_storage_triplets<fkey, types...>)
      : hook_map_base(
            target,
            utils::make_index_sequence_with_step<sizeof...(types) + 3, 0, 3>(),
            utils::make_index_sequence_with_step<sizeof...(types) + 3, 1, 3>(),
            utils::make_index_sequence_with_step<sizeof...(types) + 3, 2, 3>(),
            std::forward_as_tuple(std::forward<fkey>(first_key),
                                  std::forward<dtr>(detour), original,
                                  std::forward<types>(rest)...))
  {
  }

  template <typename T>
  template <__alterhook_are_target_key_detour_and_original_triplets_impl(
      trg, fkey, dtr, orig, types)>
  helpers::hook_map_base<T>::hook_map_base(trg&& target, fkey&& first_key,
                                           dtr&& detour, orig& original,
                                           types&&... rest)
      __alterhook_requires(
          utils::key_detour_and_storage_triplets<fkey, types...>)
      : hook_map_base(get_target_address(std::forward<trg>(target)),
                      std::forward<fkey>(first_key), std::forward<dtr>(detour),
                      original, std::forward<types>(rest)...)
  {
  }

  template <typename T>
  template <__alterhook_are_key_detour_and_original_stl_triplets_impl(tuple,
                                                                      types)>
  helpers::hook_map_base<T>::hook_map_base(std::byte* target, tuple&& first,
                                           types&&... rest)
      __alterhook_requires(utils::key_detour_and_storage_stl_triplets<
                           typename T::key_type, tuple, types...>)
      : hook_chain(
            target,
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<tuple>>>(
                    std::get<1>(first)),
                std::get<2>(first)),
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<types>>>(
                    std::get<1>(rest)),
                std::get<2>(rest))...)
  {
    list_iterator itr = base::ebegin();
    adapter::emplace(
        std::forward<std::tuple_element_t<0, utils::remove_cvref_t<tuple>>>(
            std::get<0>(first)),
        std::ref(*(itr++)));
    (adapter::emplace(
         std::forward<std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
             std::get<0>(rest)),
         std::ref(*(itr++))),
     ...);
  }

  template <typename T>
  template <__alterhook_are_target_key_detour_and_original_stl_triplets_impl(
      trg, tuple, types)>
  helpers::hook_map_base<T>::hook_map_base(trg&& target, tuple&& first,
                                           types&&... rest)
      __alterhook_requires(utils::key_detour_and_storage_stl_triplets<
                           typename T::key_type, tuple, types...>)
      : hook_map_base(get_target_address(std::forward<trg>(target)),
                      std::forward<tuple>(first), std::forward<types>(rest)...)
  {
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(const hook_map_base& other)
      : hook_chain(other.get_target())
  {
    for (const auto& [k, v] : static_cast<const adapter&>(other))
      adapter::emplace(k, *append_item(v));
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(const hook_map_base&  other,
                                           const allocator_type& alloc)
      : adapter(alloc), hook_chain(other.get_target())
  {
    for (const auto& [k, v] : static_cast<const adapter&>(other))
      adapter::emplace(k, *append_item(v));
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(hook_map_base&& other) noexcept
      : adapter(std::move(other)), hook_chain(std::move(other))
  {
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(hook_map_base&&       other,
                                           const allocator_type& alloc) noexcept
      : adapter(std::move(other), alloc), hook_chain(std::move(other))
  {
  }

  template <typename T>
  helpers::hook_map_base<T>&
      helpers::hook_map_base<T>::operator=(const hook_map_base& other)
  {
    if (this != &other)
    {
      disable_all();
      set_trampoline(other.get_trampoline());

      for (auto itr = adapter::begin(), enditr = adapter::end(); itr != enditr;)
      {
        if (other.adapter::count(itr->first))
          ++itr;
        else
          itr = adapter::erase(itr);
      }

      if (adapter::size() >= other.adapter::size())
      {
        chain_iterator itr = base::begin();
        for (auto& [k, otheritr] : static_cast<const adapter&>(other))
        {
          set_item(*itr, static_cast<const hook&>(otheritr));
          adapter::insert_or_assign(k, std::ref(*(itr++)));
        }

        base::erase(itr, base::end());
      }
      else
      {
        typename adapter::const_iterator otheritr = other.adapter::begin();
        for (list_iterator itr = base::dbegin(), itrend = base::dend();
             itr != itrend; ++itr)
        {
          set_item(*itr, otheritr->second);
          adapter::insert_or_assign(otheritr->first, std::ref(*(itr++)));
        }

        for (typename adapter::const_iterator otherend = other.adapter::end();
             otheritr != otherend; ++otheritr)
          adapter::insert_or_assign(otheritr->first,
                                    std::ref(*append_item(otheritr->second)));
      }
    }
    return *this;
  }

  template <typename T>
  helpers::hook_map_base<T>&
      helpers::hook_map_base<T>::operator=(hook_map_base&& other) noexcept
  {
    if (&other != this)
    {
      hook_chain::operator=(std::move(other));
      adapter::operator=(std::move(other));
    }
    return *this;
  }

  template <typename T>
  helpers::hook_map_base<T>&
      helpers::hook_map_base<T>::operator=(const alterhook::trampoline& other)
  {
    base::operator=(other);
    return *this;
  }

  template <typename T>
  helpers::hook_map_base<T>&
      helpers::hook_map_base<T>::operator=(alterhook::trampoline&& other)
  {
    base::operator=(std::move(other));
    return *this;
  }

  template <typename T>
  void helpers::hook_map_base<T>::clear()
  {
    base::clear();
    adapter::clear();
  }

  template <typename T>
  void helpers::hook_map_base<T>::swap(hook_map_base& other)
  {
    base::swap(other);
    adapter::swap(other);
  }

  template <typename T>
  void helpers::hook_map_base<T>::merge(hook_map_base& other)
  {
    for (auto itr = other.adapter::begin(), itrend = other.adapter::end();
         itr != itrend; ++itr)
    {
      if (adapter::count(itr->first))
        continue;
      auto [flag, newpos] = itr->second.get().is_enabled()
                                ? std::pair(transfer::enabled, base::eend())
                                : std::pair(transfer::disabled, base::dend());
      base::splice(newpos, other, itr->second.get().get_list_iterator(), flag);
      adapter::insert(*itr);
      other.adapter::erase(itr);
    }
  }

  template <typename T>
  typename helpers::regular_hook_map_base<T>::iterator
      helpers::regular_hook_map_base<T>::erase(const_iterator pos)
  {
    hook_chain::erase(pos->second.get().get_list_iterator());
    return T::erase(pos);
  }

  template <typename T>
  typename helpers::regular_hook_map_base<T>::iterator
      helpers::regular_hook_map_base<T>::erase(const_iterator first,
                                               const_iterator last)
  {
    while (first != last)
    {
      hook_chain::erase(first->second.get().get_list_iterator());
      first = T::erase(first);
    }
    return last;
  }

  template <typename T>
  template <typename K>
  typename helpers::regular_hook_map_base<T>::size_type
      helpers::regular_hook_map_base<T>::erase(const K& k)
  {
    if constexpr (utils::multi_hash_map<T>)
    {
      auto   range = T::equal_range(k);
      size_t count = 0;
      while (range.first != range.second)
      {
        hook_chain::erase(range.first->second.get().get_list_iterator());
        range.first = T::erase(range.first);
        ++count;
      }
      return count;
    }
    else
    {
      auto result = T::find(k);
      if (result == T::cend())
        return 0;
      hook_chain::erase(result->second.get().get_list_iterator());
      T::erase(result);
      return 1;
    }
  }

  template <typename T>
  template <__alterhook_is_key_detour_and_original_impl(K, dtr, orig)>
  typename helpers::regular_hook_map_base<T>::insert_ret_t
      helpers::regular_hook_map_base<T>::insert(K&& k, dtr&& detour,
                                                orig& original, transfer to)
  {
    if constexpr (!utils::multi_hash_map<T>)
    {
      if (base::count(k))
        return std::pair(iterator(), false);
    }
    list_iterator pos =
        to == transfer::enabled ? hook_chain::eend() : hook_chain::dend();
    hook& h = hook_chain::insert(pos, std::forward<dtr>(detour), original, to);
    return static_cast<insert_ret_t>(
        T::emplace(std::forward<K>(k), std::ref(h)));
  }

  template <typename T>
  template <typename K1, typename K2>
  void helpers::regular_hook_map_base<T>::swap(const K1& left, const K2& right)
  {
    if constexpr (utils::multi_hash_map<T>)
    {
      auto range_left = T::equal_range(left);
      if (range_left.first == range_left.second)
        throw(std::out_of_range("hook_map: out of range swap left operand"));
      auto range_right = T::equal_range(right);
      if (range_right.first == range_right.second)
        throw(std::out_of_range("hook_map: out of range swap right operand"));
      hook_chain::swap(range_left.first->second.get().get_list_iterator(),
                       range_right.first->second.get().get_list_iterator());

      auto [trgitrleft, trgitrright] =
          std::pair(range_right.first->second.get().get_iterator(),
                    range_left.first->second.get().get_iterator());

      ++range_right.first;
      ++range_left.first;

      for (auto itr_right = range_right.first; itr_right != range_right.second;
           ++itr_right)
      {
        hook_chain::splice(++trgitrleft,
                           itr_right->second.get().get_list_iterator());
        trgitrleft = itr_right->second.get().get_iterator();
      }

      for (auto itr_left = range_left.first; itr_left != range_left.second;
           ++itr_left)
      {
        hook_chain::splice(++trgitrright,
                           itr_left->second.get().get_list_iterator());
        trgitrright = itr_left->second.get().get_iterator();
      }
    }
    else
      hook_chain::swap(T::at(left).get().get_list_iterator(),
                       T::at(right).get().get_list_iterator());
  }

  template <typename T>
  template <typename K1, typename K2>
  void helpers::regular_hook_map_base<T>::splice(const K1& newpos,
                                                 const K2& oldpos)
  {
    if constexpr (utils::multi_hash_map<T>)
    {
      auto range = T::equal_range(oldpos);
      if (range.first == range.second)
        throw(std::out_of_range("hook_map: out of range splice oldpos"));
      auto newpositr = T::find(newpos);
      if (newpositr == T::end())
        throw(std::out_of_range("hook_map: out of range splice newpos"));

      for (auto itr = range.first; itr != range.second; ++itr)
        hook_chain::splice(newpositr->second.get().get_iterator(),
                           itr->second.get().get_list_iterator());
    }
    else
    {
      auto [hnewpos, holdpos] = std::make_pair(T::at(newpos), T::at(oldpos));
      hook_chain::splice(hnewpos.get_iterator(), holdpos.get_list_iterator());
    }
  }

  template <typename T>
  template <typename K>
  typename helpers::regular_unique_hook_map_base<T>::hook_reference
      helpers::regular_unique_hook_map_base<T>::operator[](const K& k)
  {
    return T::find(k)->second;
  }

  template <typename T>
  template <typename K>
  typename helpers::regular_unique_hook_map_base<T>::const_hook_reference
      helpers::regular_unique_hook_map_base<T>::operator[](const K& k) const
  {
    return T::find(k)->second;
  }

  template <typename T>
  template <typename K>
  typename helpers::regular_unique_hook_map_base<T>::hook_reference
      helpers::regular_unique_hook_map_base<T>::at(const K& k)
  {
    return T::at(k);
  }

  template <typename T>
  template <typename K>
  typename helpers::regular_unique_hook_map_base<T>::const_hook_reference
      helpers::regular_unique_hook_map_base<T>::at(const K& k) const
  {
    return T::at(k);
  }

  template <typename T>
  template <typename K>
  typename helpers::regular_hook_map_base<T>::iterator
      helpers::regular_hook_map_base<T>::find(const K& k)
  {
    return static_cast<iterator>(T::find(k));
  }

  template <typename T>
  template <typename K>
  typename helpers::regular_hook_map_base<T>::const_iterator
      helpers::regular_hook_map_base<T>::find(const K& k) const
  {
    return static_cast<const_iterator>(T::find(k));
  }

  template <typename T>
  template <typename K>
  std::pair<typename helpers::regular_hook_map_base<T>::iterator,
            typename helpers::regular_hook_map_base<T>::iterator>
      helpers::regular_hook_map_base<T>::equal_range(const K& k)
  {
    return static_cast<std::pair<iterator, iterator>>(T::equal_range(k));
  }

  template <typename T>
  template <typename K>
  std::pair<typename helpers::regular_hook_map_base<T>::const_iterator,
            typename helpers::regular_hook_map_base<T>::const_iterator>
      helpers::regular_hook_map_base<T>::equal_range(const K& k) const
  {
    return static_cast<std::pair<const_iterator, const_iterator>>(
        T::equal_range(k));
  }

  template <typename T>
  helpers::concurrent_hook_map_base<T>&
      helpers::concurrent_hook_map_base<T>::operator=(
          const concurrent_hook_map_base& other)
  {
    if (this != &other)
    {
      std::shared_lock lock1{ other.map_lock };
      std::unique_lock lock2{ map_lock };
      base::operator=(other);
    }
    return *this;
  }

  template <typename T>
  helpers::concurrent_hook_map_base<T>&
      helpers::concurrent_hook_map_base<T>::operator=(
          concurrent_hook_map_base&& other)
  {
    if (this != &other)
    {
      std::unique_lock lock1{ other.map_lock };
      std::unique_lock lock2{ map_lock };
      base::operator=(std::move(other));
    }
    return *this;
  }

  template <typename T>
  bool helpers::concurrent_hook_map_base<T>::empty() const noexcept
  {
    std::shared_lock lock{ map_lock };
    return base::empty();
  }

  template <typename T>
  bool helpers::concurrent_hook_map_base<T>::empty_enabled() const noexcept
  {
    std::shared_lock lock{ map_lock };
    return base::empty_enabled();
  }

  template <typename T>
  bool helpers::concurrent_hook_map_base<T>::empty_disabled() const noexcept
  {
    std::shared_lock lock{ map_lock };
    return base::empty_disabled();
  }

  template <typename T>
  size_t helpers::concurrent_hook_map_base<T>::enabled_size() const noexcept
  {
    std::shared_lock lock{ map_lock };
    return base::enabled_size();
  }

  template <typename T>
  size_t helpers::concurrent_hook_map_base<T>::disabled_size() const noexcept
  {
    std::shared_lock lock{ map_lock };
    return base::disabled_size();
  }

  template <typename T>
  std::byte* helpers::concurrent_hook_map_base<T>::get_target() const noexcept
  {
    std::shared_lock lock{ map_lock };
    return base::get_target();
  }

  template <typename T>
  helpers::concurrent_hook_map_base<T>::operator bool() const noexcept
  {
    return !empty();
  }

  template <typename T>
  template <typename trg>
  void helpers::concurrent_hook_map_base<T>::set_target(trg&& target)
  {
    std::unique_lock lock{ map_lock };
    base::set_target(std::forward<trg>(target));
  }

  template <typename T>
  void helpers::concurrent_hook_map_base<T>::disable_all()
  {
    std::unique_lock lock{ map_lock };
    base::disable_all();
  }

  template <typename T>
  void helpers::concurrent_hook_map_base<T>::enable_all()
  {
    std::unique_lock lock{ map_lock };
    base::enable_all();
  }

  template <typename T>
  void helpers::concurrent_hook_map_base<T>::swap(
      concurrent_hook_map_base& other)
  {
    std::unique_lock lock1{ other.map_lock };
    std::unique_lock lock2{ map_lock };
    base::swap(other);
  }

  template <typename T>
  void helpers::concurrent_hook_map_base<T>::merge(
      concurrent_hook_map_base& other)
  {
    std::unique_lock lock1{ other.map_lock };
    std::unique_lock lock2{ map_lock };
    base::merge(other);
  }

  template <typename T>
  void helpers::concurrent_hook_map_base<T>::clear()
  {
    std::unique_lock lock{ map_lock };
    base::clear();
  }

  template <typename T>
  template <typename K, typename callable>
  size_t helpers::custom_concurrent_hook_map_base<T>::visit(const K&   k,
                                                            callable&& func)
  {
    return T::visit(
        k, [&](auto& pair)
        { return func(std::make_pair(std::cref(pair.first), pair.second)); });
  }

  template <typename T>
  template <typename K, typename callable>
  size_t
      helpers::custom_concurrent_hook_map_base<T>::visit(const K&   k,
                                                         callable&& func) const
  {
    return T::visit(k,
                    [&](const auto& pair)
                    {
                      return func(std::make_pair(std::cref(pair.first),
                                                 std::cref(pair.second)));
                    });
  }

  template <typename T>
  template <typename K, typename callable>
  size_t
      helpers::custom_concurrent_hook_map_base<T>::cvisit(const K&   k,
                                                          callable&& func) const
  {
    return visit(k, std::forward<callable>(func));
  }

  template <typename T>
  template <typename callable>
  size_t helpers::custom_concurrent_hook_map_base<T>::visit_all(callable&& func)
  {
    return T::visit_all(
        [&](auto& pair)
        { return func(std::make_pair(std::cref(pair.first), pair.second)); });
  }

  template <typename T>
  template <typename callable>
  size_t helpers::custom_concurrent_hook_map_base<T>::visit_all(
      callable&& func) const
  {
    return T::visit_all(
        [&](const auto& pair)
        {
          return func(
              std::make_pair(std::cref(pair.first), std::cref(pair.second)));
        });
  }

  template <typename T>
  template <typename callable>
  size_t helpers::custom_concurrent_hook_map_base<T>::cvisit_all(
      callable&& func) const
  {
    return visit_all(std::forward<callable>(func));
  }

  template <typename T>
  template <typename execution_policy, typename callable>
  void helpers::custom_concurrent_hook_map_base<T>::visit_all(
      execution_policy&& policy, callable&& func)
  {
    T::visit_all(
        std::forward<execution_policy>(policy), [&](auto& pair)
        { return func(std::make_pair(std::cref(pair.first), pair.second)); });
  }

  template <typename T>
  template <typename execution_policy, typename callable>
  void helpers::custom_concurrent_hook_map_base<T>::visit_all(
      execution_policy&& policy, callable&& func) const
  {
    T::visit_all(std::forward<execution_policy>(policy),
                 [&](const auto& pair)
                 {
                   return func(std::make_pair(std::cref(pair.first),
                                              std::cref(pair.second)));
                 });
  }

  template <typename T>
  template <typename execution_policy, typename callable>
  void helpers::custom_concurrent_hook_map_base<T>::cvisit_all(
      execution_policy&& policy, callable&& func) const
  {
    visit_all(std::forward<execution_policy>(policy),
              std::forward<callable>(func));
  }

  template <typename T>
  template <__alterhook_is_key_detour_and_original_impl(K, dtr, orig)>
  bool helpers::custom_concurrent_hook_map_base<T>::insert(K&& k, dtr&& detour,
                                                           orig&    original,
                                                           transfer to)
  {
    std::unique_lock lock{ base::map_lock };
    if (T::count(k))
      return false;
    list_iterator pos =
        to == transfer::enabled ? hook_chain::eend() : hook_chain::dend();
    hook& h = hook_chain::insert(pos, std::forward<dtr>(detour), original, to);
    return T::emplace(std::forward<K>(k), std::ref(h));
  }

  template <typename T>
  template <typename callable,
            __alterhook_is_key_detour_and_original_impl(K, dtr, orig)>
  bool helpers::custom_concurrent_hook_map_base<T>::insert_or_visit(
      K&& k, dtr&& detour, orig& original, callable&& func, transfer to)
  {
    std::unique_lock lock{ base::map_lock };
    if (T::visit(k,
                 [&](auto& pair) {
                   return func(
                       std::make_pair(std::cref(pair.first), pair.second));
                 }))
      return false;
    list_iterator pos =
        to == transfer::enabled ? hook_chain::eend() : hook_chain::dend();
    hook& h = hook_chain::insert(pos, std::forward<dtr>(detour), original, to);
    return T::emplace(std::forward<K>(k), std::ref(h));
  }

  template <typename T>
  template <typename callable,
            __alterhook_is_key_detour_and_original_impl(K, dtr, orig)>
  bool helpers::custom_concurrent_hook_map_base<T>::insert_or_cvisit(
      K&& k, dtr&& detour, orig& original, callable&& func, transfer to)
  {
    std::unique_lock lock{ base::map_lock };
    if (T::cvisit(k,
                  [&](const auto& pair)
                  {
                    return func(std::make_pair(std::cref(pair.first),
                                               std::cref(pair.second)));
                  }))
      return false;
    list_iterator pos =
        to == transfer::enabled ? hook_chain::eend() : hook_chain::dend();
    hook& h = hook_chain::insert(pos, std::forward<dtr>(detour), original, to);
    return T::emplace(std::forward<K>(k), std::ref(h));
  }

  template <typename T>
  template <typename K>
  void helpers::custom_concurrent_hook_map_base<T>::splice(const K& newpos,
                                                           const K& oldpos)
  {
    hook*            phnew = nullptr;
    hook*            phold = nullptr;
    std::unique_lock lock{ base::map_lock };
    if (!T::visit(newpos, [&](auto& pair) { phnew = &pair.second.get(); }))
      throw(std::out_of_range("hook_map: out of range splice newpos"));
    if (!T::visit(oldpos, [&](auto& pair) { phold = &pair.second.get(); }))
      throw(std::out_of_range("hook_map: out of range splice oldpos"));
    hook_chain::splice(phnew->get_iterator(), phold->get_list_iterator());
  }

  template <typename T>
  template <typename K>
  typename helpers::custom_concurrent_hook_map_base<T>::size_type
      helpers::custom_concurrent_hook_map_base<T>::erase(const K& k)
  {
    return T::erase_if(k,
                       [&](auto& pair)
                       {
                         std::unique_lock lock{ base::map_lock };
                         hook_chain::erase(
                             pair.second.get().get_list_iterator());
                         return true;
                       });
  }

  template <typename T>
  template <typename K, typename callable>
  typename helpers::custom_concurrent_hook_map_base<T>::size_type
      helpers::custom_concurrent_hook_map_base<T>::erase_if(const K&   k,
                                                            callable&& func)
  {
    return T::erase_if(
        k,
        [&](auto& pair)
        {
          if (!func(std::make_pair(std::cref(pair.first), pair.second)))
            return false;
          std::unique_lock lock{ base::map_lock };
          hook_chain::erase(pair.second.get().get_list_iterator());
          return true;
        });
  }

  template <typename T>
  template <typename callable>
  typename helpers::custom_concurrent_hook_map_base<T>::size_type
      helpers::custom_concurrent_hook_map_base<T>::erase_if(callable&& func)
  {
    return T::erase_if(
        [&](auto& pair)
        {
          if (!func(std::make_pair(std::cref(pair.first), pair.second)))
            return false;
          std::unique_lock lock{ base::map_lock };
          hook_chain::erase(pair.second.get().get_list_iterator());
          return true;
        });
  }

  template <typename T>
  template <typename execution_policy, typename callable>
  typename helpers::custom_concurrent_hook_map_base<T>::size_type
      helpers::custom_concurrent_hook_map_base<T>::erase_if(
          execution_policy&& policy, callable&& func)
  {
    return T::erase_if(
        std::forward<execution_policy>(policy),
        [&](auto& pair)
        {
          if (!func(std::make_pair(std::cref(pair.first), pair.second)))
            return false;
          std::unique_lock lock{ base::map_lock };
          hook_chain::erase(pair.second.get().get_list_iterator());
          return true;
        });
  }

  template <typename T>
  template <typename K, typename callable>
  size_t helpers::default_concurrent_hook_map_base<T>::visit(const K&   k,
                                                             callable&& func)
  {
    std::unique_lock lock{ base::map_lock };

    if constexpr (utils::multi_hash_map<T>)
    {
      auto   range   = T::equal_range(k);
      size_t counter = 0;

      for (auto itr = range.first; itr != range.second; ++itr, ++counter)
        func(std::make_pair(std::cref(itr->first), itr->second));
      return counter;
    }
    else
    {
      auto result = T::find(k);
      if (result == T::end())
        return 0;

      func(std::make_pair(std::cref(result->first), result->second));
      return 1;
    }
  }

  template <typename T>
  template <typename K, typename callable>
  size_t
      helpers::default_concurrent_hook_map_base<T>::visit(const K&   k,
                                                          callable&& func) const
  {
    std::shared_lock lock{ base::map_lock };

    if constexpr (utils::multi_hash_map<T>)
    {
      auto   range   = T::equal_range(k);
      size_t counter = 0;

      for (auto itr = range.first; itr != range.second; ++itr, ++counter)
        func(std::make_pair(std::cref(itr->first), std::cref(itr->second)));
      return counter;
    }
    else
    {
      auto result = T::find(k);
      if (result == T::end())
        return 0;

      func(std::make_pair(std::cref(result->first), std::cref(result->second)));
      return 1;
    }
  }

  template <typename T>
  template <typename K, typename callable>
  size_t helpers::default_concurrent_hook_map_base<T>::cvisit(
      const K& k, callable&& func) const
  {
    return visit(k, std::forward<callable>(func));
  }

  template <typename T>
  template <typename callable>
  size_t
      helpers::default_concurrent_hook_map_base<T>::visit_all(callable&& func)
  {
    std::unique_lock lock{ base::map_lock };

    for (auto itr = T::begin(), itrend = T::end(); itr != itrend; ++itr)
      func(std::make_pair(std::cref(itr->first), itr->second));
    return T::size();
  }

  template <typename T>
  template <typename callable>
  size_t helpers::default_concurrent_hook_map_base<T>::visit_all(
      callable&& func) const
  {
    std::shared_lock lock{ base::map_lock };

    for (auto itr = T::begin(), itrend = T::end(); itr != itrend; ++itr)
      func(std::make_pair(std::cref(itr->first), std::cref(itr->second)));
    return T::size();
  }

  template <typename T>
  template <typename callable>
  size_t helpers::default_concurrent_hook_map_base<T>::cvisit_all(
      callable&& func) const
  {
    return visit_all(std::forward<callable>(func));
  }

  template <typename T>
  template <typename K1, typename K2>
  void helpers::default_concurrent_hook_map_base<T>::splice(const K1& newpos,
                                                            const K2& oldpos)
  {
    std::unique_lock lock{ base::map_lock };

    if constexpr (utils::multi_hash_map<T>)
    {
      auto range = T::equal_range(oldpos);
      if (range.first == range.second)
        throw(std::out_of_range("hook_map: out of range splice oldpos"));
      auto newpositr = T::find(newpos);
      if (newpositr == T::end())
        throw(std::out_of_range("hook_map: out of range splice newpos"));

      for (auto itr = range.first; itr != range.second; ++itr)
        hook_chain::splice(newpositr->second.get().get_iterator(),
                           itr->second.get().get_list_iterator());
    }
    else
    {
      auto [hnewpos, holdpos] = std::make_pair(T::at(newpos), T::at(oldpos));
      hook_chain::splice(hnewpos.get_iterator(), holdpos.get_list_iterator());
    }
  }

  template <typename T>
  template <typename K1, typename K2>
  void helpers::default_concurrent_hook_map_base<T>::swap(const K1& left,
                                                          const K2& right)
  {
    std::unique_lock lock{ base::map_lock };

    if constexpr (utils::multi_hash_map<T>)
    {
      auto range_left = T::equal_range(left);
      if (range_left.first == range_left.second)
        throw(std::out_of_range("hook_map: out of range swap left operand"));
      auto range_right = T::equal_range(right);
      if (range_right.first == range_right.second)
        throw(std::out_of_range("hook_map: out of range swap right operand"));
      hook_chain::swap(range_left.first->second.get().get_list_iterator(),
                       range_right.first->second.get().get_list_iterator());

      auto [trgitrleft, trgitrright] =
          std::pair(range_right.first->second.get().get_iterator(),
                    range_left.first->second.get().get_iterator());

      ++range_right.first;
      ++range_left.first;

      for (auto itr_right = range_right.first; itr_right != range_right.second;
           ++itr_right)
      {
        hook_chain::splice(++trgitrleft,
                           itr_right->second.get().get_list_iterator());
        trgitrleft = itr_right->second.get().get_iterator();
      }

      for (auto itr_left = range_left.first; itr_left != range_left.second;
           ++itr_left)
      {
        hook_chain::splice(++trgitrright,
                           itr_left->second.get().get_list_iterator());
        trgitrright = itr_left->second.get().get_iterator();
      }
    }
    else
      hook_chain::swap(T::at(left).get().get_list_iterator(),
                       T::at(right).get().get_list_iterator());
  }

  template <typename T>
  template <__alterhook_is_key_detour_and_original_impl(K, dtr, orig)>
  bool helpers::default_concurrent_hook_map_base<T>::insert(K&& k, dtr&& detour,
                                                            orig&    original,
                                                            transfer to)
  {
    std::unique_lock lock{ base::map_lock };

    if constexpr (!utils::multi_hash_map<T>)
    {
      if (T::count(k))
        return false;
    }

    list_iterator pos =
        to == transfer::enabled ? hook_chain::eend() : hook_chain::dend();
    hook& h = hook_chain::insert(pos, std::forward<dtr>(detour), original, to);
    T::emplace(std::forward<K>(k), std::ref(h));
    return true;
  }

  template <typename T>
  template <typename K>
  typename helpers::default_concurrent_hook_map_base<T>::size_type
      helpers::default_concurrent_hook_map_base<T>::erase(const K& k)
  {
    std::unique_lock lock{ base::map_lock };

    if constexpr (utils::multi_hash_map<T>)
    {
      auto   range   = T::equal_range(k);
      size_t counter = 0;

      while (range.first != range.second)
      {
        hook_chain::erase(range.first->second.get().get_list_iterator());
        range.first = T::erase(range.first);
        ++counter;
      }
      return counter;
    }
    else
    {
      auto result = T::find(k);
      if (result != T::end())
      {
        hook_chain::erase(result->second.get().get_list_iterator());
        T::erase(result);
        return 1;
      }
      return 0;
    }
  }

  template <typename T>
  template <typename K, typename callable>
  typename helpers::default_concurrent_hook_map_base<T>::size_type
      helpers::default_concurrent_hook_map_base<T>::erase_if(const K&   k,
                                                             callable&& func)
  {
    std::unique_lock lock{ base::map_lock };

    if constexpr (utils::multi_hash_map<T>)
    {
      auto   range   = T::equal_range(k);
      size_t counter = 0;

      while (range.first != range.second)
      {
        if (!func(std::make_pair(std::cref(range.first->first),
                                 range.first->second)))
        {
          ++range.first;
          continue;
        }

        hook_chain::erase(range.first->second.get().get_list_iterator());
        range.first = T::erase(range.first);
        ++counter;
      }
      return counter;
    }
    else
    {
      auto result = T::find(k);
      if (result == T::end())
        return 0;

      hook_chain::erase(result->second.get().get_list_iterator());
      T::erase(result);
      return 1;
    }
  }

  template <typename T>
  template <typename callable>
  typename helpers::default_concurrent_hook_map_base<T>::size_type
      helpers::default_concurrent_hook_map_base<T>::erase_if(callable&& func)
  {
    std::unique_lock lock{ base::map_lock };

    for (auto itr = T::begin(), itrend = T::end(); itr != itrend;)
    {
      if (!func(std::make_pair(std::cref(itr->first), itr->second)))
      {
        ++itr;
        continue;
      }

      hook_chain::erase(itr->second.get().get_list_iterator());
      itr = T::erase(itr);
    }
  }

  template <typename T>
  template <typename K>
  typename helpers::default_concurrent_hook_map_base<T>::size_type
      helpers::default_concurrent_hook_map_base<T>::count(const K& k) const
  {
    std::shared_lock lock{ base::map_lock };
    return T::count(k);
  }

  template <typename T>
  typename helpers::default_concurrent_hook_map_base<T>::size_type
      helpers::default_concurrent_hook_map_base<T>::bucket_count()
          const noexcept
  {
    std::shared_lock lock{ base::map_lock };
    return T::bucket_count();
  }

  template <typename T>
  float
      helpers::default_concurrent_hook_map_base<T>::load_factor() const noexcept
  {
    std::shared_lock lock{ base::map_lock };
    return T::load_factor();
  }

  template <typename T>
  float helpers::default_concurrent_hook_map_base<T>::max_load_factor()
      const noexcept
  {
    std::shared_lock lock{ base::map_lock };
    return T::max_load_factor();
  }

  template <typename T>
  void helpers::default_concurrent_hook_map_base<T>::max_load_factor(float z)
  {
    std::unique_lock lock{ base::map_lock };
    T::max_load_factor(z);
  }

  template <typename T>
  void helpers::default_concurrent_hook_map_base<T>::rehash(size_type n)
  {
    std::unique_lock lock{ base::map_lock };
    T::rehash(n);
  }

  template <typename T>
  void helpers::default_concurrent_hook_map_base<T>::reserve(size_type n)
  {
    std::unique_lock lock{ base::map_lock };
    T::reserve(n);
  }

  template <typename T>
  template <typename callable,
            __alterhook_is_key_detour_and_original_impl(K, dtr, orig)>
  bool helpers::default_unique_concurrent_hook_map_base<T>::insert_or_visit(
      K&& k, dtr&& detour, orig& original, callable&& func, transfer to)
  {
    std::unique_lock lock{ base::map_lock };
    auto             result = T::find(k);
    if (result != T::end())
    {
      func(std::make_pair(std::cref(result->first), result->second));
      return false;
    }

    list_iterator pos =
        to == transfer::enabled ? hook_chain::eend() : hook_chain::dend();
    hook& h = hook_chain::insert(pos, std::forward<dtr>(detour), original, to);
    T::emplace(std::forward<K>(k), std::ref(h));
    return true;
  }

  template <typename T>
  template <typename callable,
            __alterhook_is_key_detour_and_original_impl(K, dtr, orig)>
  bool helpers::default_unique_concurrent_hook_map_base<T>::insert_or_cvisit(
      K&& k, dtr&& detour, orig& original, callable&& func, transfer to)
  {
    std::unique_lock lock{ base::map_lock };
    auto             result = T::find(k);
    if (result != T::end())
    {
      func(std::make_pair(std::cref(result->first), std::cref(result->second)));
      return false;
    }

    list_iterator pos =
        to == transfer::enabled ? hook_chain::eend() : hook_chain::dend();
    hook& h = hook_chain::insert(pos, std::forward<dtr>(detour), original, to);
    T::emplace(std::forward<K>(k), std::ref(h));
    return true;
  }

  /*
   * NON-TEMPLATE DEFINITIONS (ignore them)
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
