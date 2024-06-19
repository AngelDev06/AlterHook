/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include "hook_chain.h"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4251 4715)
#elif utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wreturn-type"
  #pragma clang diagnostic ignored "-Wunused-parameter"
  #pragma clang diagnostic ignored "-Wcomma"
#endif

namespace alterhook
{
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
    typedef T                                adapted;
    typedef hook_chain                       base;
    typedef typename base::iterator          chain_iterator;
    typedef typename base::const_iterator    const_chain_iterator;
    typedef typename hook_chain::hook&       hook_reference;
    typedef const typename hook_chain::hook& const_hook_reference;
    typedef std::pair<const typename adapted::key_type&,
                      typename hook_chain::hook&>
        reference;
    typedef std::pair<const typename adapted::key_type&,
                      const typename hook_chain::hook&>
        const_reference;

    using typename adapted::allocator_type;
    using typename adapted::const_pointer;
    using typename adapted::difference_type;
    using typename adapted::hasher;
    using typename adapted::key_equal;
    using typename adapted::key_type;
    using typename adapted::mapped_type;
    using typename adapted::pointer;
    using typename adapted::size_type;
    using typename adapted::value_type;
    using typename base::const_list_iterator;
    using typename base::const_reverse_list_iterator;
    using typename base::hook;
    using typename base::include;
    using typename base::list_iterator;
    using typename base::reverse_list_iterator;
    using transfer = base::transfer;

    using adapted::adapted;

    hook_map_base(std::byte* target);

    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    hook_map_base(trg&& target);

    template <typename key, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<key, dtr, orig&, types...>>>
    hook_map_base(std::byte* target, key&& first_key, dtr&& detour,
                  orig& original, types&&... rest);

    template <typename trg, typename key, typename dtr, typename orig,
              typename... types,
              typename = std::enable_if_t<
                  utils::callable_type<trg> &&
                  utils::keys_detours_and_originals<key, dtr, orig&, types...>>>
    hook_map_base(trg&& target, key&& first_key, dtr&& detour, orig& original,
                  types&&... rest);

    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    hook_map_base(std::byte* target, tuple&& first, types&&... rest);

    template <typename trg, typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    hook_map_base(trg&& target, tuple&& first, types&&... rest);

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
    using adapted::get_allocator;
    using adapted::max_size;
    using adapted::size;

    // setters
    using base::set_target;

    // lookup
    using adapted::count;

    // status update
    using base::disable_all;
    using base::enable_all;

    // modifiers
    using base::swap;
    void clear();
    void swap(hook_map_base& other);
    void merge(hook_map_base& other);

    // bucket interface
    using adapted::bucket_count;

    // hash policy
    using adapted::load_factor;
    using adapted::max_load_factor;
    using adapted::rehash;
    using adapted::reserve;

    // observers
    using adapted::hash_function;
    using adapted::key_eq;

    bool operator==(const hook_map_base& other) const noexcept;
    bool operator!=(const hook_map_base& other) const noexcept;

  protected:
    template <typename K, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&, types...>>>
    auto insert(transfer trg, K&& key, dtr&& detour, orig& original,
                types&&... rest);
    template <typename K, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&, types...>>>
    auto insert(K&& key, dtr&& detour, orig& original, types&&... rest);
    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    auto insert(transfer trg, tuple&& first, types&&... rest);
    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    auto insert(tuple&& first, types&&... rest);

  private:
    void swap(hook_chain&)                         = delete;
    void swap(list_iterator, base&, list_iterator) = delete;

    template <size_t... k_indexes, size_t... d_indexes, size_t... o_indexes,
              typename... types>
    hook_map_base(std::byte* target, std::index_sequence<k_indexes...>,
                  std::index_sequence<d_indexes...>,
                  std::index_sequence<o_indexes...>,
                  std::tuple<types...>&& args);
    template <size_t... k_indexes, size_t... d_indexes, size_t... o_indexes,
              typename... types>
    auto insert_impl(transfer to, std::index_sequence<k_indexes...>,
                     std::index_sequence<d_indexes...>,
                     std::index_sequence<o_indexes...>,
                     std::tuple<types...>&& args);
    template <typename... keys, typename... detours, typename... originals,
              size_t... indexes>
    auto insert_impl(transfer to, std::index_sequence<indexes...>,
                     std::tuple<std::tuple<keys...>, std::tuple<detours...>,
                                std::tuple<originals...>>&& args);
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
    template <typename K, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&, types...>>>
    auto insert(transfer trg, K&& key, dtr&& detour, orig& original,
                types&&... rest);

    template <typename K, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&, types...>>>
    auto insert(K&& key, dtr&& detour, orig& original, types&&... rest);

    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    auto insert(transfer trg, tuple&& first, types&&... rest);

    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    auto insert(tuple&& first, types&&... rest);

    iterator erase(const_iterator pos);
    iterator erase(const_iterator first, const_iterator last);
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

    concurrent_hook_map_base(concurrent_hook_map_base&& other) noexcept
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
    explicit   operator bool() const noexcept;

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

    bool operator==(const concurrent_hook_map_base& other) const noexcept;
    bool operator!=(const concurrent_hook_map_base& other) const noexcept;

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

    template <typename K, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&, types...>>>
    auto insert(transfer trg, K&& key, dtr&& detour, orig& original,
                types&&... rest);
    template <typename K, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&, types...>>>
    auto insert(K&& key, dtr&& detour, orig& original, types&&... rest);
    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    auto insert(transfer trg, tuple&& first, types&&... rest);
    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    auto insert(tuple&& first, types&&... rest);
    template <typename callable, typename K, typename dtr, typename orig,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&>>>
    bool insert_or_visit(K&& k, dtr&& detour, orig& original, callable&& func,
                         transfer to = transfer::enabled);
    template <typename callable, typename K, typename dtr, typename orig,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&>>>
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

    template <typename K, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&, types...>>>
    auto insert(transfer trg, K&& key, dtr&& detour, orig& original,
                types&&... rest);
    template <typename K, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&, types...>>>
    auto insert(K&& key, dtr&& detour, orig& original, types&&... rest);
    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    auto insert(transfer trg, tuple&& first, types&&... rest);
    template <typename tuple, typename... types,
              typename = std::enable_if_t<
                  utils::key_detour_and_original_triplets<tuple, types...>>>
    auto insert(tuple&& first, types&&... rest);
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

    template <typename callable, typename K, typename dtr, typename orig,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&>>>
    bool insert_or_visit(K&& k, dtr&& detour, orig& original, callable&& func,
                         transfer to = transfer::enabled);
    template <typename callable, typename K, typename dtr, typename orig,
              typename = std::enable_if_t<
                  utils::keys_detours_and_originals<K, dtr, orig&>>>
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

    template <typename iseq, typename... types>
    struct get_all_keys_impl2;

    template <size_t... indexes, typename... types>
    struct get_all_keys_impl2<std::index_sequence<indexes...>, types...>
    {
      typedef utils::type_sequence<utils::type_at_t<indexes, types...>...> type;
    };

    template <typename tseq, typename = void>
    struct get_all_keys_impl;

    template <typename key, typename dtr, typename orig, typename... types>
    struct get_all_keys_impl<utils::type_sequence<key, dtr, orig, types...>,
                             std::enable_if_t<utils::keys_detours_and_originals<
                                 key, dtr, orig, types...>>>
        : get_all_keys_impl2<
              utils::make_index_sequence_with_step<sizeof...(types) + 3, 0, 3>,
              key, dtr, orig, types...>
    {
    };

    template <typename tuple, typename... types>
    struct get_all_keys_impl<
        utils::type_sequence<tuple, types...>,
        std::enable_if_t<
            utils::key_detour_and_original_triplets<tuple, types...>>>
    {
      typedef utils::type_sequence<
          std::tuple_element_t<0, utils::remove_cvref_t<tuple>>,
          std::tuple_element_t<0, utils::remove_cvref_t<types>>...>
          type;
    };

    template <typename... types>
    using get_all_keys =
        typename get_all_keys_impl<utils::type_sequence<types...>>::type;
  } // namespace helpers

  template <typename trg, typename... types>
  hook_map(trg, types&&...) -> hook_map<typename helpers::get_all_keys<
      types...>::template to<std::common_type_t>>;

  /*
   * TEMPLATE DEFINITIONS (ignore them)
   */
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

    (adapted::emplace(
         std::forward<std::tuple_element_t<k_indexes, std::tuple<types...>>>(
             std::get<k_indexes>(args)),
         std::ref(*(itr++))),
     ...);
  }

  template <typename T>
  template <size_t... k_indexes, size_t... d_indexes, size_t... o_indexes,
            typename... types>
  auto helpers::hook_map_base<T>::insert_impl(transfer trg,
                                              std::index_sequence<k_indexes...>,
                                              std::index_sequence<d_indexes...>,
                                              std::index_sequence<o_indexes...>,
                                              std::tuple<types...>&& args)
  {
    return insert_impl(
        trg, std::make_index_sequence<sizeof...(d_indexes)>(),
        std::tuple(
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<k_indexes, std::tuple<types...>>>(
                    std::get<k_indexes>(args))...),
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<d_indexes, std::tuple<types...>>>(
                    std::get<d_indexes>(args))...),
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<o_indexes, std::tuple<types...>>>(
                    std::get<o_indexes>(args))...)));
  }

  template <typename T>
  template <typename... keys, typename... detours, typename... originals,
            size_t... indexes>
  auto helpers::hook_map_base<T>::insert_impl(
      transfer trg, std::index_sequence<indexes...>,
      std::tuple<std::tuple<keys...>, std::tuple<detours...>,
                 std::tuple<originals...>>&& args)
  {
    const bool enable_hook = trg == transfer::enabled;

    if constexpr (utils::multi_hash_map<T>)
    {
      auto [itr, enditr] = base::append(
          trg, std::forward_as_tuple(
                   std::forward<detours>(std::get<indexes>(std::get<1>(args))),
                   std::forward<originals>(
                       std::get<indexes>(std::get<2>(args))))...);

      if constexpr (sizeof...(keys) == 1)
      {
        try
        {
          return T::emplace(
              std::forward<std::tuple_element_t<0, std::tuple<keys...>>>(
                  std::get<0>(std::get<0>(args))),
              std::ref(*itr));
        }
        catch (...)
        {
          base::pop_back(trg);
          throw;
        }
      }
      else
      {
        try
        {
          (T::emplace(std::forward<keys>(std::get<indexes>(std::get<0>(args))),
                      std::ref(*(itr++))),
           ...);
        }
        catch (...)
        {
          base::erase(itr, enditr);
          throw;
        }
        return sizeof...(keys);
      }
    }
    else if constexpr (utils::regular_hash_map<T>)
    {
      if constexpr (sizeof...(keys) == 1)
      {
        auto [result, status] = T::try_emplace(
            std::forward<std::tuple_element_t<0, std::tuple<keys...>>>(
                std::get<0>(std::get<0>(args))),
            base::empty_ref_wrap());
        if (!status)
          return std::pair(result, status);
        try
        {
          base::push_back(
              std::forward<std::tuple_element_t<0, std::tuple<detours...>>>(
                  std::get<0>(std::get<1>(args))),
              std::get<0>(std::get<2>(args)), enable_hook);
        }
        catch (...)
        {
          T::erase(result);
          throw;
        }
        result->second = std::ref(enable_hook ? base::eback() : base::dback());
        return std::pair(result, status);
      }
      else
      {
        utils::static_vector<hook_init_item, sizeof...(keys)>       tba_hooks{};
        utils::static_vector<typename T::iterator, sizeof...(keys)> sources{};

        auto inserter = [&, trg](auto&& key, auto&& detour, auto& original)
        {
          typedef decltype(key)      key_t;
          typedef decltype(detour)   detour_t;
          typedef decltype(original) original_t;
          auto [result, status] =
              T::try_emplace(std::forward<key_t>(key), base::empty_ref_wrap());
          if (!status)
            return;
          tba_hooks.emplace_back(
              get_target_address<original_t>(std::forward<detour_t>(detour)),
              helpers::original_wrapper(original));
          sources.push_back(result);
        };

        try
        {
          (inserter(std::forward<keys>(std::get<indexes>(std::get<0>(args))),
                    std::forward<detours>(std::get<indexes>(std::get<1>(args))),
                    std::get<indexes>(std::get<2>(args))),
           ...);
          base::append_list(trg,
                            { tba_hooks.raw_begin(), tba_hooks.raw_end() });
        }
        catch (...)
        {
          for (auto itr : sources)
            T::erase(itr);
          throw;
        }

        list_iterator hitr = enable_hook ? base::eend() : base::dend();
        for (size_t i = sources.size(); i != 0; --i)
          sources[i - 1]->second = std::ref(*(--hitr));
        return sources.size();
      }
    }
    else
    {
      if constexpr (sizeof...(keys) == 1)
      {
        base::push_back(
            std::forward<std::tuple_element_t<0, std::tuple<detours...>>>(
                std::get<0>(std::get<1>(args))),
            std::get<0>(std::get<2>(args)), enable_hook);

        try
        {
          return T::try_emplace_or_cvisit(
              std::forward<std::tuple_element_t<0, std::tuple<keys...>>>(
                  std::get<0>(std::get<0>(args))),
              std::ref(enable_hook ? base::eback() : base::dback()),
              [&, trg](const auto&) { base::pop_back(trg); });
        }
        catch (...)
        {
          base::pop_back(trg);
          throw;
        }
      }
      else
      {
        size_t count    = 0;
        auto   inserter = [this, &count, enable_hook](auto&& key, auto&& detour,
                                                    auto& original)
        {
          typedef decltype(key)      key_t;
          typedef decltype(detour)   detour_t;
          typedef decltype(original) original_t;
          base::push_back(std::forward<detour_t>(detour), original,
                          enable_hook);
          bool result = false;
          try
          {
            result = T::try_emplace(
                std::forward<key_t>(key),
                std::ref(enable_hook ? base::eback() : base::dback()));
          }
          catch (...)
          {
            base::pop_back(static_cast<transfer>(enable_hook));
            throw;
          }

          if (!result)
            base::pop_back(static_cast<transfer>(enable_hook));
          else
            ++count;
        };

        (inserter(std::forward<keys>(std::get<indexes>(std::get<0>(args))),
                  std::forward<detours>(std::get<indexes>(std::get<1>(args))),
                  std::get<indexes>(std::get<2>(args))),
         ...);
        return count;
      }
    }
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(std::byte* target) : base(target)
  {
  }

  template <typename T>
  template <typename trg, typename>
  helpers::hook_map_base<T>::hook_map_base(trg&& target)
      : hook_map_base(get_target_address(std::forward<trg>(target)))
  {
  }

  template <typename T>
  template <typename key, typename dtr, typename orig, typename... types,
            typename>
  helpers::hook_map_base<T>::hook_map_base(std::byte* target, key&& first_key,
                                           dtr&& detour, orig& original,
                                           types&&... rest)
      : hook_map_base(
            target,
            utils::make_index_sequence_with_step<sizeof...(types) + 3, 0, 3>(),
            utils::make_index_sequence_with_step<sizeof...(types) + 3, 1, 3>(),
            utils::make_index_sequence_with_step<sizeof...(types) + 3, 2, 3>(),
            std::forward_as_tuple(std::forward<key>(first_key),
                                  std::forward<dtr>(detour), original,
                                  std::forward<types>(rest)...))
  {
  }

  template <typename T>
  template <typename trg, typename key, typename dtr, typename orig,
            typename... types, typename>
  helpers::hook_map_base<T>::hook_map_base(trg&& target, key&& first_key,
                                           dtr&& detour, orig& original,
                                           types&&... rest)
      : hook_map_base(get_target_address(std::forward<trg>(target)),
                      std::forward<key>(first_key), std::forward<dtr>(detour),
                      original, std::forward<types>(rest)...)
  {
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  helpers::hook_map_base<T>::hook_map_base(std::byte* target, tuple&& first,
                                           types&&... rest)
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
    adapted::emplace(
        std::forward<std::tuple_element_t<0, utils::remove_cvref_t<tuple>>>(
            std::get<0>(first)),
        std::ref(*(itr++)));
    (adapted::emplace(
         std::forward<std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
             std::get<0>(rest)),
         std::ref(*(itr++))),
     ...);
  }

  template <typename T>
  template <typename trg, typename tuple, typename... types, typename>
  helpers::hook_map_base<T>::hook_map_base(trg&& target, tuple&& first,
                                           types&&... rest)
      : hook_map_base(get_target_address(std::forward<trg>(target)),
                      std::forward<tuple>(first), std::forward<types>(rest)...)
  {
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(const hook_map_base& other)
      : hook_chain(other.get_target())
  {
    for (const auto& [k, v] : static_cast<const adapted&>(other))
      adapted::emplace(k, *append_hook(v));
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(const hook_map_base&  other,
                                           const allocator_type& alloc)
      : adapted(alloc), hook_chain(other.get_target())
  {
    for (const auto& [k, v] : static_cast<const adapted&>(other))
      adapted::emplace(k, *append_hook(v));
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(hook_map_base&& other) noexcept
      : adapted(std::move(other)), hook_chain(std::move(other))
  {
  }

  template <typename T>
  helpers::hook_map_base<T>::hook_map_base(hook_map_base&&       other,
                                           const allocator_type& alloc) noexcept
      : adapted(std::move(other), alloc), hook_chain(std::move(other))
  {
  }

  template <typename T>
  helpers::hook_map_base<T>&
      helpers::hook_map_base<T>::operator=(const hook_map_base& other)
  {
    if (this == &other)
      return *this;

    disable_all();
    set_trampoline(other.get_trampoline());

    if constexpr (utils::multi_hash_map<T>)
      adapted::clear();
    else
    {
      for (auto itr = adapted::begin(), enditr = adapted::end(); itr != enditr;)
      {
        if (other.adapted::count(itr->first))
          ++itr;
        else
          itr = adapted::erase(itr);
      }
    }

    if (adapted::size() >= other.adapted::size())
    {
      chain_iterator itr = base::begin();
      for (auto& [k, ref] : static_cast<const adapted&>(other))
      {
        hcopy(*itr, ref);
        if constexpr (utils::multi_hash_map<T>)
          adapted::insert({ k, std::ref(*(itr++)) });
        else
          adapted::insert_or_assign(k, std::ref(*(itr++)));
      }

      base::erase(itr, base::end());
    }
    else
    {
      typename adapted::const_iterator otheritr = other.adapted::begin();
      for (list_iterator itr = base::dbegin(), itrend = base::dend();
           itr != itrend; ++itr)
      {
        hcopy(*itr, otheritr->second);
        if constexpr (utils::multi_hash_map<T>)
          adapted::insert({ otheritr->first, std::ref(*(itr++)) });
        else
          adapted::insert_or_assign(otheritr->first, std::ref(*(itr++)));
      }

      for (typename adapted::const_iterator otherend = other.adapted::end();
           otheritr != otherend; ++otheritr)
      {
        if constexpr (utils::multi_hash_map<T>)
          adapted::insert(
              { otheritr->first, std::ref(happend(otheritr->second, false)) });
        else
          adapted::insert_or_assign(otheritr->first,
                                    std::ref(happend(otheritr->second, false)));
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
      adapted::operator=(std::move(other));
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
    adapted::clear();
  }

  template <typename T>
  void helpers::hook_map_base<T>::swap(hook_map_base& other)
  {
    base::swap(other);
    adapted::swap(other);
  }

  template <typename T>
  void helpers::hook_map_base<T>::merge(hook_map_base& other)
  {
    for (auto itr = other.adapted::begin(), itrend = other.adapted::end();
         itr != itrend; ++itr)
    {
      if (adapted::count(itr->first))
        continue;
      auto [flag, newpos] = itr->second.get().is_enabled()
                                ? std::pair(transfer::enabled, base::eend())
                                : std::pair(transfer::disabled, base::dend());
      base::splice(newpos, other, itr->second.get().get_list_iterator(), flag);
      adapted::insert(*itr);
      other.adapted::erase(itr);
    }
  }

  template <typename T>
  bool helpers::hook_map_base<T>::operator==(
      const hook_map_base& other) const noexcept
  {
    return std::equal(adapted::begin(), adapted::end(), other.adapted::begin(),
                      other.adapted::end(),
                      [](const auto& left, const auto& right)
                      {
                        return std::tie(left.first, left.second.get()) ==
                               std::tie(right.first, right.second.get());
                      });
  }

  template <typename T>
  bool helpers::hook_map_base<T>::operator!=(
      const hook_map_base& other) const noexcept
  {
    return !operator==(other);
  }

  template <typename T>
  template <typename K, typename dtr, typename orig, typename... types,
            typename>
  auto helpers::hook_map_base<T>::insert(transfer trg, K&& key, dtr&& detour,
                                         orig& original, types&&... rest)
  {
    return insert_impl(
        trg, utils::make_index_sequence_with_step<sizeof...(rest) + 3, 0, 3>(),
        utils::make_index_sequence_with_step<sizeof...(rest) + 3, 1, 3>(),
        utils::make_index_sequence_with_step<sizeof...(rest) + 3, 2, 3>(),
        std::forward_as_tuple(std::forward<K>(key), std::forward<dtr>(detour),
                              original, std::forward<types>(rest)...));
  }

  template <typename T>
  template <typename K, typename dtr, typename orig, typename... types,
            typename>
  auto helpers::hook_map_base<T>::insert(K&& key, dtr&& detour, orig& original,
                                         types&&... rest)
  {
    return insert(transfer::enabled, std::forward<K>(key),
                  std::forward<dtr>(detour), original,
                  std::forward<types>(rest)...);
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  auto helpers::hook_map_base<T>::insert(transfer trg, tuple&& first,
                                         types&&... rest)
  {
    return insert_impl(
        trg, std::make_index_sequence<sizeof...(rest) + 1>(),
        std::tuple(
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<tuple>>>(
                    std::get<0>(first)),
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
                    std::get<0>(rest))...),
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<tuple>>>(
                    std::get<1>(first)),
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<types>>>(
                    std::get<1>(rest))...),
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<2, utils::remove_cvref_t<tuple>>>(
                    std::get<2>(first)),
                std::forward<
                    std::tuple_element_t<2, utils::remove_cvref_t<types>>>(
                    std::get<2>(rest))...)));
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  auto helpers::hook_map_base<T>::insert(tuple&& first, types&&... rest)
  {
    return insert(transfer::enabled, std::forward<tuple>(first),
                  std::forward<types>(rest)...);
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
  template <typename K, typename dtr, typename orig, typename... types,
            typename>
  auto helpers::regular_hook_map_base<T>::insert(transfer trg, K&& key,
                                                 dtr&& detour, orig& original,
                                                 types&&... rest)
  {
    auto result =
        base::insert(trg, std::forward<K>(key), std::forward<dtr>(detour),
                     original, std::forward<types>(rest)...);
    if constexpr (sizeof...(rest) == 0)
      return static_cast<insert_ret_t>(result);
    else
      return result;
  }

  template <typename T>
  template <typename K, typename dtr, typename orig, typename... types,
            typename>
  auto helpers::regular_hook_map_base<T>::insert(K&& key, dtr&& detour,
                                                 orig& original,
                                                 types&&... rest)
  {
    return insert(transfer::enabled, std::forward<K>(key),
                  std::forward<dtr>(detour), original,
                  std::forward<types>(rest)...);
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  auto helpers::regular_hook_map_base<T>::insert(transfer trg, tuple&& first,
                                                 types&&... rest)
  {
    auto result = base::insert(trg, std::forward<tuple>(first),
                               std::forward<types>(rest)...);
    if constexpr (sizeof...(rest) == 0)
      return static_cast<insert_ret_t>(result);
    else
      return result;
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  auto helpers::regular_hook_map_base<T>::insert(tuple&& first, types&&... rest)
  {
    return insert(transfer::enabled, std::forward<tuple>(first),
                  std::forward<types>(rest)...);
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
  inline bool helpers::concurrent_hook_map_base<T>::operator==(
      const concurrent_hook_map_base& other) const noexcept
  {
    std::shared_lock lock{ map_lock };
    std::shared_lock lock2{ other.map_lock };
    return base::operator==(other);
  }

  template <typename T>
  inline bool helpers::concurrent_hook_map_base<T>::operator!=(
      const concurrent_hook_map_base& other) const noexcept
  {
    std::shared_lock lock{ map_lock };
    std::shared_lock lock2{ other.map_lock };
    return base::operator!=(other);
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
  template <typename K, typename dtr, typename orig, typename... types,
            typename>
  auto helpers::custom_concurrent_hook_map_base<T>::insert(
      transfer trg, K&& key, dtr&& detour, orig& original, types&&... rest)
  {
    std::unique_lock lock{ base::map_lock };
    return base::insert(trg, std::forward<K>(key), std::forward<dtr>(detour),
                        original, std::forward<types>(rest)...);
  }

  template <typename T>
  template <typename K, typename dtr, typename orig, typename... types,
            typename>
  auto helpers::custom_concurrent_hook_map_base<T>::insert(K&&   key,
                                                           dtr&& detour,
                                                           orig& original,
                                                           types&&... rest)
  {
    return insert(transfer::enabled, std::forward<K>(key),
                  std::forward<dtr>(detour), original,
                  std::forward<types>(rest)...);
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  auto helpers::custom_concurrent_hook_map_base<T>::insert(transfer trg,
                                                           tuple&&  first,
                                                           types&&... rest)
  {
    std::unique_lock lock{ base::map_lock };
    return base::insert(trg, std::forward<tuple>(first),
                        std::forward<types>(rest)...);
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  auto helpers::custom_concurrent_hook_map_base<T>::insert(tuple&& first,
                                                           types&&... rest)
  {
    return insert(transfer::enabled, std::forward<tuple>(first),
                  std::forward<types>(rest)...);
  }

  template <typename T>
  template <typename callable, typename K, typename dtr, typename orig,
            typename>
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
  template <typename callable, typename K, typename dtr, typename orig,
            typename>
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
  template <typename K, typename dtr, typename orig, typename... types,
            typename>
  auto helpers::default_concurrent_hook_map_base<T>::insert(
      transfer trg, K&& key, dtr&& detour, orig& original, types&&... rest)
  {
    std::unique_lock lock{ base::map_lock };
    auto             result =
        base::insert(trg, std::forward<K>(key), std::forward<dtr>(detour),
                     original, std::forward<types>(rest)...);

    if constexpr (sizeof...(rest) == 0)
      return result.second;
    else
      return result;
  }

  template <typename T>
  template <typename K, typename dtr, typename orig, typename... types,
            typename>
  auto helpers::default_concurrent_hook_map_base<T>::insert(K&&   key,
                                                            dtr&& detour,
                                                            orig& original,
                                                            types&&... rest)
  {
    return insert(transfer::enabled, std::forward<K>(key),
                  std::forward<dtr>(detour), original,
                  std::forward<types>(rest)...);
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  auto helpers::default_concurrent_hook_map_base<T>::insert(transfer trg,
                                                            tuple&&  first,
                                                            types&&... rest)
  {
    std::unique_lock lock{ base::map_lock };
    auto             result = base::insert(trg, std::forward<tuple>(first),
                                           std::forward<types>(rest)...);

    if constexpr (utils::multi_hash_map<T>)
      return true;
    else if constexpr (sizeof...(types) == 0)
      return result.second;
    else
      return result;
  }

  template <typename T>
  template <typename tuple, typename... types, typename>
  auto helpers::default_concurrent_hook_map_base<T>::insert(tuple&& first,
                                                            types&&... rest)
  {
    return insert(transfer::enabled, std::forward<tuple>(first),
                  std::forward<types>(rest)...);
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
    size_t           counter = 0;

    for (auto itr = T::begin(), itrend = T::end(); itr != itrend;)
    {
      if (!func(std::make_pair(std::cref(itr->first), itr->second)))
      {
        ++itr;
        continue;
      }

      hook_chain::erase(itr->second.get().get_list_iterator());
      itr = T::erase(itr);
      ++counter;
    }
    return counter;
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
  template <typename callable, typename K, typename dtr, typename orig,
            typename>
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
  template <typename callable, typename K, typename dtr, typename orig,
            typename>
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
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#elif utils_clang
  #pragma clang diagnostic pop
#endif
