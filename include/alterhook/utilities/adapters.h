/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "utils_macros.h"
#include "other.h"
#include "concepts.h"
#include <initializer_list>
#include <memory>
#include <shared_mutex>

namespace utils
{
  template <typename T>
  class concurrent_unordered_map_adapter : public T
  {
  public:
    static_assert(!concurrent_hash_map<T>,
                  "concurrent unordered map adapter instantiated with a "
                  "concurrent unordered map");

    typedef typename T::key_type        key_type;
    typedef typename T::mapped_type     mapped_type;
    typedef typename T::value_type      value_type;
    typedef typename T::hasher          hasher;
    typedef typename T::key_equal       key_equal;
    typedef typename T::allocator_type  allocator_type;
    typedef typename T::pointer         pointer;
    typedef typename T::const_pointer   const_pointer;
    typedef typename T::reference       reference;
    typedef typename T::const_reference const_reference;
    typedef typename T::size_type       size_type;
    typedef typename T::difference_type difference_type;

    using T::T;

    concurrent_unordered_map_adapter(
        const concurrent_unordered_map_adapter& other)
        : concurrent_unordered_map_adapter(other,
                                           std::shared_lock(other.map_lock))
    {
    }

    concurrent_unordered_map_adapter(concurrent_unordered_map_adapter&& other)
        : concurrent_unordered_map_adapter(std::move(other),
                                           std::unique_lock(other.map_lock))
    {
    }

    concurrent_unordered_map_adapter&
        operator=(const concurrent_unordered_map_adapter& other)
    {
      std::unique_lock lock{ map_lock };
      T::operator=(other);
      return *this;
    }

    concurrent_unordered_map_adapter&
        operator=(concurrent_unordered_map_adapter&& other) noexcept(
            noexcept(T::operator=(std::move(other))))
    {
      std::unique_lock lock{ map_lock };
      T::operator=(std::move(other));
      return *this;
    }

    concurrent_unordered_map_adapter&
        operator=(std::initializer_list<value_type> list)
    {
      std::unique_lock lock{ map_lock };
      T::operator=(list);
      return *this;
    }

    template <typename K, typename callable>
    size_t visit(const K& key, callable&& func)
    {
      std::unique_lock lock{ map_lock };
      auto             pair    = T::equal_range(key);
      size_t           counter = 0;

      for (auto itr = pair.first; itr != pair.second; ++itr, ++counter)
        func(*itr);
      return counter;
    }

    template <typename K, typename callable>
    size_t visit(const K& key, callable&& func) const
    {
      std::shared_lock lock{ map_lock };
      auto             pair    = T::equal_range(key);
      size_t           counter = 0;

      for (auto itr = pair.first; itr != pair.second; ++itr, ++counter)
        func(*itr);
      return counter;
    }

    template <typename K, typename callable>
    size_t cvisit(const K& key, callable&& func) const
    {
      return visit(key, std::forward<callable>(func));
    }

    template <typename callable>
    void visit_all(callable&& func)
    {
      std::unique_lock lock{ map_lock };
      for (auto& pair : *this)
        func(pair);
    }

    template <typename callable>
    void visit_all(callable&& func) const
    {
      std::shared_lock lock{ map_lock };
      for (const auto& pair : *this)
        func(pair);
    }

    template <typename callable>
    void cvisit_all(callable&& func) const
    {
      return visit_all(std::forward<callable>(func));
    }

    template <typename... types>
    bool emplace(types&&... args)
    {
      std::unique_lock lock{ map_lock };
      return T::emplace(std::forward<types>(args)...).second;
    }

    bool insert(const value_type& val)
    {
      std::unique_lock lock{ map_lock };
      return T::insert(val).second;
    }

    bool insert(value_type&& val)
    {
      std::unique_lock lock{ map_lock };
      return T::insert(std::move(val)).second;
    }

    template <typename itr>
    size_type insert(itr first, itr last)
    {
      std::unique_lock lock{ map_lock };
      size_t           counter = 0;
      while (first != last)
      {
        if (T::emplace(*first).second)
          ++counter;
        ++first;
      }
      return counter;
    }

    size_type insert(std::initializer_list<value_type> list)
    {
      return insert(list.begin(), list.end());
    }

    template <typename callable, typename... types>
    bool emplace_or_visit(callable&& func, types&&... args)
    {
      std::unique_lock lock{ map_lock };
      auto             pair = T::emplace(std::forward<types>(args)...);
      if (!pair.second)
        func(*pair.first);
      return pair.second;
    }

    template <typename callable>
    bool insert_or_visit(const value_type& val, callable&& func)
    {
      std::unique_lock lock{ map_lock };
      auto             pair = T::insert(val);
      if (!pair.second)
        func(*pair.first);
      return pair.second;
    }

    template <typename callable>
    bool insert_or_cvisit(const value_type& val, callable&& func)
    {
      std::unique_lock                            lock{ map_lock };
      std::pair<typename T::const_iterator, bool> pair = T::insert(val);
      if (!pair.second)
        func(*pair.first);
      return pair.second;
    }

    template <typename itr, typename callable>
    size_type insert_or_visit(itr first, itr last, callable&& func)
    {
      std::unique_lock lock{ map_lock };
      size_type        counter = 0;

      while (first != last)
      {
        auto pair = T::insert(*first);
        if (!pair.second)
          func(*pair.first);
        else
          ++counter;
        ++first;
      }
      return counter;
    }

    template <typename itr, typename callable>
    size_type insert_or_cvisit(itr first, itr last, callable&& func)
    {
      std::unique_lock lock{ map_lock };
      size_type        counter = 0;

      while (first != last)
      {
        std::pair<typename T::const_iterator, bool> pair = T::insert(*first);
        if (!pair.second)
          func(*pair.first);
        else
          ++counter;
        ++first;
      }
      return counter;
    }

    template <typename callable>
    size_type insert_or_visit(std::initializer_list<value_type> list,
                              callable&&                        func)
    {
      return insert_or_visit(list.begin(), list.end(),
                             std::forward<callable>(func));
    }

    template <typename callable>
    size_type insert_or_cvisit(std::initializer_list<value_type> list,
                               callable&&                        func)
    {
      return insert_or_cvisit(list.begin(), list.end(),
                              std::forward<callable>(func));
    }

    template <typename K, typename... types>
    bool try_emplace(K&& key, types&&... args)
    {
      std::unique_lock lock{ map_lock };
      return T::try_emplace(std::forward<K>(key), std::forward<types>(args)...)
          .second;
    }

    template <typename K, typename callable, typename... types>
    bool try_emplace_or_visit(K&& key, callable&& func, types&&... args)
    {
      std::unique_lock lock{ map_lock };
      auto             pair =
          T::try_emplace(std::forward<K>(key), std::forward<types>(args)...);
      if (!pair.second)
        func(*pair.first);
      return pair.second;
    }

    template <typename K, typename callable, typename... types>
    bool try_emplace_or_cvisit(K&& key, callable&& func, types&&... args)
    {
      std::unique_lock                            lock{ map_lock };
      std::pair<typename T::const_iterator, bool> pair =
          T::try_emplace(std::forward<K>(key), std::forward<types>(args)...);
      if (!pair.second)
        func(*pair.first);
      return pair.second;
    }

    template <typename K, typename M>
    bool insert_or_assign(K&& key, M&& obj)
    {
      std::unique_lock lock{ map_lock };
      return T::insert_or_assign(std::forward<K>(key), std::forward<M>(obj));
    }

    bool empty() const noexcept
    {
      std::shared_lock lock{ map_lock };
      return T::empty();
    }

    size_type size() const noexcept
    {
      std::shared_lock lock{ map_lock };
      return T::size();
    }

    size_type max_size() const noexcept
    {
      std::shared_lock lock{ map_lock };
      return T::max_size();
    }

    template <typename K>
    size_type count(K&& key)
    {
      std::shared_lock lock{ map_lock };
      return T::count(std::forward<K>(key));
    }

    size_type bucket_count() const noexcept
    {
      std::shared_lock lock{ map_lock };
      return T::bucket_count();
    }

    float load_factor() const noexcept
    {
      std::shared_lock lock{ map_lock };
      return T::load_factor();
    }

    float max_load_factor() const noexcept
    {
      std::shared_lock lock{ map_lock };
      return T::max_load_factor();
    }

    void max_load_factor(float z)
    {
      std::unique_lock lock{ map_lock };
      T::max_load_factor(z);
    }

    void rehash(size_type n)
    {
      std::unique_lock lock{ map_lock };
      T::rehash(n);
    }

    void reserve(size_type n)
    {
      std::unique_lock lock{ map_lock };
      T::reserve(n);
    }

    bool operator==(const concurrent_unordered_map_adapter& other)
    {
      std::shared_lock lock{ map_lock };
      return static_cast<T&>(*this) == other;
    }

    bool operator!=(const concurrent_unordered_map_adapter& other)
    {
      std::shared_lock lock{ map_lock };
      return static_cast<T&>(*this) != other;
    }

    void swap(concurrent_unordered_map_adapter& other) noexcept(
        noexcept(T::swap(other)))
    {
      std::unique_lock lock{ map_lock };
      T::swap(other);
    }

    template <typename K>
    size_type erase(K&& key)
    {
      std::unique_lock lock{ map_lock };
      return T::erase(std::forward<K>(key));
    }

    bool contains(const key_type& key)
    {
      std::shared_lock lock{ map_lock };
#if utils_cpp20
      return T::contains(key);
#else
      return T::count(key);
#endif
    }

    void clear()
    {
      std::unique_lock lock{ map_lock };
      T::clear();
    }

  private:
    concurrent_unordered_map_adapter(
        const concurrent_unordered_map_adapter& other,
        std::shared_lock<std::shared_mutex>&&   lock)
        : T(other)
    {
    }

    concurrent_unordered_map_adapter(concurrent_unordered_map_adapter&& other,
                                     std::unique_lock<std::shared_mutex>&& lock)
        : T(std::move(other))
    {
    }

    using T::begin;
    using T::cbegin;
    using T::cend;
    using T::end;
    using T::operator[];
    using T::at;
    using T::emplace_hint;
    using T::equal_range;
    void find()        = delete;
    void bucket()      = delete;
    void bucket_size() = delete;
    void extract()     = delete;

    mutable std::shared_mutex map_lock;
  };

  template <typename T, bool concurrent_mode,
            bool is_concurrent_map = concurrent_hash_map<T>>
  struct unordered_map_adapter
  {
    static_assert(
        is_concurrent_map && !concurrent_mode,
        "can't use a non-concurrent adapter with a concurrent unordered map");
    typedef T type;
  };

  template <typename T>
  struct unordered_map_adapter<T, true, false>
  {
    typedef concurrent_unordered_map_adapter<T> type;
  };

  template <typename T, bool concurrent_mode>
  using unordered_map_adapter_t = typename unordered_map_adapter<T, concurrent_mode>::type;

} // namespace utils
