/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "utils_macros.h"
#include <optional>
#include <limits>
#if utils_windows
  #include <intrin.h>
  #pragma intrinsic(_BitScanForward)
  #if utils_64bit
    #pragma intrinsic(_BitScanForward64)
  #endif
#endif
#if utils_cpp20
  #include <bit>
#endif

namespace alterhook::utils
{
  template <typename T>
  constexpr T rol(const T value, const int rotation) noexcept;

  template <typename T>
  constexpr T ror(const T value, const int rotation) noexcept
  {
    static_assert(std::is_integral_v<T> && std::is_unsigned_v<T>,
                  "rol: value must be of integral and unsigned type");
#if utils_cpp20
    return std::rotr(value, rotation);
#else
    constexpr auto digits = std::numeric_limits<T>::digits;
  #if utils_msvc
    if constexpr (digits == 64)
      return _rotr64(value, rotation);
    else if constexpr (digits == 32)
      return _rotr(value, rotation);
    else if constexpr (digits == 16)
      return _rotr16(value, rotation);
    else
      return _rotr8(value, rotation);
  #else
    const auto remainder = rotation % digits;
    if (remainder > 0)
      return static_cast<T>(static_cast<T>(value >> remainder) |
                            static_cast<T>(value << (digits - remainder)));
    else if (!remainder)
      return value;
    else
      return rol(value, -remainder);
  #endif
#endif
  }

  template <typename T>
  constexpr T rol(const T value, const int rotation) noexcept
  {
    static_assert(std::is_integral_v<T> && std::is_unsigned_v<T>,
                  "rol: value must be of integral and unsigned type");
#if utils_cpp20
    return std::rotl(value, rotation);
#else
    constexpr auto digits = std::numeric_limits<T>::digits;
  #if utils_msvc
    if constexpr (digits == 64)
      return _rotl64(value, rotation);
    else if constexpr (digits == 32)
      return _rotl(value, rotation);
    else if constexpr (digits == 16)
      return _rotl16(value, rotation);
    else
      return _rotl8(value, rotation);
  #else
    const auto remainder = rotation % digits;
    if (remainder > 0)
      return static_cast<T>(static_cast<T>(value << remainder) |
                            static_cast<T>(value >> (digits - remainder)));
    else if (!remainder)
      return value;
    else
      return ror(value, -remainder);
  #endif
#endif
  }

  template <typename T>
  constexpr auto to_underlying(const T value) noexcept
  {
    static_assert(std::is_enum_v<T>,
                  "to_underlying: value is expected to be of enum type");
    return static_cast<std::underlying_type_t<T>>(value);
  }

  template <typename T, typename... types>
  constexpr bool any_of(T&& value, types&&... args) noexcept
  {
    return ((value == args) || ...);
  }

  template <typename T, typename align_t>
  constexpr T align(T value, align_t alignment) noexcept
  {
    static_assert(std::is_integral_v<T> && std::is_integral_v<align_t> &&
                      std::is_unsigned_v<align_t>,
                  "align: both value and alignment are expected to be of "
                  "integral types and alignment must be unsigned");
    utils_assert(alignment > 0, "alignment cannot be 0");
    return (value / alignment) * alignment;
  }

  template <typename T, typename align_t>
  T* align(T* value, align_t alignment) noexcept
  {
    return reinterpret_cast<T*>(
        align(reinterpret_cast<uintptr_t>(value), alignment));
  }

  template <typename T, typename align_t>
  constexpr T align_up(T value, align_t alignment) noexcept
  {
    static_assert(std::is_integral_v<T> && std::is_integral_v<align_t> &&
                      std::is_unsigned_v<align_t>,
                  "align_up: both value and alignment are expected to be of "
                  "integral types and alignment must be unsigned");
    utils_assert(alignment > 0, "alignment cannot be 0");
    return ((value + (alignment - 1)) / alignment) * alignment;
  }

  template <typename T, typename align_t>
  T* align_up(T* value, align_t alignment) noexcept
  {
    return reinterpret_cast<T*>(
        align_up(reinterpret_cast<uintptr_t>(value), alignment));
  }

  template <typename T>
  std::optional<uint8_t> bitscanf(const T value) noexcept
  {
    static_assert(
        std::is_integral_v<T> && std::is_unsigned_v<T>,
        "bitscanf: value is expected to be of integral and unsigned type");
#if utils_windows
    unsigned long index = 0;
  #if utils_64bit
    if constexpr (std::numeric_limits<T>::digits == 64)
    {
      if (!_BitScanForward64(&index, value))
        return std::nullopt;
    }
    else
  #endif
    {
      if (!_BitScanForward(&index, value))
        return std::nullopt;
    }
    return index;
#else
    if constexpr (std::numeric_limits<T>::digits == 64)
    {
      if (int result = __builtin_ffsll(value))
        return result - 1;
    }
    else
    {
      if (int result = __builtin_ffs(value))
        return result - 1;
    }
    return std::nullopt;
#endif
  }
} // namespace alterhook::utils