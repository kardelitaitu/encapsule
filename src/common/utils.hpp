// Copyright 2022 PragmaTwice
//
// Licensed under the Apache License,
// Version 2.0(the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ENCAPSULE_COMMON_UTILS
#define ENCAPSULE_COMMON_UTILS

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <random>
#include <regex>
#include <string>

// trim from start (in place)
inline void ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
          }));
}

// trim from end (in place)
inline void rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

// trim from both ends (in place)
inline void trim(std::string &s) {
  ltrim(s);
  rtrim(s);
}

// trim from start (copying)
inline std::string ltrim_copy(std::string s) {
  ltrim(s);
  return s;
}

// trim from end (copying)
inline std::string rtrim_copy(std::string s) {
  rtrim(s);
  return s;
}

// trim from both ends (copying)
inline std::string trim_copy(std::string s) {
  trim(s);
  return s;
}

inline bool all_of_digit(const auto &v) {
  return std::all_of(v.begin(), v.end(),
                     [](auto c) { return std::isdigit(c); });
}

// utf8_encode/decode from cycfi::elements

// Convert a wide Unicode string to an UTF8 string
inline std::string utf8_encode(std::wstring const &wstr) {
  if (wstr.empty())
    return {};
  int size = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(),
                                 nullptr, 0, nullptr, nullptr);
  std::string result(size, 0);
  WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &result[0], size,
                      nullptr, nullptr);
  return result;
}

// Convert an UTF8 string to a wide Unicode String
inline std::wstring utf8_decode(std::string const &str) {
  if (str.empty())
    return {};
  int size =
      MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), nullptr, 0);
  std::wstring result(size, 0);
  MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &result[0], size);
  return result;
}

inline bool filename_wildcard_match(const char *pattern, const char *str) {
  for (; *pattern; ++pattern) {
    switch (*pattern) {
    case '?':
      if (*str == 0)
        return false;
      ++str;
      break;
    case '*': {
      if (pattern[1] == 0)
        return true;
      for (const char *ptr = str; *ptr; ++ptr)
        if (filename_wildcard_match(pattern + 1, ptr))
          return true;
      return false;
    }
    case '/':
    case '\\':
      if (*str != '/' && *str != '\\')
        return false;
      ++str;
      break;
    default:
      if (std::tolower(*str) != std::tolower(*pattern))
        return false;
      ++str;
    }
  }
  return *str == 0;
}

inline std::size_t replace_all_inplace(std::string &inout,
                                       std::string_view what,
                                       std::string_view with) {
  std::size_t count{};
  for (std::string::size_type pos{};
       inout.npos != (pos = inout.find(what.data(), pos, what.length()));
       pos += with.length(), ++count) {
    inout.replace(pos, what.length(), with.data(), with.length());
  }
  return count;
}

inline std::string replace_all(const std::string &input, std::string_view what,
                               std::string_view with) {
  std::string result = input;
  replace_all_inplace(result, what, with);
  return result;
}

inline bool regex_match_filename(const std::string &pattern,
                                 const std::string &input) {
  bool matched = false;

  try {
    std::regex re(pattern, std::regex_constants::icase |
                               std::regex_constants::ECMAScript);
    matched = std::regex_match(replace_all(input, "/", "\\"), re) ||
              std::regex_match(replace_all(input, "\\", "/"), re);
  } catch (const std::regex_error &) {
  }

  return matched;
}

inline const std::wstring port_mapping_name = L"ENCAPSULE_PORT_IPC_";

inline std::wstring get_port_mapping_name(DWORD pid) {
  return port_mapping_name + std::to_wstring(pid);
}

// The IPC mapping payload (P4-3): the control port plus a per-injection
// random token. Guessing the mapping name (it only embeds a pid) no longer
// lets another process read or forge control messages, because the injectee
// echoes the token back inside every InjecteeMessage. Both sides must agree
// on this exact layout, so the size is exposed as a helper rather than as a
// sizeof() at the call sites: the injector maps
// get_port_mapping_payload_size() bytes and writes one port_mapping_payload,
// the injectee reads the same struct back.
inline constexpr std::size_t port_mapping_token_size = 8;

struct port_mapping_payload {
  std::uint16_t port = 0;
  unsigned char token[port_mapping_token_size] = {};
};

static_assert(sizeof(port_mapping_payload) ==
                  port_mapping_token_size + sizeof(std::uint16_t),
              "the payload is copied byte-for-byte between processes");
static_assert(port_mapping_token_size % sizeof(unsigned) == 0,
              "the token is filled in whole random_device draws");

inline constexpr std::size_t get_port_mapping_payload_size() {
  return sizeof(port_mapping_payload);
}

// Build the payload for one injection: the control port plus a fresh random
// token. Returns nullopt when the RNG is unavailable, so a caller must refuse
// the injection instead of falling back to a predictable token.
inline std::optional<port_mapping_payload>
get_port_mapping_payload(std::uint16_t port) {
  port_mapping_payload payload;
  payload.port = port;

  std::random_device rd;
  try {
    for (std::size_t i = 0; i < port_mapping_token_size;
         i += sizeof(unsigned)) {
      const unsigned part = rd();
      std::memcpy(&payload.token[i], &part, sizeof(part));
    }
  } catch (const std::exception &) {
    return std::nullopt;
  }

  return payload;
}

inline std::string encapsule_copyright(const std::string &version) {
  return "encapsule " + version + "\n\n" + "Copyright (c) PragmaTwice\n" +
         "Licensed under the Apache License, Version 2.0";
}

inline std::string encapsule_description =
    "A socks5 proxy injection tool for Windows: just select some processes "
    "and make them proxy-able!\nPlease visit "
    "https://github.com/kardelitaitu/encapsule for more information.";

#endif
