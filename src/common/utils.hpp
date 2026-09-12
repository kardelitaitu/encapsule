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
#include <string_view>

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

// --------------------------------------------------------- proxy endpoint --

// The proxy endpoint every frontend takes, spelled
//
//     [user[:pass]@]host:port
//
// There is no scheme in it and nothing is percent-decoded: every character is
// literal, which is exactly what makes a password containing '@' or ':'
// expressible.  Both separators are therefore resolved structurally instead of
// by escaping:
//
//   * the endpoint splits at the LAST '@', so everything in front of it is the
//     userinfo and an '@' inside a password stays part of the password;
//   * the userinfo splits at its FIRST ':', so "user:a:b" is user "user" with
//     password "a:b";
//   * a password with nothing in it -- no ':' in the userinfo at all, or a ':'
//     with nothing after it -- leaves the password UNSET rather than handing
//     back an empty string.  The two are not interchangeable further down:
//     schema.hpp adds no bytes for an unset field and a length-only field for
//     an empty one, so an empty password means "sign in with this username
//     only", exactly as the GUI's empty password box already means.
//   * an EMPTY username means no credentials at all, so "@host:1080" and
//     ":pass@host:1080" come back with neither field set: a password with
//     nobody to sign in as is not a credential.
//
// A bare IPv6 host cannot be told apart from a port, so it has to arrive
// bracketed the way every other tool spells it, "[2001:db8::1]:1080"; the
// brackets are stripped here, before any ':' logic runs, so a caller never
// sees them and the address keeps its plain, storable form.
//
// Refused, i.e. nullopt: an empty host, or one carrying a stray bracket; a
// missing, empty, non-numeric or out-of-range port (0 included -- it is "no
// port", not a port); an unterminated '['; and a username or password longer
// than RFC 1929 can carry, which could never be sent no matter what a server
// were willing to accept.
struct proxy_endpoint {
  std::string host;
  std::uint16_t port = 0;
  std::optional<std::string> username;
  std::optional<std::string> password;
};

// Both credential lengths travel in a single octet, so a longer string could
// never reach a server no matter which frontend accepted it.
inline constexpr std::size_t proxy_credential_max_length = 255;

// The widest port is "65535".
inline constexpr std::size_t proxy_port_max_length = 5;

inline std::optional<proxy_endpoint> parse_proxy_url(std::string_view url) {
  std::string_view userinfo, authority;
  if (const auto at = url.rfind('@'); at != std::string_view::npos) {
    userinfo = url.substr(0, at);
    authority = url.substr(at + 1);
  } else {
    authority = url;
  }

  std::string_view host, port_text;
  if (!authority.empty() && authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string_view::npos) {
      return std::nullopt;
    }
    host = authority.substr(1, close - 1);
    const auto tail = authority.substr(close + 1);
    if (tail.empty() || tail.front() != ':') {
      return std::nullopt; // whatever follows ']' has to be ":port"
    }
    port_text = tail.substr(1);
  } else {
    const auto colon = authority.rfind(':');
    if (colon == std::string_view::npos) {
      return std::nullopt; // no separator means no port
    }
    host = authority.substr(0, colon);
    port_text = authority.substr(colon + 1);
  }

  if (host.empty()) {
    return std::nullopt;
  }
  // Brackets belong to the IPv6 form above and to nothing else, so a stray
  // one -- "[[::1]:1080", "a]b:1" -- is refused here instead of becoming part
  // of a host nobody can resolve.
  if (host.find_first_of("[]") != std::string_view::npos) {
    return std::nullopt;
  }

  // Accumulated digit by digit rather than handed to std::stoul: the port is
  // digits or nothing (no sign, no space, no trailing garbage), and the value
  // has to be bounded without throwing on the garbage refused here.
  if (port_text.empty() || port_text.size() > proxy_port_max_length) {
    return std::nullopt;
  }
  std::uint32_t port = 0;
  for (const char digit : port_text) {
    if (digit < '0' || digit > '9') {
      return std::nullopt;
    }
    port = port * 10 + static_cast<std::uint32_t>(digit - '0');
  }
  if (port == 0 || port > 65535) {
    return std::nullopt; // port 0 is not an endpoint, it is "no port"
  }

  proxy_endpoint endpoint;
  endpoint.host = std::string(host);
  endpoint.port = static_cast<std::uint16_t>(port);

  if (userinfo.empty()) {
    return endpoint;
  }

  const auto colon = userinfo.find(':');
  const auto name = userinfo.substr(0, colon);
  const auto password = colon == std::string_view::npos
                            ? std::string_view{}
                            : userinfo.substr(colon + 1);

  // The caps are checked before the empty-username rule, so a credential too
  // long to put on the wire is a typo to report rather than a silent
  // downgrade to an unauthenticated connection.
  if (name.size() > proxy_credential_max_length ||
      password.size() > proxy_credential_max_length) {
    return std::nullopt;
  }

  if (!name.empty()) {
    endpoint.username = std::string(name);
    if (!password.empty()) {
      endpoint.password = std::string(password);
    }
  }

  return endpoint;
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
