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

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

// <Windows.h> must come first: utils.hpp uses DWORD / WideCharToMultiByte
// without including it, and winsock2 must stay ahead of <winsock.h>.
#include <Windows.h>

#include "test_support.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <utils.hpp>

// The watch-mode primitives under test live in winraii.hpp, which carries
// non-inline helpers -- safe here because this is the only translation unit of
// this binary (same reason the e2e binary includes it).
#include <winraii.hpp>

// ---------------------------------------------------------------- wildcard --

void wildcard_star() {
  // a '*' that ends the pattern matches everything, including nothing
  CHECK(filename_wildcard_match("*", ""));
  CHECK(filename_wildcard_match("*", "anything"));
  CHECK(filename_wildcard_match("py*", "python"));
  CHECK(filename_wildcard_match("py*", "py"));
  // a trailing '*' matches an empty tail, but never a missing literal
  CHECK(!filename_wildcard_match("py*", "p"));
  CHECK(!filename_wildcard_match("py*", "thon"));
  // a '*' that is not last must find the rest of the pattern somewhere
  CHECK(filename_wildcard_match("*py", "happy"));
  CHECK(!filename_wildcard_match("*py", "python"));
  CHECK(filename_wildcard_match("*.exe", "python.exe"));
  CHECK(!filename_wildcard_match("*.exe", "python.dll"));
  CHECK(filename_wildcard_match("C:*.dll", "C:\\windows\\x.dll"));
  // mid-pattern '*' can stand for an empty run as long as the remainder
  // matches at the current position, but it cannot match past the end
  CHECK(filename_wildcard_match("py*x", "pyx"));
  CHECK(filename_wildcard_match("py*x", "pythox"));
  CHECK(!filename_wildcard_match("py*x", "py"));
  CHECK(!filename_wildcard_match("a*b*c", "ac"));
  CHECK(filename_wildcard_match("a*b*c", "abbbc"));
}

void wildcard_question() {
  CHECK(filename_wildcard_match("?", "a"));
  CHECK(!filename_wildcard_match("?", ""));
  CHECK(filename_wildcard_match("py??on", "python"));
  CHECK(filename_wildcard_match("py??on", "pyTHon"));
  CHECK(!filename_wildcard_match("py??on", "pyton"));   // one char too few
  CHECK(!filename_wildcard_match("py??on", "pythxon")); // ... is not enough
  CHECK(!filename_wildcard_match("", "a"));             // empty pattern
  CHECK(filename_wildcard_match("", ""));
}

void wildcard_separator_equivalence() {
  // '/' and '\\' in the pattern are interchangeable, and so are they in str
  CHECK(filename_wildcard_match("C:/a/b.exe", "C:\\a\\b.exe"));
  CHECK(filename_wildcard_match("C:\\a\\b.exe", "C:/a/b.exe"));
  CHECK(filename_wildcard_match("C:/a/b.exe", "C:/a/b.exe"));
  CHECK(filename_wildcard_match("C:\\a\\b.exe", "C:\\a\\b.exe"));
  CHECK(filename_wildcard_match("*/b", "a\\b"));
  CHECK(filename_wildcard_match("*\\b", "a/b"));
  // a separator in the pattern must not match an ordinary character
  CHECK(!filename_wildcard_match("C:/a", "C:xa"));
  CHECK(!filename_wildcard_match("C:/a", "C:a"));
  // ... and an ordinary pattern char must not match a separator
  CHECK(!filename_wildcard_match("C:a", "C:\\a"));
}

void wildcard_case_folding() {
  CHECK(filename_wildcard_match("PYTHON", "python"));
  CHECK(filename_wildcard_match("python", "PYTHON"));
  CHECK(filename_wildcard_match("PyThOn.Exe", "python.exe"));
  CHECK(filename_wildcard_match("C:/Program Files/X.EXE",
                                "c:\\program files\\x.exe"));
  CHECK(filename_wildcard_match("*.DLL", "C:\\Win\\Thing.dll"));
  // case folding does not make a pattern shorter or longer than the input
  CHECK(!filename_wildcard_match("PYTHON", "python.exe"));
  CHECK(!filename_wildcard_match("python", "pytho"));
  // '?' consumes any char, folded or not, and needs that char to exist
  CHECK(filename_wildcard_match("python?", "pythoNX"));
  CHECK(!filename_wildcard_match("python?", "pythoN"));
}

// ------------------------------------------------------------------- regex --

void regex_icase_and_anchoring() {
  CHECK(regex_match_filename("py.*", "PYTHON"));
  CHECK(regex_match_filename("python\\.exe", "Python.EXE"));
  // std::regex_match is a full match, not a search
  CHECK(!regex_match_filename("py", "python"));
  CHECK(!regex_match_filename("python", "python.exe"));
  CHECK(regex_match_filename("py.*|exp.*", "expected"));
  CHECK(regex_match_filename("py.*|exp.*", "python3"));
  CHECK(!regex_match_filename("py.*|exp.*", "xylophone"));
}

void regex_separator_alternation() {
  // backslash pattern against a forward-slash input (and its own spelling)
  CHECK(regex_match_filename(R"(C:\\programs\\(python|node)\..*)",
                             "C:/programs/python.exe"));
  CHECK(regex_match_filename(R"(C:\\programs\\(python|node)\..*)",
                             "C:\\programs\\node.exe"));
  // forward-slash pattern against a backslash input
  CHECK(regex_match_filename(R"(C:/programs/(python|node)\..*)",
                             "C:\\programs\\node.exe"));
  CHECK(regex_match_filename(R"(C:/programs/(python|node)\..*)",
                             "C:/programs/python.exe"));
  // both spellings of the same path match the same pattern
  CHECK(regex_match_filename(R"(C:\\a\\(x|y)\\b)", "C:\\a\\y\\b"));
  CHECK(regex_match_filename(R"(C:\\a\\(x|y)\\b)", "C:/a/x/b"));
  CHECK(!regex_match_filename(R"(C:\\a\\(x|y)\\b)", "C:/a/z/b"));
  CHECK(regex_match_filename("C:/a/(x|y)/b", "C:\\a\\y\\b"));
}

void regex_invalid_pattern_is_false() {
  bool threw = false;
  const char *bad[] = {"(", "[z-a]", "a{2,1}", "(?", "\\", "*)"};
  for (const char *p : bad) {
    try {
      CHECK(!regex_match_filename(p, "anything"));
    } catch (const std::regex_error &) {
      threw = true;
    } catch (...) {
      threw = true;
    }
  }
  CHECK(!threw); // regex_match_filename must swallow regex_error itself
}

// -------------------------------------------------------------- replace_all --

void replace_all_cases() {
  CHECK_EQ(replace_all("a/b/c", "/", "\\"), "a\\b\\c");
  CHECK_EQ(replace_all("C:/programs/python.exe", "/", "\\"),
           "C:\\programs\\python.exe");
  CHECK_EQ(replace_all("python", "z", "y"), "python"); // nothing to do
  CHECK_EQ(replace_all("", "a", "b"), "");
  CHECK_EQ(replace_all("xxx", "x", "yy"), "yyyyyy");
  // the scan resumes with.length() past each replacement, so a shorter
  // replacement re-exposes the tail: "aaaa" -> "baa" -> "bb"
  CHECK_EQ(replace_all("aaaa", "aa", "b"), "bb");
  CHECK_EQ(replace_all("hello world", "o", "01"), "hell01 w01rld");
  CHECK_EQ(replace_all("aba", "a", ""), "b"); // erase every occurrence

  std::string in_place = "a/b/c";
  CHECK_EQ(replace_all_inplace(in_place, "/", "\\"), std::size_t(2));
  CHECK_EQ(in_place, "a\\b\\c");
  CHECK_EQ(replace_all_inplace(in_place, "/", "\\"), std::size_t(0));
  CHECK_EQ(in_place, "a\\b\\c");
}

// -------------------------------------------------------------------- trim --

void trim_in_place() {
  std::string both = "  abc  ";
  trim(both);
  CHECK_EQ(both, "abc");

  std::string left = "  abc  ";
  ltrim(left);
  CHECK_EQ(left, "abc  ");

  std::string right = "  abc  ";
  rtrim(right);
  CHECK_EQ(right, "  abc");

  std::string kinds = "\t\n\v\f\r abc \r\n\f\v\t";
  trim(kinds);
  CHECK_EQ(kinds, "abc");

  std::string blank = "   ";
  trim(blank);
  CHECK_EQ(blank, "");

  std::string empty;
  trim(empty);
  CHECK_EQ(empty, "");

  std::string untouched = "abc";
  trim(untouched);
  CHECK_EQ(untouched, "abc");
}

void trim_copy_variants() {
  CHECK_EQ(trim_copy("  abc  "), "abc");
  CHECK_EQ(ltrim_copy("  abc  "), "abc  ");
  CHECK_EQ(rtrim_copy("  abc  "), "  abc");
  CHECK_EQ(trim_copy(""), "");
  CHECK_EQ(trim_copy("   "), "");
  CHECK_EQ(trim_copy("\t x \n"), "x");

  // the *_copy forms must not touch their argument
  std::string orig = "  x  ";
  std::string copy = trim_copy(orig);
  CHECK_EQ(orig, "  x  ");
  CHECK_EQ(copy, "x");
}

// ------------------------------------------------------------- all_of_digit --

void all_of_digit_cases() {
  CHECK(all_of_digit(std::string("12345")));
  CHECK(all_of_digit(std::string("0")));
  CHECK(all_of_digit(std::string("007")));
  CHECK(all_of_digit(std::string_view("42")));
  CHECK(all_of_digit(std::vector<char>{'9', '0'}));
  // vacuously true for the empty input
  CHECK(all_of_digit(std::string("")));

  CHECK(!all_of_digit(std::string("12a45")));
  CHECK(!all_of_digit(std::string("12 ")));
  CHECK(!all_of_digit(std::string("-1")));
  CHECK(!all_of_digit(std::string("1.5")));
  CHECK(!all_of_digit(std::string("0x1f")));
}

// ------------------------------------------------------- port mapping name --

void port_mapping_name_contract() {
  // P3 renames the prefix; the contract that must survive is the concatenation
  CHECK_EQ(get_port_mapping_name(123), port_mapping_name + L"123");
  CHECK_EQ(get_port_mapping_name(0), port_mapping_name + L"0");
  CHECK_EQ(get_port_mapping_name(1), port_mapping_name + L"1");
  CHECK_EQ(get_port_mapping_name(65535), port_mapping_name + L"65535");
  CHECK_EQ(get_port_mapping_name(0xFFFFFFFF),
           port_mapping_name + L"4294967295");

  // rename-proof restatements of the same contract
  const std::wstring name = get_port_mapping_name(123);
  CHECK_EQ(name.rfind(port_mapping_name, 0), std::size_t(0)); // starts with it
  CHECK_EQ(name.substr(port_mapping_name.size()), L"123"); // ends with pid
  CHECK_EQ(name.size(), port_mapping_name.size() + 3);
  CHECK_EQ(port_mapping_name.empty(), false);
}

// ------------------------------------------------------- proxy endpoint --

// parse_proxy_url is pure, so what a case really asserts is which of the four
// fields the string lands on -- and for a rejected string, that it lands on
// none of them.  Both helpers name the input on failure: a CHECK inside this
// file would otherwise point at a shared line and say nothing about which of
// the thirty endpoint spellings below went wrong.

using opt = std::optional<std::string>;

void check_endpoint(const std::string &url, const std::string &host,
                    std::uint16_t port, const opt &user = std::nullopt,
                    const opt &pass = std::nullopt) {
  const auto ep = parse_proxy_url(url);
  if (ep && ep->host == host && ep->port == port &&
      ep->username == user && ep->password == pass) {
    return;
  }

  ++test_failures;
  std::printf("FAIL proxy endpoint \"%s\" -> ", url.c_str());
  if (!ep) {
    std::printf("rejected\n");
    return;
  }
  // Both values are echoed here: this is a test binary, not a product log,
  // and the interesting part of a failure is which separator landed on
  // which side of which field.
  const auto shown = [](const opt &v) -> std::string {
    return v ? *v : std::string("unset");
  };
  std::printf("  got %s:%u username=%s password=%s\n", ep->host.c_str(),
              static_cast<unsigned>(ep->port),
              shown(ep->username).c_str(), shown(ep->password).c_str());
}

void check_rejected(const std::string &url) {
  const auto ep = parse_proxy_url(url);
  if (!ep) {
    return;
  }

  ++test_failures;
  std::printf("FAIL proxy endpoint \"%s\" accepted as \"%s\":%u\n", url.c_str(),
              ep->host.c_str(), static_cast<unsigned>(ep->port));
}

void endpoint_host_and_port() {
  check_endpoint("127.0.0.1:1080", "127.0.0.1", 1080);
  check_endpoint("localhost:1", "localhost", 1);
  check_endpoint("proxy.example.com:8080", "proxy.example.com", 8080);
  check_endpoint("10.0.0.1:65535", "10.0.0.1", 65535); // widest legal port
  // the host is syntax here, not an address to validate
  check_endpoint("0.0.0.0:1", "0.0.0.0", 1);
}

void endpoint_credentials() {
  check_endpoint("user:pass@127.0.0.1:1080", "127.0.0.1", 1080, opt("user"),
                 opt("pass"));
  check_endpoint("alice:s3cr3t!@socks.host:1", "socks.host", 1,
                 opt("alice"), opt("s3cr3t!"));

  // A userinfo with no ":" carries a username and no password at all: unset,
  // never an empty string, because the two encode differently on the wire.
  check_endpoint("user@host:1080", "host", 1080, opt("user"));
  check_endpoint("user:@host:1080", "host", 1080, opt("user"));

  // The password keeps every ":" after the first one, and every "@" after the
  // last one, and it is never un-escaped: those are literal characters.
  check_endpoint("user:a:b@h:1", "h", 1, opt("user"), opt("a:b"));
  check_endpoint("p@ss:w@host:1080", "host", 1080, opt("p@ss"), opt("w"));
  check_endpoint("user:p@ss@host:1080", "host", 1080, opt("user"),
                 opt("p@ss"));
  check_endpoint("user:a@b:c@h:1", "h", 1, opt("user"), opt("a@b:c"));
  check_endpoint("user:%70ass@h:1", "h", 1, opt("user"), opt("%70ass"));
  check_endpoint("us er:pa ss@h:1", "h", 1, opt("us er"), opt("pa ss"));
}

void endpoint_ipv6_host() {
  // The brackets exist because a v6 host is full of ":", so they come off
  // before any of the host/port reasoning: what is stored is the plain
  // address, ready for ip::make_address, with the port after the last ":".
  check_endpoint("[2001:db8::1]:1080", "2001:db8::1", 1080);
  check_endpoint("[::1]:1", "::1", 1);
  check_endpoint("[fe80::1]:65535", "fe80::1", 65535);
  check_endpoint("user:pass@[2001:db8::1]:1080", "2001:db8::1", 1080,
                 opt("user"), opt("pass"));
  check_endpoint("user@[::1]:1080", "::1", 1080, opt("user"));
  check_endpoint(":pw@[fe80::1]:1", "fe80::1", 1); // no user, brackets kept

  check_rejected("[2001:db8::1]");     // brackets, but no port
  check_rejected("[2001:db8::1]1080"); // port, but no separator
  check_rejected("[2001:db8::1:1080"); // bracket never closed
  check_rejected("[::1]:");            // separator, empty port
  check_rejected("[]:1080");           // nothing inside the brackets
  check_rejected("[[::1]:1080");       // a bracket inside the host
  check_rejected("a]b:1080");          // ... or outside it
}

void endpoint_without_a_username_has_no_credentials() {
  // Every spelling here has an empty username, and an empty username is nobody
  // to sign in as: the endpoint stands, the credentials do not.
  check_endpoint(":pw@h:1080", "h", 1080);
  check_endpoint("@h:1080", "h", 1080);
  check_endpoint("@[2001:db8::1]:1080", "2001:db8::1", 1080);
  check_endpoint("::@h:1", "h", 1); // the first ":" splits, and the user is ""
}

void endpoint_credential_length_caps() {
  const std::string ok(255, 'u');
  const std::string too_long(256, 'u');
  const std::string pw(255, 'p');
  const std::string pw_too_long(256, 'p');

  // RFC 1929 sends both lengths in one octet, so 255 is the widest pair there
  // is and 256 could never be offered to a server.
  check_endpoint(ok + ":pw@h:1080", "h", 1080, opt(ok), opt("pw"));
  check_endpoint("user:" + pw + "@h:1080", "h", 1080, opt("user"), opt(pw));
  check_endpoint(ok + ":" + pw + "@h:1080", "h", 1080, opt(ok), opt(pw));
  check_rejected(too_long + ":pw@h:1080");
  check_rejected("user:" + pw_too_long + "@h:1080");
  check_rejected(too_long + ":" + pw_too_long + "@h:1080");
  // The cap is checked before the empty-username rule, so a credential too
  // long to send is a typo to report, not a silent drop to no auth.
  check_rejected(":" + pw_too_long + "@h:1080");
}

void endpoint_rejects_garbage() {
  check_rejected("");
  check_rejected("host");        // no port at all
  check_rejected("host:");       // an empty port is no port
  check_rejected("host:port");   // not numeric
  check_rejected("host:1080x");  // ... nor partly numeric
  check_rejected("host:-1");     // ... nor signed
  check_rejected("host:+80");
  check_rejected("host: 1080");  // ... nor with room to breathe
  check_rejected("host:1080 ");
  check_rejected("host:65536");  // out of range, though it is all digits
  check_rejected("host:99999999");
  check_rejected("host:0");      // "no port" in another costume
  check_rejected(":1080");       // empty host
  check_rejected("@:1080");      // empty credentials and an empty host
  check_rejected("user@");       // userinfo, but no host
  check_rejected("user@host");   // credentials, but no port
  check_rejected("@");
}

// ------------------------------------------------- credential redaction --

// What `encapsule-cli` writes to stderr when a command line fails to parse
// must not carry the socks5 password: argv is readable by every same-user
// process (and by Sysmon EID 1), and argparse quotes the offending token
// verbatim into its message.  The cases below pin that property on the
// OUTPUT of `sanitize_parse_error` -- the string the CLI prints -- rather
// than on how the scrubber reaches it, so the redactor may be rewritten
// under them as long as no secret travels.

namespace redact = encapsule::utils;

namespace {

// The composition argparse produces for an unrecognised option: a fixed
// prefix plus the offending token, straight from argv.
std::string unknown_argument(const std::string &token) {
  return redact::sanitize_parse_error("Unknown argument: " + token);
}

// Reports which output leaked which value: a bare CHECK on a shared line
// would name none of the spellings below.
bool hides(const std::string &out, const std::string &secret) {
  if (out.find(secret) == std::string::npos) {
    return true;
  }
  ++test_failures;
  std::printf("FAIL redaction: output \"%s\" still holds \"%s\"\n",
              out.c_str(), secret.c_str());
  return false;
}

} // namespace

struct redacted_case {
  const char *token; // what argv held
  const char *secret; // what stderr must not hold
  const char *output; // what stderr must hold, exactly
};

void a_glued_proxy_url_keeps_the_authority_and_loses_the_login() {
  const redacted_case cases[] = {
      {"-palice:hunter2@1.2.3.4:1080", "hunter2",
       "Unknown argument: 1.2.3.4:1080"},
      {"-p=alice:hunter2@1.2.3.4:1080", "hunter2",
       "Unknown argument: 1.2.3.4:1080"},
      {"--alice:hunter2@1.2.3.4", "hunter2", "Unknown argument: 1.2.3.4"},
      {"--set-proxy=alice:hunter2@1.2.3.4:1080", "hunter2",
       "Unknown argument: 1.2.3.4:1080"},
      // A password holding its own '@': the LAST one is the separator, so
      // the whole of `p@ssw0rd' is userinfo and none of it is printed.
      {"-palice:p@ssw0rd@1.2.3.4:1080", "ssw0rd",
       "Unknown argument: 1.2.3.4:1080"},
  };

  for (const auto &c : cases) {
    const std::string out = unknown_argument(c.token);
    // The security property, stated three ways so a rewrite cannot pass by
    // accident: no password, no username, and no '@' left to show that a
    // login was ever there.
    CHECK(hides(out, c.secret));
    CHECK(hides(out, "alice"));
    CHECK(out.find('@') == std::string::npos);
    // Then the actionable half, whole: the host:port the user can fix and
    // the fixed words that say which argument was wrong.  Without this, a
    // redactor that deleted the entire message would pass every check
    // above.
    CHECK_EQ(out, c.output);
  }
}

void an_authority_with_no_userinfo_keeps_every_byte() {
  // Nothing to strip, so nothing changes: the redaction removes the
  // userinfo and never the address the rejection is about.
  CHECK_EQ(unknown_argument("1.2.3.4:1080"),
           "Unknown argument: 1.2.3.4:1080");
  CHECK_EQ(unknown_argument("[2001:db8::1]:1080"),
           "Unknown argument: [2001:db8::1]:1080");
  CHECK_EQ(redact::scrub_token("1.2.3.4:1080").value_or("<dropped>"),
           "1.2.3.4:1080");
  // A username with no password is still userinfo, and goes with it.
  CHECK_EQ(unknown_argument("-palice@1.2.3.4:1080"),
           "Unknown argument: 1.2.3.4:1080");
}

void a_token_holding_nothing_but_a_secret_collapses_to_the_prefix() {
  // The empty-authority case: `-p<user:pass>` with no '@' has no host to
  // name, so there is NO printable remainder and the token is dropped
  // WHOLE, leaving only the fixed prefix.  The bug this pins is the echo of
  // a bare password, which is what printing the remainder would be.
  const char *secret_only[] = {"-palice:hunter2", "-p=alice:hunter2",
                               "-p:hunter2", "--set-proxy=alice:hunter2"};
  for (const char *t : secret_only) {
    CHECK(!redact::scrub_token(t).has_value());
    const std::string out = unknown_argument(t);
    CHECK(hides(out, "hunter2"));
    CHECK_EQ(out, "Unknown argument:");
  }

  // Take the fixed prefix away too and nothing printable is left at all:
  // the message becomes text that names no value.
  CHECK_EQ(redact::sanitize_parse_error("-p:alice:hunter2"),
           "Invalid argument (value redacted)");
}

void a_non_proxy_unknown_argument_passes_through_unchanged() {
  // The redactor is targeted, not a global mangler: every token below is an
  // unknown argument that holds no proxy credential, and each has to come
  // back byte-for-byte.  If these were scrubbed too, no parse message
  // could be trusted to say what the user typed.
  const char *plain[] = {"--bogus-token", "-z", "--name", "42",
                         "-Ppython.exe", "--path=C:/x/y.exe",
                         "-rpy.*|exp.*"};
  for (const char *t : plain) {
    CHECK_EQ(redact::scrub_token(t).value_or("<dropped>"), std::string(t));
    CHECK_EQ(unknown_argument(t), std::string("Unknown argument: ") + t);
  }

  // And the same for the fixed-worded messages on this path, which quote
  // no value at all: sanitizing them is a no-op.
  const char *fixed[] = {"Too few arguments",
                         "Maximum number of arguments exceeded",
                         "Expected at least one of `-i`, `-n` or `-e`",
                         "Argument `-i` expected an argument, but got none"};
  for (const char *m : fixed) {
    CHECK_EQ(redact::sanitize_parse_error(m), std::string(m));
  }
}

void only_a_proxy_flag_spelling_reads_as_a_proxy_flag() {
  // What makes the redactor targeted is this predicate, so it is pinned on
  // its own: true only for a proxy flag carrying a glued-on value.
  CHECK(redact::is_proxy_flag_token("-palice:pw"));
  CHECK(redact::is_proxy_flag_token("-p=alice:pw"));
  CHECK(redact::is_proxy_flag_token("--set-proxy=alice:pw"));
  CHECK(redact::is_proxy_flag_token("-puser:pw@1.2.3.4:1080"));
  // A bare flag carries no value, so it stays printable...
  CHECK(!redact::is_proxy_flag_token("-p"));
  CHECK(!redact::is_proxy_flag_token("--set-proxy"));
  // ... and the file-name flags -- uppercase `-P`, spelled `path` -- are
  // never treated as if they held a login.
  CHECK(!redact::is_proxy_flag_token("-Puser:pw"));
  CHECK(!redact::is_proxy_flag_token("--path=C:/x/y.exe"));
  CHECK(!redact::is_proxy_flag_token("alice:pw")); // not a flag at all
  CHECK(!redact::is_proxy_flag_token(""));
}

// --------------------------------------- the argparse v3 gap: NO test yet --
//
// DELIBERATELY NOT ADDED, and no scrub implemented either.  Reading it as
// an oversight would be the wrong response.
//
// The pinned dependency is argparse v2.9, and every failure it can throw
// out of `parse_args` puts the offending value in its own
// whitespace-separated run: "Unknown argument: " + token
// (argparse.hpp:1522 and :1526), "Too few arguments for '<x>'", the
// "expected an argument" family.  That is what `sanitize_parse_error`
// tokenises on, and what the cases above pin.
//
// The dependency dossier reports that argparse v3 adds a further form,
// "Invalid argument <x>", which is NOT scrubbed for today.  Two reasons
// keep it untested here:
//
//   * v2.9 cannot produce that string, so a case written now would assert
//     the shape of a message we invent, not one the CLI can emit -- it
//     could only pass or fail on the invention. Untestable speculation.
//   * inventing it would also put a second "Invalid argument"-prefixed
//     message on this path, right beside the scrubber's own fixed
//     fallback text, "Invalid argument (value redacted)".  A test that
//     greps for one would quietly be watching the other.
//
// When the bump lands, in this order: (1) re-run the measured CLI cases
// whose stderr the tests above mirror, plus the new form, against the real
// binary; (2) add the "Invalid argument <x>" case then, fed the string the
// bumped parser actually throws; and (3) if in that form the value is no
// longer a whitespace-separated run of its own -- glued into the fixed
// text, or wrapped in brackets that survive the split -- extend the
// redactor to that shape before the case is written, because a scrub for a
// message that still cannot be produced is worth nothing.

// ------------------------------------------------------------ watch diff --

// process_watch_diff is the pure half of auto-inject: no syscalls and no
// snapshot to blame, so the rule a watcher will live by can be pinned right
// here.  Each case is the same three lists: what the caller had already seen,
// what the next poll found, and the pids a watcher may act on.

std::vector<DWORD> diff_of(const std::set<DWORD> &prev,
                           const std::vector<DWORD> &now) {
  return process_watch_diff(prev, now);
}

void an_empty_previous_snapshot_reports_everything() {
  // nothing seen yet, so everything is an appearance -- and the order the
  // snapshot came in is not the order the watcher is handed
  CHECK_EQ(diff_of({}, {30, 10, 20}), (std::vector<DWORD>{10, 20, 30}));
  CHECK(diff_of({}, {}).empty()); // an empty world is still an empty answer
}

void an_unchanged_snapshot_reports_nothing() {
  const std::set<DWORD> prev{10, 20, 30};

  // the same three processes, spelled however you like: none of them is new
  CHECK(diff_of(prev, {10, 20, 30}).empty());
  CHECK(diff_of(prev, {30, 10, 20}).empty()); // order carries no information
  CHECK(diff_of(prev, {20, 20, 10, 30, 30}).empty());

  // processes are allowed to have EXITED between polls, which is not an
  // appearance either: the diff reports arrivals only
  CHECK(diff_of(prev, {10, 30}).empty());
  CHECK(diff_of(prev, {}).empty());
}

void a_reappearing_pid_is_reported_again() {
  // three polls of one pid: new, gone, and back.  The middle one stores a prev
  // without 40, so the last one must report 40 again -- a watcher that
  // remembered 40 forever would never re-inject a program it restarted, which
  // is the whole point of auto-inject.
  CHECK_EQ(diff_of({}, {40}), std::vector<DWORD>{40});
  CHECK(diff_of(std::set<DWORD>{40}, {}).empty());
  CHECK_EQ(diff_of(std::set<DWORD>{}, {40}), std::vector<DWORD>{40});

  // and a known pid sitting next to a new one is still not news
  CHECK_EQ(diff_of(std::set<DWORD>{40}, {40, 41}), std::vector<DWORD>{41});
}

void results_are_ascending_and_duplicate_free() {
  const std::set<DWORD> prev{7, 50, 50, 1000};
  const std::vector<DWORD> now{1000, 3, 50, 99, 3, 7};

  // 7, 50 and 1000 were already known; 3 and 99 are new; 3 was listed twice
  // but it is one process, so it is one report
  CHECK_EQ(diff_of(prev, now), (std::vector<DWORD>{3, 99}));

  // ascending is the contract, not luck of the input
  CHECK_EQ(diff_of({}, {4000, 1, 2000, 300, 3}),
           (std::vector<DWORD>{1, 3, 300, 2000, 4000}));
  CHECK_EQ(diff_of({}, {1, 1, 1}), std::vector<DWORD>{1});
}

// --------------------------------------------------------- live processes --

// What a real snapshot guarantees, as opposed to what it happens to hold:
// other processes come and go while this runs, so the only process that may be
// asserted to exist is this one -- the process we are standing in.  Anything
// spawned is probed optionally, because losing the race is normal.

void the_snapshot_contains_this_process() {
  const DWORD self = GetCurrentProcessId();

  const auto pids = enumerate_pids();
  CHECK(!pids.empty());
  CHECK(std::find(pids.begin(), pids.end(), self) != pids.end());

  // the invariant that keeps a watcher from re-injecting the world: a poll
  // that is fed back as prev, unchanged, produces no work
  const std::set<DWORD> as_set(pids.begin(), pids.end());
  CHECK(diff_of(as_set, pids).empty());
  // and one poll later, whatever else started in the meantime: we are in prev,
  // we are still alive, so we must not come back as an appearance
  const auto later = diff_of(as_set, enumerate_pids());
  CHECK(std::find(later.begin(), later.end(), self) == later.end());
}

void the_short_name_of_this_process_is_its_stem() {
  // our own image is alive and openable, so this cannot race.  The spelling
  // below is the CMake target of this binary (tests/utils/CMakeLists.txt:1):
  // a basename, folded to lower case, with the extension dropped -- exactly
  // the shape a name pattern is matched against.
  const std::string name =
      process_short_name(GetCurrentProcessId()).value_or("");
  CHECK_EQ(name, "encapsule_test_utils");
  CHECK(name.find_first_of("\\/") == std::string::npos); // no directory left
  CHECK(!name.ends_with(".exe"));                        // no extension left

  // value_or above also covers the contract that a name is returned at all
  CHECK(process_short_name(GetCurrentProcessId()).has_value());
}

void a_pid_that_cannot_be_opened_has_no_name() {
  // pid 0 is the reserved System Idle Process and pid (DWORD)-1 is not a pid:
  // both answers are "no such process", which a watcher must skip rather than
  // treat as a match.  This is the nullopt documented on the helper.
  CHECK(!process_short_name(0).has_value());
  CHECK(!process_short_name(static_cast<DWORD>(-1)).has_value());
}

void a_spawned_child_is_named_while_it_survives() {
  // cmd.exe /c exit is on its way out before CreateProcess even returns, so
  // the probe stays optional: no assertion is made about catching it, and the
  // one that is made only runs when the name really was readable.
  auto proc = create_process("cmd.exe /c exit");
  if (!proc) {
    return; // nothing to probe, which is still not a failure
  }
  handle process = proc->hProcess; // winraii's own RAII closes both handles
  handle thread = proc->hThread;

  if (auto name = process_short_name(proc->dwProcessId)) {
    CHECK_EQ(*name, "cmd"); // the image we asked for, folded to its stem
  }
}

// ------------------------------------------- process snapshot failure (M1-d) --

void the_snapshot_failure_sentinel_is_not_null() {
  // The trap this header used to fall into, pinned as a fact about the API
  // rather than about our code: CreateToolhelp32Snapshot answers "no snapshot"
  // with (HANDLE)-1, which is truthy, so the 'if (handle snapshot = ...)'
  // guard that stood there could never fire -- and -1 is also what
  // GetCurrentProcess() returns, so the destructor's CloseHandle was a call
  // about a value that is never a closable handle.  Anyone tempted to
  // "simplify" the raw sentinel test back into a truthiness test has to change
  // these lines first.
  CHECK(INVALID_HANDLE_VALUE != nullptr);
  CHECK(static_cast<bool>(INVALID_HANDLE_VALUE));
  CHECK(static_cast<LONG_PTR>(reinterpret_cast<std::intptr_t>(
            INVALID_HANDLE_VALUE)) == -1);
}

void a_bogus_pid_is_enumerated_and_never_found() {
  // The other half of the fix: the sentinel test must not turn the enumeration
  // into a silent no-op.  A guard that always returned early would leave every
  // "not found" assertion below green by accident, so the success path is
  // asserted first -- the snapshot yields rows, and we are in them.
  int seen = 0;
  bool found_self = false;
  match_process([&](const PROCESSENTRY32W &entry) {
    ++seen;
    if (entry.th32ProcessID == GetCurrentProcessId()) {
      found_self = true;
    }
  });
  CHECK(seen > 0);
  CHECK(found_self);
  CHECK(!enumerate_pids().empty());

  // The documented "do not know" answer, through the public helpers a caller
  // actually uses: a pid no allocator hands out is simply absent, so
  // get_process_name yields the empty string (which matches no pattern) and
  // the pid list does not contain it.  A freshly exited pid gives the same
  // answer and is deliberately not asserted: pid recycling is legal, so that
  // variant could turn a correct enumeration into a flaky failure.
  const DWORD bogus = static_cast<DWORD>(-1);
  CHECK(get_process_name(bogus).empty());
  const auto pids = enumerate_pids();
  CHECK(std::find(pids.begin(), pids.end(), bogus) == pids.end());
  CHECK(!process_short_name(bogus).has_value());
}

// --------------------------------------------- scope-bound publication (C4) --

namespace {

// The shape do_client() has in the injectee: a plain pointer slot, an object
// whose fields are written BEFORE it is published, and reader threads that test
// the slot and then use what they tested.
struct scoped_object {
  std::uint64_t a = 0;
  std::uint64_t b = 0;
};

constexpr std::uint64_t k_scope_stamp = 0x0C4E40DE00000000ull;

alignas(void *) scoped_object *scope_slot = nullptr;

} // namespace

void a_scope_bind_publishes_the_slot_and_retires_it() {
  // Sequential contract first: the bind is visible, the scope end clears it,
  // and rebinding works after a retirement (the ordering in scope_ptr_bind is
  // release on both ends, so a later acquire cannot see a stale non-null).
  scoped_object first{}, second{};
  first.a = k_scope_stamp;
  first.b = k_scope_stamp + 1;
  second.a = k_scope_stamp;
  second.b = k_scope_stamp + 1;

  CHECK(load_scope(scope_slot) == nullptr);

  {
    scope_ptr_bind bind(scope_slot, &first);
    CHECK(load_scope(scope_slot) == &first);
    if (auto *got = load_scope(scope_slot)) {
      CHECK(got->a == k_scope_stamp);           // published payload is visible
      CHECK(got->b == got->a + 1);
    }
  }
  CHECK(load_scope(scope_slot) == nullptr);

  {
    scope_ptr_bind bind(scope_slot, &second);
    CHECK(load_scope(scope_slot) == &second);
  }
  CHECK(load_scope(scope_slot) == nullptr);
}

void a_racing_read_uses_the_one_value_it_tested() {
  // The property C4 actually fixed, pinned: a reader performs ONE load, so the
  // pointer it tested is the pointer it dereferences.  Four fully initialised
  // objects cycle through the slot, each published and retired thousands of
  // times, while three readers hammer load_scope().  Anything other than "null"
  // or "one of these four, with its own invariant intact" is a torn or stale or
  // reloaded read -- and the old two-read shape produced exactly that: the
  // second read coming back null after the first said non-null.
  scoped_object pool[4];
  for (auto &o : pool) {
    o.a = k_scope_stamp;
    o.b = k_scope_stamp + 1;
  }

  std::atomic<bool> stop{false};
  std::atomic<long> good{0}, garbage{0}, torn{0};

  std::thread binder([&] {
    for (int round = 0; round < 3000 && !stop.load(); ++round) {
      {
        scope_ptr_bind bind(scope_slot, &pool[round & 3]);
        // Hold each publication long enough that an unscheduled reader still
        // gets to observe it; yield rather than sleep to keep the test under
        // the millisecond scale.
        for (int hold = 0; hold < 64; ++hold) {
          std::this_thread::yield();
        }
      }
      // and the gap where the slot is null is the retirement half of the race
      for (int gap = 0; gap < 8; ++gap) {
        std::this_thread::yield();
      }
    }
    stop.store(true);
  });

  auto reader = [&] {
    while (!stop.load(std::memory_order_relaxed)) {
      if (auto *got = load_scope(scope_slot)) {
        const bool one_of_ours = got == &pool[0] || got == &pool[1] ||
                                got == &pool[2] || got == &pool[3];
        if (!one_of_ours) {
          garbage.fetch_add(1, std::memory_order_relaxed);
        } else if (got->a != k_scope_stamp || got->b != got->a + 1) {
          torn.fetch_add(1, std::memory_order_relaxed);
        } else {
          good.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
  };
  std::thread r1(reader), r2(reader), r3(reader);
  binder.join();
  r1.join();
  r2.join();
  r3.join();

  CHECK_EQ(garbage.load(), 0L); // no read produced a pointer outside the pool
  CHECK_EQ(torn.load(), 0L);    // no read saw an object before its fields did
  // The race really ran: readers observed publications, and the test above is
  // not a tautology about an idle slot.
  CHECK(good.load() > 0);
  CHECK(load_scope(scope_slot) == nullptr); // every bind was retired
}

int main() {
  RUN(wildcard_star);
  RUN(wildcard_question);
  RUN(wildcard_separator_equivalence);
  RUN(wildcard_case_folding);
  RUN(regex_icase_and_anchoring);
  RUN(regex_separator_alternation);
  RUN(regex_invalid_pattern_is_false);
  RUN(replace_all_cases);
  RUN(trim_in_place);
  RUN(trim_copy_variants);
  RUN(all_of_digit_cases);
  RUN(port_mapping_name_contract);
  RUN(endpoint_host_and_port);
  RUN(endpoint_credentials);
  RUN(endpoint_ipv6_host);
  RUN(endpoint_without_a_username_has_no_credentials);
  RUN(endpoint_credential_length_caps);
  RUN(endpoint_rejects_garbage);
  RUN(a_glued_proxy_url_keeps_the_authority_and_loses_the_login);
  RUN(an_authority_with_no_userinfo_keeps_every_byte);
  RUN(a_token_holding_nothing_but_a_secret_collapses_to_the_prefix);
  RUN(a_non_proxy_unknown_argument_passes_through_unchanged);
  RUN(only_a_proxy_flag_spelling_reads_as_a_proxy_flag);
  RUN(an_empty_previous_snapshot_reports_everything);
  RUN(an_unchanged_snapshot_reports_nothing);
  RUN(a_reappearing_pid_is_reported_again);
  RUN(results_are_ascending_and_duplicate_free);
  RUN(the_snapshot_contains_this_process);
  RUN(the_short_name_of_this_process_is_its_stem);
  RUN(a_pid_that_cannot_be_opened_has_no_name);
  RUN(a_spawned_child_is_named_while_it_survives);
  RUN(the_snapshot_failure_sentinel_is_not_null);
  RUN(a_bogus_pid_is_enumerated_and_never_found);
  RUN(a_scope_bind_publishes_the_slot_and_retires_it);
  RUN(a_racing_read_uses_the_one_value_it_tested);
  return test_failures;
}
