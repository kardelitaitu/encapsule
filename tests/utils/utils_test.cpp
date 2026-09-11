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
#include <cctype>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include <utils.hpp>

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
  return test_failures;
}
