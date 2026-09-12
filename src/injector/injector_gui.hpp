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

#ifndef ENCAPSULE_INJECTOR_INJECTOR_GUI
#define ENCAPSULE_INJECTOR_INJECTOR_GUI

#include "server.hpp"
#include "ui_elements/dynamic_list.hpp"
#include "ui_elements/text_box.hpp"
#include "ui_elements/tooltip.hpp"

#include "utils.hpp"
#include "version.hpp"
#include <elements.hpp>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string_view>

namespace ce = cycfi::elements;

auto constexpr bg_color = ce::rgba(35, 35, 37, 255);

constexpr auto bred = ce::colors::red.opacity(0.4);
constexpr auto bblue = ce::colors::blue.opacity(0.4);
constexpr auto brblue = ce::colors::royal_blue.opacity(0.4);
constexpr auto bcblue = ce::colors::cornflower_blue.opacity(0.4);

using process_vector = std::vector<std::pair<DWORD, std::string>>;

struct injectee_session_ui : injectee_session {
  injectee_session_ui(tcp::socket socket, injector_server &server,
                      ce::view &view_, process_vector &vec_, auto &list_,
                      auto &log_)
      : injectee_session(std::move(socket), server), view_(view_), vec_(vec_),
        list_(list_), log_(log_) {}

  ce::view &view_;
  process_vector &vec_;

  ce::dynamic_list_s &list_;
  ce::selectable_text_box &log_;

  asio::awaitable<void> process_connect(const InjecteeConnect &msg) override {
    auto curr_time = std::chrono::system_clock::now();
    auto curr_sec = std::chrono::system_clock::to_time_t(curr_time);
    auto curr_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        curr_time.time_since_epoch());
    auto curr_milli_part = curr_ms.count() % 1000;

    std::stringstream stream;
    stream << "["
           << std::put_time(std::localtime(&curr_sec), "%Y-%m-%d %H:%M:%S")
           << "." << std::setfill('0') << std::setw(3) << curr_milli_part
           << "] ";
    stream << (int)pid_ << ": " << *msg["syscall"_f] << " " << *msg["addr"_f];
    if (auto v = msg["proxy"_f])
      stream << " via " << *v;
    stream << "\n";

    view_.post([&log = log_, str = stream.str()] {
      log.set_text(log.get_text() + str);
    });
    view_.refresh();

    co_return;
  }

  asio::awaitable<void> process_pid() override {
    vec_.emplace_back(pid_, get_process_name(pid_));
    refresh();
    co_return;
  }

  void process_close() override {
    auto iter = std::find_if(vec_.begin(), vec_.end(), [this](auto &&pair) {
      return pair.first == pid_;
    });
    if (iter != vec_.end()) {
      vec_.erase(iter);
      refresh();
    }
  }

  void refresh() {
    std::sort(vec_.begin(), vec_.end());
    view_.post([&list = list_, &vec = vec_] { list.resize(vec.size()); });
    view_.refresh();
  }
};

template <typename T> auto make_tip_below(T &&element, const std::string &tip) {
  return ce::tooltip_below(
      std::forward<T>(element),
      ce::layer(ce::margin({20, 8, 20, 8}, ce::label(tip)), ce::panel{}));
}

template <typename T>
auto make_tip_below_r(T &&element, const std::string &tip) {
  auto res = make_tip_below(std::forward<T>(element), tip);

  res.location = [](const ce::rect &wh, const ce::rect &ctx) {
    return wh.move_to(ctx.right - wh.right, ctx.bottom);
  };

  return res;
}

const std::vector<std::pair<std::string_view, std::string_view>> input_tips{
    {"pid", "a process ID (e.g. `2333`)"},
    {"name",
     "a process name with wildcard matching (e.g. `python`, `py*`, `py??on`)"},
    {"name regexp",
     "a regular expression for process name (e.g. `python`, `py.*|firefox`)"},
    {"path", "a process full path with wildcard matching (e.g. "
             "`C:/program.exe`, `C:/programs/*.exe`)"},
    {"path regexp", "a regular expression for process full path (e.g. "
                    "`C:/program.exe`, `C:/programs/(a|b).*`)"},
    {"exec",
     "command line (e.g. `python`, `C:/programs/something --some-option`)"}};

const std::map<std::string_view, std::string_view>
    input_tip_texts(input_tips.begin(), input_tips.end());

const std::vector<std::string_view> input_tip_options = [] {
  std::vector<std::string_view> result;

  for (const auto &[key, _] : input_tips) {
    result.emplace_back(key);
  }

  return result;
}();

// The address box is free text, so it gets a length bound before a parser
// sees it.  Not a grammar rule and no cap borrowed from <utils.hpp>, which has
// none: no numeric address is anywhere near this long (15 characters for IPv4,
// 45 for IPv6), so what exceeds it is a paste that went wrong, not a proxy to
// reach.  Refusing it by length, in its own words, is also what stops the
// generic "not an address" line from being the only thing a 300-character box
// can say.
constexpr std::size_t proxy_host_max_length = 255;

// The same bound for the pid box: a DWORD is 32 bits, and the widest value one
// can hold -- 4294967295 -- is ten digits.  Ten digits also fit a uint64_t
// twelve times over, so the accumulation below has nothing to overflow.
constexpr std::size_t process_id_max_digits = 10;

// The pid box, parsed the way the port of the proxy panel is: compared against
// '0'..'9' rather than handed to std::isdigit (whose argument is a signed char
// here, and every byte above 0x7f is outside its domain), bounded by
// `process_id_max_digits` before any arithmetic, and never passed to
// `std::stoul` -- which throws `out_of_range` at the eleventh digit, out of a
// click handler, on the thread that owns the window.  Returns null and fills
// `out`, or returns fixed text naming the refusal; what was typed is never in
// it, because a paste gone wrong belongs in nobody's log.
inline const char *parse_process_id(const std::string &text, DWORD &out) {
  constexpr const char *bad_id =
      "the process id must be a number from 1 to 4294967295";

  if (text.empty())
    return "no process id was entered";
  if (text.size() > process_id_max_digits)
    return bad_id;

  std::uint64_t value = 0;
  for (const char digit : text) {
    if (digit < '0' || digit > '9') {
      return bad_id;
    }
    value = value * 10 + static_cast<std::uint64_t>(digit - '0');
  }
  if (value == 0 || value > 0xFFFFFFFFull) {
    return bad_id; // 0 is "no process", not a process
  }

  out = static_cast<DWORD>(value);
  return nullptr;
}

auto make_controls(injector_server &server, ce::view &view,
                   process_vector &process_vec) {
  using namespace ce;

  // Created before every handler that can refuse a click, because this log is
  // the only text the window can make the user see: a rejection nobody reads is
  // a silent failure, and a silent failure in a tool that injects into other
  // processes is an outage with no report.
  auto log_box = share(selectable_text_box(""));

  // One refusal, one shape: a FIXED line, panel-tagged, appended to that log,
  // then a repaint.  Guarded inside, because the handlers below report from
  // within a `catch` -- and a throw on the way out of a catch ends the process
  // exactly like one that was never caught at all.  The growing log is the
  // realistic thing to fail here: this box keeps every line the tool has
  // reported since it started.
  // log_box is copied, not captured by reference: this closure is copied into
  // the handlers below and lives in the widget tree, so it outlives this
  // function, and a reference to a local shared_ptr would dangle on the first
  // refusal.  view is a reference parameter, so binding to it is safe.
  auto report = [log_box, &view](std::string_view panel, std::string_view why) {
    try {
      auto line = log_box->get_text() + std::string(panel) + " " +
                  std::string(why) + "\n";
      log_box->set_text(line);
      view.refresh();
    } catch (...) {
    }
  };

  // The backstop for the clicks that cannot be refused by validating first: an
  // allocation that fails, a throw from inside asio, protopuf or the injector,
  // a std::regex giving up in some way its own catch does not name.  The line
  // to show is a literal at every call site, so nothing about the click has to
  // be guessed at -- and nothing of it is printed.
  auto guarded = [report](auto &&action, std::string_view panel,
                          const char *line) {
    try {
      action();
    } catch (...) {
      report(panel, line);
    }
  };

  auto [process_input, process_input_ptr] =
      input_box(std::string(input_tip_texts.at("pid")));

  auto [input_select, input_select_ptr] = selection_menu(
      [process_input_ptr, report](auto str) {
        // Picking from this menu is a click, and this was a throwing map
        // lookup inside one.  `str` comes back from the widget rather than
        // from here, so the key is nobody's promise: `input_tip_texts` and the
        // menu are built from the same table today, but a lookup that cannot
        // fail should not be one that ends the process if it ever can.
        auto tip = input_tip_texts.find(str);
        if (tip != input_tip_texts.end()) {
          process_input_ptr->_placeholder = tip->second;
        } else {
          report("[process]", "that process selector is not known");
        }
      },
      input_tip_options);

  // CLI `-w` parity: give a launched console process its own console window.
  // Unchecked (the default) keeps the current flags == 0 behavior.
  auto new_console_toggle = share(check_box("new console"));

  auto inject_click =
      [input_select_ptr, process_input_ptr, new_console_toggle,
       report]<typename F>(F &&f) {
    auto text = trim_copy(process_input_ptr->get_text());
    if (text.empty()) {
      // A click with nothing in the box used to do nothing at all, which is
      // indistinguishable from a click that was refused for a reason.  It is a
      // refusal, so it now says so, in the same fixed-text shape as the rest.
      report("[process]", "no process id, name, path or command was entered");
      return;
    }
    auto option = input_select_ptr->get_text();
    if (option == "pid") {
      // Where this stood, `all_of_digit` then `std::stoul`: the first leans on
      // `std::isdigit` with a signed char, and the second throws
      // `out_of_range` at the eleventh digit -- a number the box accepts, since
      // a run of digits is exactly what a pid looks like.  `parse_process_id`
      // is both checks done without either hazard, and its refusal is a line in
      // the log instead of the end of the process.
      DWORD pid = 0;
      if (const char *why = parse_process_id(text, pid)) {
        report("[process]", why);
        return;
      }

      if (!std::forward<F>(f)(pid))
        return;
    } else if (option == "name") {
      bool success = false;
      injector::pid_by_name_wildcard(text, [&success, &f](DWORD pid) {
        if (std::forward<F>(f)(pid))
          success = true;
      });
      if (!success)
        return;
    } else if (option == "name regexp") {
      bool success = false;
      injector::pid_by_name_regex(text, [&success, &f](DWORD pid) {
        if (std::forward<F>(f)(pid))
          success = true;
      });
      if (!success)
        return;
    } else if (option == "path") {
      bool success = false;
      injector::pid_by_path_wildcard(text, [&success, &f](DWORD pid) {
        if (std::forward<F>(f)(pid))
          success = true;
      });
      if (!success)
        return;
    } else if (option == "path regexp") {
      bool success = false;
      injector::pid_by_path_regex(text, [&success, &f](DWORD pid) {
        if (std::forward<F>(f)(pid))
          success = true;
      });
      if (!success)
        return;
    } else if (option == "exec") {
      DWORD creation_flags =
          new_console_toggle->value() ? CREATE_NEW_CONSOLE : 0;
      auto res = create_process(text, creation_flags);
      if (!res) {
        return;
      }

      if (!std::forward<F>(f)(res->dwProcessId)) {
        return;
      }
    }
    process_input_ptr->set_text("");
  };

  // The two buttons share everything but the operation, and both need the same
  // backstop: past the parse there is a process enumeration, a regex the user
  // wrote, a `CreateProcessW` argument built from a paste, and an injector
  // that allocates.  None of it can be refused by validating the box first, so
  // it is caught, and the line naming it is a literal.
  auto inject_button = icon_button(icons::plus, 1.2, bblue);
  inject_button.on_click = [&server, inject_click, guarded](bool) {
    guarded(
        [&] { inject_click([&server](DWORD x) { return server.inject(x); }); },
        "[process]", "the process was not added");
  };

  auto remove_button = icon_button(icons::cancel, 1.2, bred);
  remove_button.on_click = [&server, inject_click, guarded](bool) {
    guarded(
        [&] { inject_click([&server](DWORD x) { return server.close(x); }); },
        "[process]", "the process was not removed");
  };

  auto process_list = share(dynamic_list_s(basic_cell_composer(
      process_vec.size(), [&process_vec](size_t index) -> element_ptr {
        if (index < process_vec.size()) {
          auto [pid, name] = process_vec[index];
          return share(align_center(
              htile(hsize(80, align_center(label(std::to_string(pid)))),
                    hmin_size(120, align_center(label(name))))));
        }
        return share(align_center(label("unknown")));
      })));

  auto [addr_input, addr_input_ptr] = input_box("IP address");
  auto [port_input, port_input_ptr] = input_box("port");
  auto [user_input, user_input_ptr] = input_box("username");
  auto [pass_input, pass_input_ptr] = input_box("password");

  auto proxy_toggle = share(toggle_icon_button(icons::power, 1.2, brblue));
  proxy_toggle->on_click = [&server, proxy_toggle, report, addr_input_ptr,
                            port_input_ptr, user_input_ptr,
                            pass_input_ptr](bool on) {
    // This handler answers a click on the UI thread, so an exception that
    // escapes it is not an error message -- it is the injector process dying,
    // taking the control channel of every already-injected process with it.
    // Every field it reads is free text, and the conversions they fed either
    // throw or silently narrow, so: validate every one of them against the
    // rules the CLI applies to `-p`, through parsers that report rather than
    // throw, and catch whatever is left.  A refusal snaps the toggle back
    // (what a rejected click has always looked like) and puts one line in the
    // log below.  No user text is echoed into it: the address box
    // takes free input too, and `user:pass@host` pasted there is a password
    // the log would keep on screen.
    // Every refusal in this handler is one of these: the toggle back off, and
    // one fixed line in the log.  The write that snaps the toggle is covered
    // too, because `refuse` is also what runs from the `catch` below -- and
    // what is escaping a catch there is the same death this whole block exists
    // to prevent.  `report` guards its own log write and repaint.
    auto refuse = [&](std::string_view why) {
      try {
        proxy_toggle->value(false);
      } catch (...) {
      }
      report("[proxy]", why);
    };

    try {
      if (!on) {
        server.clear_proxy();
        return;
      }

      auto addr = trim_copy(addr_input_ptr->get_text());
      auto port = trim_copy(port_input_ptr->get_text());
      // A username gets trimmed: a space around a name is a slip of the
      // keyboard.  A password does not: credentials are raw strings whose
      // every character counts, and trimming one would authenticate with a
      // secret nobody typed -- worse than any typo this could hide.
      auto user = trim_copy(user_input_ptr->get_text());
      auto pass = pass_input_ptr->get_text();

      // schema.hpp:88-89 assigns the length caps to the frontends, so this
      // panel is where they belong.  Both lengths travel in a single octet, so
      // an over-long credential can never reach a server: accepting it here
      // would leave the injectee building no auth request at all, every
      // connect of the process refused, and not one word said anywhere.
      if (user.size() > proxy_credential_max_length ||
          pass.size() > proxy_credential_max_length) {
        return refuse("username and password must each be at most " +
                      std::to_string(proxy_credential_max_length) +
                      " characters");
      }

      if (addr.empty() || port.empty()) {
        return refuse("an IP address and a port are both required");
      }

      // Digits, at most as long as the widest port, and a value 16 bits can
      // hold -- the same three rules `parse_proxy_url` applies to the port of
      // `-p` (utils.hpp:251-266), applied the same way: accumulated digit by
      // digit rather than handed to a converter.  `std::stoul` was the second
      // thrower in this handler, `out_of_range` at the eleventh digit, and no
      // amount of preceding checking makes a throwing call the right one on a
      // UI thread -- so there is none left here.  Bounding the length by
      // `proxy_port_max_length` first is what makes the accumulation
      // overflow-free; the range bound then stops 99999 from being truncated
      // to 34463 on its way to the wire (server.hpp takes a uint32_t,
      // schema.hpp stores a uint16_t), and port 0, which means "no port" and
      // not an endpoint.  A port that is not digits at all -- "1080abc", "+1",
      // "1_0" -- falls out of the same loop, one fixed line for all of them.
      constexpr const char *bad_port =
          "the port must be a number from 1 to 65535";
      if (port.size() > proxy_port_max_length) {
        return refuse(bad_port);
      }
      std::uint32_t port_value = 0;
      for (const char digit : port) {
        if (digit < '0' || digit > '9') {
          return refuse(bad_port);
        }
        port_value = port_value * 10 + static_cast<std::uint32_t>(digit - '0');
      }
      if (port_value == 0 || port_value > 65535) {
        return refuse(bad_port);
      }

      if (addr.size() > proxy_host_max_length) {
        return refuse("the proxy address is too long to be an IP address");
      }

      // A bracketed IPv6 host is the spelling every endpoint of this tool
      // takes -- `parse_proxy_url` takes the brackets off `-p` before it
      // parses a thing (utils.hpp:221-231) -- so the box accepts it too, since
      // refusing here would reject a string the CLI accepts.  Any bracket that
      // is not a matching pair around a non-empty host ("[::1", "a]b") stays
      // in place: the parser below refuses it, which is also what
      // `parse_proxy_url` does with a stray one.
      if (addr.front() == '[' && addr.size() > 2 && addr.back() == ']') {
        addr = addr.substr(1, addr.size() - 2);
      }

      // The numeric test is the CLI's own `ip::make_address` call, through
      // the overload that reports failure in `error_code`.  What stood here
      // before, `ip::address::from_string` -- deprecated exactly because it
      // throws -- ended the process on a hostname, which is the one thing a
      // box labelled "address" invites.  Nothing resolves a name on this path:
      // IpAddr carries an address, never a name, so a name is refused here
      // rather than becoming a crash or a half-configured proxy.
      asio::error_code ec;
      auto ip_addr = ip::make_address(addr, ec);
      if (ec) {
        return refuse("the proxy address must be a numeric IPv4 or IPv6 "
                      "address; names are not resolved here");
      }

      server.set_proxy(ip_addr, port_value);

      // Credentials follow the same apply path as the address. A password
      // without a username is ignored, matching the CLI; an empty field
      // means "unset", never an empty string.
      if (user.empty()) {
        server.clear_proxy_credentials();
      } else if (pass.empty()) {
        server.set_proxy_credentials(std::move(user), std::nullopt);
      } else {
        server.set_proxy_credentials(std::move(user), std::move(pass));
      }
    } catch (...) {
      // The backstop for whatever the checks above do not foresee: an
      // allocation that fails behind a megabyte of pasted text, a throw from
      // inside asio or protopuf on the apply path.  Fixed text again -- an
      // exception's `what()` is the one string in this handler nobody
      // reviewed, and a converter is free to put whatever it was handed into
      // it, which is exactly the byte the log must never keep on screen.
      // `refuse` cannot throw on its way out, so nothing is left to escape.
      refuse("the proxy settings were not applied");
    }
  };

  // Three more clicks that take no input to validate and still allocate, or
  // reach into asio and protopuf to push a config: the same backstop, with a
  // literal line each, so the answer to "why is the log still empty?" is never
  // a window that quietly stopped being there.
  auto log_toggle = toggle_icon_button(icons::doc, 1.2, brblue);
  log_toggle.on_click = [&server, guarded](bool on) {
    guarded([&] { server.enable_log(on); }, "[proxy]",
            "the connection log was not switched");
  };

  auto subprocess_toggle = toggle_icon_button(icons::record, 1.2, brblue);
  subprocess_toggle.on_click = [&server, guarded](bool on) {
    guarded([&] { server.enable_subprocess(on); }, "[proxy]",
            "subprocess injection was not switched");
  };

  auto clean_button = icon_button(icons::trash, 1.2, bcblue);
  clean_button.on_click = [log_box, guarded](bool) {
    guarded([&] { log_box->set_text(""); }, "[proxy]",
            "the log was not cleared");
  };

  auto info_button = icon_button(icons::info, 1.2, bcblue);
  info_button.on_click = [&view, guarded](bool) {
    guarded(
        [&] {
          view.add(message_box1(view, encapsule_copyright(encapsule_version),
                                icons::info, [] {}));
        },
        "[proxy]", "the information box did not open");
  };

  // clang-format off
  return std::make_tuple(
      margin({10, 10, 10, 10},
        htile(
          hmin_size(200, 
            vtile(
              htile(
                hsize(80, input_select),
                left_margin(5, hmin_size(100, process_input)),
                left_margin(10, make_tip_below(inject_button, "add specific processes to inject")), 
                left_margin(5, make_tip_below(remove_button, "remove specific processes from injecting")),
                left_margin(10,
                  make_tip_below(hold(new_console_toggle),
                    "create a new console window for the launched process"))
              ),
              top_margin(10, 
                vmin_size(250, 
                  layer(vscroller(hold(process_list)), frame())
                )
              )
            )
          ),
          left_margin(10,
            hmin_size(200, 
              vtile(
                htile(
                  hmin_size(100, addr_input),
                  left_margin(5, hsize(100, port_input)),
                  left_margin(5, hmin_size(100, user_input)),
                  left_margin(5, make_tip_below_r(hmin_size(100, pass_input),
                    "proxy password - NOT masked (elements has no"
                    " password box): it stays visible on screen,"
                    " beware of shoulder-surfing; credentials are"
                    " held in memory only, never logged")),
                  left_margin(10, make_tip_below_r(hold(proxy_toggle), "enable/disable proxy injection")),
                  left_margin(5, make_tip_below_r(log_toggle, "enable/disable connection log")),
                  left_margin(5, make_tip_below_r(subprocess_toggle, "enable/disable subprocess injection")),
                  left_margin(8, make_tip_below_r(clean_button, "clean the logging box")),
                  left_margin(5, make_tip_below_r(info_button, "software information"))
                ),
                top_margin(10,
                  vmin_size(250, 
                    layer(vscroller(hold(log_box)), frame())
                  )
                )
              )
            )
          )
        )
      ), process_list, log_box);
  // clang-format on
}

#endif
