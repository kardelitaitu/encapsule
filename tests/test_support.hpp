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

#ifndef PROXINJECT_TEST_SUPPORT
#define PROXINJECT_TEST_SUPPORT

#include <cstdio>
#include <string>

inline int test_failures = 0;

#define CHECK(expr) \
	do { \
		if (!(expr)) { \
			++test_failures; \
			std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
		} \
	} while (0)

#define CHECK_EQ(a, b) \
	do { \
		auto &&va_ = (a); \
		auto &&vb_ = (b); \
		if (!(va_ == vb_)) { \
			++test_failures; \
			std::printf("FAIL %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
		} \
	} while (0)

template <class F>
inline int run_test(const char *name, F &&fn) {
	std::printf("[RUN ] %s\n", name);
	const int before = test_failures;
	try {
		fn();
	} catch (const std::exception &e) {
		++test_failures;
		std::printf("FAIL %s: uncaught exception: %s\n", name, e.what());
	} catch (...) {
		++test_failures;
		std::printf("FAIL %s: uncaught non-standard exception\n", name);
	}
	std::printf("[DONE] %s (%d failures)\n", name, test_failures - before);
	return test_failures;
}

#define RUN(fn) run_test(#fn, fn)

#endif // PROXINJECT_TEST_SUPPORT
