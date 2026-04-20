// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

package libddrc

/*
#cgo LDFLAGS: -L../../target/debug -lrc_x509_test_harness -Wl,-rpath,${SRCDIR}/../../target/debug
#include <stdlib.h>
#include "libdd_rc_test_harness.h"

extern struct Ctx *rc_init_test(void);
*/
import "C"

// NewTestClient create client with echo test harness.
// Echo respond with Pong to all messages. Good for test FFI layer.
//
// This use rc_init_test() function from FFI library.
func NewTestClient() *Client {
	c := &Client{ctx: C.rc_init_test()}
	return c
}
