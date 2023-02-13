/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020-2021, Hugo Lefeuvre <hugo.lefeuvre@manchester.ac.uk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* No need to include flexos/isolation.h for this example since we don't call
 * any gate, but let's put it for good measure. */
#include <flexos/isolation.h>

#include <flexos/example/isolated.h>
#include <stdio.h>

#include <uk/sched.h>
#include <uk/thread.h>

/* note: these buffers are volatile so that accesses don't get optimized away in
 * this example
 */

/* the static buffer that we return from function2: has to be shared */
/* FIXME FLEXOS: use __section and not __attribute__((flexos_whitelist)) because
 * of a bug in Coccinelle. Revisit this later. */
static char static_buf[128] __attribute__((flexos_whitelist))
	= "Aux meilleurs esprits, Que d'erreurs promises!";

/* a private static buffer: only accessible from this compartment */
static char static_lib_secret[32] = "abcdefghijklmnopqrstuvwxyz";

static int compute_signature(char *buf)
{
	/* do some crypto stuff, touch static_lib_secret */
	return static_lib_secret[0] + buf[0];
}

/* FIXME FLEXOS: if we simply put these string literals in the code, they will
 * be stored under the microlib's section, leading to a protection domain fault
 * when printing. We have to find a way to automatically put them in the shared
 * section.
 */
static char nullbuf[100] __attribute__((flexos_whitelist)) = "buf is NULL!\n";
static char zerobuf[100] __attribute__((flexos_whitelist)) = "buf is 0!\n";

int function1(char *buf)
{
	if (!buf) {
		flexos_gate(libc, printf, &nullbuf[0]);
		/* should not happen, bug in the toolchain? */
		return 1;
	}

	if (buf[0] == 0) {
		flexos_gate(libc, printf, &zerobuf[0]);
		/* should not happen, bug in the toolchain? */
		return 2;
	}

	/* note: this should crash if we do not have access to buf */
	compute_signature(buf);

	return 0;
}

char *function2(void)
{
	return static_buf;
}

char perform_sensitive_operation() {
	return 'x';
}
