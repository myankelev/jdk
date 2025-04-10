/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @bug 8349583
 * @summary Add mechanism to disable signature schemes based on their TLS scope
 * @library /javax/net/ssl/templates
 *          /test/lib
 * @run main/othervm MixingTLSUsageConstraintsWithNonTLS
 */

import static jdk.test.lib.Asserts.assertEquals;
import static jdk.test.lib.Asserts.assertTrue;
import static jdk.test.lib.Utils.runAndCheckException;

import java.security.Security;

public class MixingTLSUsageConstraintsWithNonTLS extends SSLSocketTemplate {

    public static void main(String[] args) throws Exception {
        Security.setProperty("jdk.tls.disabledAlgorithms",
                "rsa_pkcs1_sha1 usage handshakeSignature certificateSignature TLSServer");

        runAndCheckException(
                () -> new MixingTLSUsageConstraintsWithNonTLS().run(),
                e -> {
                    assertTrue(e instanceof ExceptionInInitializerError);
                    assertTrue(
                            e.getCause() instanceof IllegalArgumentException);
                    assertEquals(e.getCause().getMessage(),
                            "Can't mix TLS protocol specific constraints"
                                    + " with other usage constraints");
                });
    }
}
