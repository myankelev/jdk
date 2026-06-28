/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 8377981
 * @library /test/lib
 * @summary check that X509CRLSelector.setDateAndTime(Instant) and
 *          getDateAndTimeInstant() are consistent with their Date-returning
 *          counterparts and that match() behaves identically for both.
 * @run junit X509CRLSelectorTest
 */

import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.time.Instant;
import java.util.Date;

import jdk.test.lib.security.CertUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class X509CRLSelectorTest {

    private static final String TEST_CRL =
            """
            -----BEGIN X509 CRL-----
            MIIBGzCBhQIBATANBgkqhkiG9w0BAQQFADAfMQswCQYDVQQGEwJVUzEQMA4GA1UE
            ChMHRXhhbXBsZRcNMDkwNDI3MDIzODA0WhcNMjgwNjI2MDIzODA0WjAiMCACAQUX
            DTA5MDQyNzAyMzgwMFowDDAKBgNVHRUEAwoBBKAOMAwwCgYDVR0UBAMCAQIwDQYJ
            KoZIhvcNAQEEBQADgYEAoarfzXEtw3ZDi4f9U8eSvRIipHSyxOrJC7HR/hM5VhmY
            CErChny6x9lBVg9s57tfD/P9PSzBLusCcHwHMAbMOEcTltVVKUWZnnbumpywlYyg
            oKLrE9+yCOkYUOpiRlz43/3vkEL5hjIKMcDSZnPKBZi1h16Yj2hPe9GMibNip54=
            -----END X509 CRL-----""";

    private static final Instant IN_RANGE =
            Instant.parse("2020-06-15T12:00:00Z");
    private static final Instant OUT_OF_RANGE =
            Instant.parse("2030-01-01T00:00:00Z");
    private static final Date IN_RANGE_DATE = Date.from(IN_RANGE);

    @Test
    public void setDateAndTimeTest() {
        final X509CRLSelector selector = new X509CRLSelector();

        selector.setDateAndTime(IN_RANGE_DATE);
        assertEquals(IN_RANGE_DATE.toInstant(),
                selector.getDateAndTimeInstant());

        selector.setDateAndTime(IN_RANGE);
        assertEquals(IN_RANGE_DATE, selector.getDateAndTime());
    }

    @Test
    public void nullInstantHandlingTest() {
        final X509CRLSelector sel = new X509CRLSelector();
        assertNull(sel.getDateAndTimeInstant());

        sel.setDateAndTime(IN_RANGE);
        sel.setDateAndTime((Instant) null);
        assertNull(sel.getDateAndTimeInstant());
        assertNull(sel.getDateAndTime());
    }

    @Test
    public void matchX509CRLTest() throws Exception {
        final X509CRL crl = CertUtils.getCRLFromString(TEST_CRL);

        final X509CRLSelector selector = new X509CRLSelector();
        selector.setDateAndTime(IN_RANGE);
        assertTrue(selector.match(crl));

        selector.setDateAndTime(OUT_OF_RANGE);
        assertFalse(selector.match(crl));

        final X509CRLSelector selectorDate = new X509CRLSelector();
        selectorDate.setDateAndTime(IN_RANGE_DATE);
        selector.setDateAndTime(IN_RANGE);
        assertEquals(selectorDate.match(crl), selector.match(crl));
    }
}
