/*
 * Copyright (c) 2003, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package sun2.security.jca;

import java.security.*;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import jdk2.internal.event.EventHelper;
import jdk2.internal.event.X509CertificateEvent;
import sun2.security.util.KeyUtil;

/**
 * Collection of static utility methods used by the security framework.
 *
 * @author  Andreas Sterbenz
 * @since   1.5
 */
public final class JCAUtil {

    private JCAUtil() {
        // no instantiation
    }

    // size of the temporary arrays we use. Should fit into the CPU's 1st
    // level cache and could be adjusted based on the platform
    private static final int ARRAY_SIZE = 4096;

    /**
     * Get the size of a temporary buffer array to use in order to be
     * cache efficient. totalSize indicates the total amount of data to
     * be buffered. Used by the engineUpdate(ByteBuffer) methods.
     */
    public static int getTempArraySize(int totalSize) {
        return Math.min(ARRAY_SIZE, totalSize);
    }

    // cached SecureRandom instance
    private static class CachedSecureRandomHolder {
        public static SecureRandom instance = new SecureRandom();
    }

    private static volatile SecureRandom def = null;

    /**
     * Get a SecureRandom instance. This method should be used by JDK
     * internal code in favor of calling "new SecureRandom()". That needs to
     * iterate through the provider table to find the default SecureRandom
     * implementation, which is fairly inefficient.
     */
    public static SecureRandom getSecureRandom() {
        return CachedSecureRandomHolder.instance;
    }

    // called by sun2.security.jca.Providers class when provider list is changed
    static void clearDefSecureRandom() {
        def = null;
    }

    /**
     * Get the default SecureRandom instance. This method is the
     * optimized version of "new SecureRandom()" which re-uses the default
     * SecureRandom impl if the provider table is the same.
     */
    public static SecureRandom getDefSecureRandom() {
        SecureRandom result = def;
        if (result == null) {
            synchronized (JCAUtil.class) {
                result = def;
                if (result == null) {
                    def = result = new SecureRandom();
                }
            }
        }
        return result;

    }

    public static void tryCommitCertEvent(Certificate cert) {
        if ((X509CertificateEvent.isTurnedOn() || EventHelper.isLoggingSecurity())) {
            if (cert instanceof X509Certificate) {
                X509Certificate x509 = (X509Certificate) cert;
            PublicKey pKey = x509.getPublicKey();
            String algId = x509.getSigAlgName();
            String serNum = x509.getSerialNumber().toString(16);
            String subject = x509.getSubjectX500Principal().toString();
            String issuer = x509.getIssuerX500Principal().toString();
            String keyType = pKey.getAlgorithm();
            int length = KeyUtil.getKeySize(pKey);
            int hashCode = x509.hashCode();
            long beginDate = x509.getNotBefore().getTime();
            long endDate = x509.getNotAfter().getTime();
            if (X509CertificateEvent.isTurnedOn()) {
                X509CertificateEvent xce = new X509CertificateEvent();
                xce.algorithm = algId;
                xce.serialNumber = serNum;
                xce.subject = subject;
                xce.issuer = issuer;
                xce.keyType = keyType;
                xce.keyLength = length;
                xce.certificateId = hashCode;
                xce.validFrom = beginDate;
                xce.validUntil = endDate;
                xce.commit();
            }
            if (EventHelper.isLoggingSecurity()) {
                EventHelper.logX509CertificateEvent(algId,
                        serNum,
                        subject,
                        issuer,
                        keyType,
                        length,
                        hashCode,
                        beginDate,
                        endDate);
            }
            }
        }
    }
}
