/*
 * Copyright (c) 2017, 2018, Oracle and/or its affiliates. All rights reserved.
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

package sun2.security.util;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.PatternSyntaxException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import javax.crypto.spec.DHParameterSpec;
import sun2.security.action.GetPropertyAction;

/**
 * Various constants such as version number, default key length, used by
 * the JDK security/crypto providers.
 */
public final class SecurityProviderConstants {
    // Cannot create one of these
    private SecurityProviderConstants () {}

    private static final Debug debug =
        Debug.getInstance("jca", "ProviderConfig");

    // cache for provider aliases; key is the standard algorithm name
    // value is the associated aliases List
    private static final ConcurrentHashMap<String, List<String>> aliasesMap;

    // utility method for generating aliases list using the supplied
    // 'oid' and 'extraAliases', then store into "aliasesMap" cache under the
    // key 'stdName'
    private static List<String> store(String stdName, KnownOIDs oid,
            String ... extraAliases) {
        List<String> value;
        if (oid == null && extraAliases.length != 0) {
            value = List.of(extraAliases);
        } else {
            value = new ArrayList<>();
            if (oid != null) {
                value.add("OID." + oid.value());
                value.add(oid.value());
                String[] knownAliases = oid.aliases();
                if (knownAliases != null) {
                    for (String ka : knownAliases) {
                        value.add(ka);
                    }
                }
            }
            for (String ea : extraAliases) {
                value.add(ea);
            }
        }
        aliasesMap.put(stdName, value);
        return value;
    }

    // returns an aliases List for the specified algorithm name o
    // NOTE: exception is thrown if no aliases nor oid found, so
    // only call this method if aliases are expected
    public static List<String> getAliases(String o) {
        List<String> res = aliasesMap.get(o);
        if (res == null) {
            KnownOIDs e = KnownOIDs.findMatch(o);
            if (e != null) {
                return store(o, e);
            }
            ProviderException pe =
                    new ProviderException("Cannot find aliases for " + o);
            throw pe;
        }
        return res;
    }

    public static final int getDefDSASubprimeSize(int primeSize) {
        if (primeSize <= 1024) {
            return 160;
        } else if (primeSize == 2048) {
            return 224;
        } else if (primeSize == 3072) {
            return 256;
        } else {
            throw new InvalidParameterException("Invalid DSA Prime Size: " +
                primeSize);
        }
    }

    public static final int getDefDHPrivateExpSize(DHParameterSpec spec) {

        int dhGroupSize = spec.getP().bitLength();

        if (spec instanceof SafeDHParameterSpec) {
            // Known safe primes
            // use 2*security strength as default private exponent size
            // as in table 2 of NIST SP 800-57 part 1 rev 5, sec 5.6.1.1
            // and table 25 of NIST SP 800-56A rev 3, appendix D.
            if (dhGroupSize >= 15360) {
                return 512;
            } else if (dhGroupSize >= 8192) {
                return 400;
            } else if (dhGroupSize >= 7680) {
                return 384;
            } else if (dhGroupSize >= 6144) {
                return 352;
            } else if (dhGroupSize >= 4096) {
                return 304;
            } else if (dhGroupSize >= 3072) {
                return 256;
            } else if (dhGroupSize >= 2048) {
                return 224;
            } else {
                // min value for legacy key sizes
                return 160;
            }
        } else {
            // assume the worst and use groupSize/2 as private exp length
            // up to 1024-bit and use the same minimum 384 as before
            return Math.max((dhGroupSize >= 2048 ? 1024 : dhGroupSize >> 1),
                    384);
        }

    }

    public static final int DEF_DSA_KEY_SIZE;
    public static final int DEF_RSA_KEY_SIZE;
    public static final int DEF_RSASSA_PSS_KEY_SIZE;
    public static final int DEF_DH_KEY_SIZE;
    public static final int DEF_EC_KEY_SIZE;

    private static final String KEY_LENGTH_PROP =
        "jdk2.security.defaultKeySize";

    static {
        String keyLengthStr = GetPropertyAction.privilegedGetProperty
            (KEY_LENGTH_PROP);
        int dsaKeySize = 2048;
        int rsaKeySize = 2048;
        int rsaSsaPssKeySize = rsaKeySize; // default to same value as RSA
        int dhKeySize = 2048;
        int ecKeySize = 256;

        if (keyLengthStr != null) {
            try {
                String[] pairs = keyLengthStr.split(",");
                for (String p : pairs) {
                    String[] algoAndValue = p.split(":");
                    if (algoAndValue.length != 2) {
                        // invalid pair, skip to next pair
                        if (debug != null) {
                            debug.println("Ignoring invalid pair in " +
                                KEY_LENGTH_PROP + " property: " + p);
                        }
                        continue;
                    }
                    String algoName = algoAndValue[0].trim().toUpperCase();
                    int value = -1;
                    try {
                        value = Integer.parseInt(algoAndValue[1].trim());
                    } catch (NumberFormatException nfe) {
                        // invalid value, skip to next pair
                        if (debug != null) {
                            debug.println("Ignoring invalid value in " +
                                KEY_LENGTH_PROP + " property: " + p);
                        }
                        continue;
                    }
                    if (algoName.equals("DSA")) {
                        dsaKeySize = value;
                    } else if (algoName.equals("RSA")) {
                        rsaKeySize = value;
                    } else if (algoName.equals("RSASSA-PSS")) {
                        rsaSsaPssKeySize = value;
                    } else if (algoName.equals("DH")) {
                        dhKeySize = value;
                    } else if (algoName.equals("EC")) {
                        ecKeySize = value;
                    } else {
                        if (debug != null) {
                            debug.println("Ignoring unsupported algo in " +
                                KEY_LENGTH_PROP + " property: " + p);
                        }
                        continue;
                    }
                    if (debug != null) {
                        debug.println("Overriding default " + algoName +
                            " keysize with value from " +
                            KEY_LENGTH_PROP + " property: " + value);
                    }
                }
            } catch (PatternSyntaxException pse) {
                // if property syntax is not followed correctly
                if (debug != null) {
                    debug.println("Unexpected exception while parsing " +
                        KEY_LENGTH_PROP + " property: " + pse);
                }
            }
        }
        DEF_DSA_KEY_SIZE = dsaKeySize;
        DEF_RSA_KEY_SIZE = rsaKeySize;
        DEF_RSASSA_PSS_KEY_SIZE = rsaSsaPssKeySize;
        DEF_DH_KEY_SIZE = dhKeySize;
        DEF_EC_KEY_SIZE = ecKeySize;

        // Set up aliases with default mappings
        // This is needed when the mapping contains non-oid
        // aliases
        aliasesMap = new ConcurrentHashMap<>();

        store("SHA1withDSA", KnownOIDs.SHA1withDSA,
                KnownOIDs.OIW_JDK_SHA1withDSA.value(),
                KnownOIDs.OIW_SHA1withDSA.value(),
                "DSA", "SHA/DSA", "SHA-1/DSA",
                "SHA1/DSA", "SHAwithDSA", "DSAWithSHA1");

        store("DSA", KnownOIDs.DSA, KnownOIDs.OIW_DSA.value());

        store("SHA1withRSA", KnownOIDs.SHA1withRSA,
                KnownOIDs.OIW_SHA1withRSA.value());

        store("SHA-1", KnownOIDs.SHA_1);

        store("PBEWithMD5AndDES", KnownOIDs.PBEWithMD5AndDES, "PBE");

        store("DiffieHellman", KnownOIDs.DiffieHellman);

        store("AES", KnownOIDs.AES, "Rijndael");

        store("EC", KnownOIDs.EC, "EllipticCurve");

        store("X.509", null, "X509");
        store("NONEwithDSA", null, "RawDSA");
        store("DESede", null, "TripleDES");
        store("ARCFOUR", KnownOIDs.ARCFOUR);
        // For backward compatility, refer to PKCS1 mapping for RSA
        // KeyPairGenerator and KeyFactory
        store("PKCS1", KnownOIDs.PKCS1, KnownOIDs.RSA.value());
    }
}
