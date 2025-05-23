/*
 * Copyright (c) 1998, 1999, Oracle and/or its affiliates. All rights reserved.
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

package sun2.security.pkcs;

import java.io.*;
import sun2.security.x509.*;
import sun2.security.util.DerValue;
import sun2.security.util.DerOutputStream;

/**
 * This class implements the <code>EncryptedPrivateKeyInfo</code> type,
 * which is defined in PKCS #8 as follows:
 *
 * <pre>
 * EncryptedPrivateKeyInfo ::=  SEQUENCE {
 *     encryptionAlgorithm   AlgorithmIdentifier,
 *     encryptedData   OCTET STRING }
 * </pre>
 *
 * @author Jan Luehe
 *
 */

public class EncryptedPrivateKeyInfo {

    // the "encryptionAlgorithm" field
    private AlgorithmId algid;

    // the "encryptedData" field
    private byte[] encryptedData;

    // the ASN.1 encoded contents of this class
    private byte[] encoded;

    /**
     * Constructs (i.e., parses) an <code>EncryptedPrivateKeyInfo</code> from
     * its encoding.
     */
    public EncryptedPrivateKeyInfo(byte[] encoded)
        throws IOException
    {
        if (encoded == null) {
            throw new IllegalArgumentException("encoding must not be null");
        }

        DerValue val = new DerValue(encoded);

        DerValue[] seq = new DerValue[2];

        seq[0] = val.data.getDerValue();
        seq[1] = val.data.getDerValue();

        if (val.data.available() != 0) {
            throw new IOException("overrun, bytes = " + val.data.available());
        }

        this.algid = AlgorithmId.parse(seq[0]);
        if (seq[0].data.available() != 0) {
            throw new IOException("encryptionAlgorithm field overrun");
        }

        this.encryptedData = seq[1].getOctetString();
        if (seq[1].data.available() != 0)
            throw new IOException("encryptedData field overrun");

        this.encoded = encoded.clone();
    }

    /**
     * Constructs an <code>EncryptedPrivateKeyInfo</code> from the
     * encryption algorithm and the encrypted data.
     */
    public EncryptedPrivateKeyInfo(AlgorithmId algid, byte[] encryptedData) {
        this.algid = algid;
        this.encryptedData = encryptedData.clone();
    }

    /**
     * Returns the encryption algorithm.
     */
    public AlgorithmId getAlgorithm() {
        return this.algid;
    }

    /**
     * Returns the encrypted data.
     */
    public byte[] getEncryptedData() {
        return this.encryptedData.clone();
    }

    /**
     * Returns the ASN.1 encoding of this class.
     */
    public byte[] getEncoded()
        throws IOException
    {
        if (this.encoded != null) return this.encoded.clone();

        DerOutputStream out = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();

        // encode encryption algorithm
        algid.encode(tmp);

        // encode encrypted data
        tmp.putOctetString(encryptedData);

        // wrap everything into a SEQUENCE
        out.write(DerValue.tag_Sequence, tmp);
        this.encoded = out.toByteArray();

        return this.encoded.clone();
    }

    public boolean equals(Object other) {
        if (this == other)
            return true;
        if (!(other instanceof EncryptedPrivateKeyInfo))
            return false;
        try {
            byte[] thisEncrInfo = this.getEncoded();
            byte[] otherEncrInfo
                = ((EncryptedPrivateKeyInfo)other).getEncoded();

            if (thisEncrInfo.length != otherEncrInfo.length)
                return false;
            for (int i = 0; i < thisEncrInfo.length; i++)
                 if (thisEncrInfo[i] != otherEncrInfo[i])
                     return false;
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Returns a hashcode for this EncryptedPrivateKeyInfo.
     *
     * @return a hashcode for this EncryptedPrivateKeyInfo.
     */
    public int hashCode() {
        int retval = 0;

        for (int i = 0; i < this.encryptedData.length; i++)
            retval += this.encryptedData[i] * i;
        return retval;
    }
}
