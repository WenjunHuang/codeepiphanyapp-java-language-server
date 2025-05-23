/*
 * Copyright (c) 1997, 2023, Oracle and/or its affiliates. All rights reserved.
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

package com.sun2.crypto.provider;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.lang.ref.Reference;
import java.security.MessageDigest;
import java.security.KeyRep;
import java.security.InvalidKeyException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;

import jdk2.internal.ref.CleanerFactory;

/**
 * This class represents a DES key.
 *
 * @author Jan Luehe
 *
 */

final class DESKey implements SecretKey {

    private static final long serialVersionUID = 7724971015953279128L;

    private byte[] key;

    /**
     * Uses the first 8 bytes of the given key as the DES key.
     *
     * @param key the buffer with the DES key bytes.
     *
     * @exception InvalidKeyException if less than 8 bytes are available for
     * the key.
     */
    DESKey(byte[] key) throws InvalidKeyException {
        this(key, 0);
    }

    /**
     * Uses the first 8 bytes in <code>key</code>, beginning at
     * <code>offset</code>, as the DES key
     *
     * @param key the buffer with the DES key bytes.
     * @param offset the offset in <code>key</code>, where the DES key bytes
     * start.
     *
     * @exception InvalidKeyException if less than 8 bytes are available for
     * the key.
     */
    DESKey(byte[] key, int offset) throws InvalidKeyException {
        if (key == null || key.length - offset < DESKeySpec.DES_KEY_LEN) {
            throw new InvalidKeyException("Wrong key size");
        }
        this.key = new byte[DESKeySpec.DES_KEY_LEN];
        System.arraycopy(key, offset, this.key, 0, DESKeySpec.DES_KEY_LEN);
        DESKeyGenerator.setParityBit(this.key, 0);

        // Use the cleaner to zero the key when no longer referenced
        final byte[] k = this.key;
        CleanerFactory.cleaner().register(this,
                () -> java.util.Arrays.fill(k, (byte)0x00));
    }

    public byte[] getEncoded() {
        // Return a copy of the key, rather than a reference,
        // so that the key data cannot be modified from outside

        // The key is zeroized by finalize()
        // The reachability fence ensures finalize() isn't called early
        byte[] result = key.clone();
        Reference.reachabilityFence(this);
        return result;
    }

    public String getAlgorithm() {
        return "DES";
    }

    public String getFormat() {
        return "RAW";
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    public int hashCode() {
        int retval = 0;
        for (int i = 1; i < this.key.length; i++) {
            retval += this.key[i] * i;
        }
        return(retval ^ "des".hashCode());
    }

    public boolean equals(Object obj) {
        if (this == obj)
            return true;

        if (!(obj instanceof SecretKey))
            return false;

        String thatAlg = ((SecretKey)obj).getAlgorithm();
        if (!(thatAlg.equalsIgnoreCase("DES")))
            return false;

        byte[] thatKey = ((SecretKey)obj).getEncoded();
        boolean ret = MessageDigest.isEqual(this.key, thatKey);
        java.util.Arrays.fill(thatKey, (byte)0x00);
        return ret;
    }

    /**
     * Restores the state of this object from the stream.
     *
     * @param  s the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    private void readObject(java.io.ObjectInputStream s)
         throws IOException, ClassNotFoundException
    {
        s.defaultReadObject();
        if ((key == null) || (key.length != DESKeySpec.DES_KEY_LEN)) {
            throw new InvalidObjectException("Wrong key size");
        }
        key = key.clone();

        DESKeyGenerator.setParityBit(key, 0);

        // Use the cleaner to zero the key when no longer referenced
        final byte[] k = key;
        CleanerFactory.cleaner().register(this,
                () -> java.util.Arrays.fill(k, (byte)0x00));
    }

    /**
     * Replace the DES key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException if a new object representing
     * this DES key could not be created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.SECRET,
                        getAlgorithm(),
                        getFormat(),
                        getEncoded());
    }
}
