/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
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

package sun2.nio.cs;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;

import static sun2.nio.cs.CharsetMapping.*;

public class MS950_HKSCS_XP extends Charset
{
    public MS950_HKSCS_XP() {
        super("x-MS950-HKSCS-XP", StandardCharsets.aliases_MS950_HKSCS_XP());
    }

    public boolean contains(Charset cs) {
        return ((cs.name().equals("US-ASCII"))
                || (cs instanceof MS950)
                || (cs instanceof MS950_HKSCS_XP));
    }

    public CharsetDecoder newDecoder() {
        return new Decoder(this);
    }

    public CharsetEncoder newEncoder() {
        return new Encoder(this);
    }

    static class Decoder extends HKSCS.Decoder {
        private static DoubleByte.Decoder ms950 =
            (DoubleByte.Decoder)new MS950().newDecoder();

        /*
         * Note current decoder decodes 0x8BC2 --> U+F53A
         * ie. maps to Unicode PUA.
         * Unaccounted discrepancy between this mapping
         * inferred from MS950/windows-950 and the published
         * MS HKSCS mappings which maps 0x8BC2 --> U+5C22
         * a character defined with the Unified CJK block
         */
        private static char[][] b2cBmp = new char[0x100][];
        static {
            initb2c(b2cBmp, HKSCS_XPMapping.b2cBmpStr);
        }

        public char decodeDoubleEx(int b1, int b2) {
            return UNMAPPABLE_DECODING;
        }

        private Decoder(Charset cs) {
            super(cs, ms950, b2cBmp, null);
        }
    }

    private static class Encoder extends HKSCS.Encoder {
        private static DoubleByte.Encoder ms950 =
            (DoubleByte.Encoder)new MS950().newEncoder();

        /*
         * Note current encoder encodes U+F53A --> 0x8BC2
         * Published MS HKSCS mappings show
         * U+5C22 <--> 0x8BC2
         */
        static char[][] c2bBmp = new char[0x100][];
        static {
            initc2b(c2bBmp, HKSCS_XPMapping.b2cBmpStr, null);
        }

        public int encodeSupp(int cp) {
            return UNMAPPABLE_ENCODING;
        }

        private Encoder(Charset cs) {
            super(cs, ms950, c2bBmp, null);
        }
    }
}
