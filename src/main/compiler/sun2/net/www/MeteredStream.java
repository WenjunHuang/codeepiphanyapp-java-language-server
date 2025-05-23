/*
 * Copyright (c) 1994, 2017, Oracle and/or its affiliates. All rights reserved.
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

package sun2.net.www;

import java.io.*;
import sun2.net.ProgressSource;
import sun2.net.www.http.ChunkedInputStream;


public class MeteredStream extends FilterInputStream {

    // Instance variables.
    /* if expected != -1, after we've read >= expected, we're "closed" and return -1
     * from subsequest read() 's
     */
    protected boolean closed = false;
    protected long expected;
    protected long count = 0;
    protected long markedCount = 0;
    protected int markLimit = -1;
    protected ProgressSource pi;

    public MeteredStream(InputStream is, ProgressSource pi, long expected)
    {
        super(is);

        this.pi = pi;
        this.expected = expected;

        if (pi != null) {
            pi.updateProgress(0, expected);
        }
    }

    private final void justRead(long n) throws IOException   {
        if (n == -1) {

            /*
             * don't close automatically when mark is set and is valid;
             * cannot reset() after close()
             */
            if (!isMarked()) {
                close();
            }
            return;
        }

        count += n;

        /**
         * If read beyond the markLimit, invalidate the mark
         */
        if (count - markedCount > markLimit) {
            markLimit = -1;
        }

        if (pi != null)
            pi.updateProgress(count, expected);

        if (isMarked()) {
            return;
        }

        // if expected length is known, we could determine if
        // read overrun.
        if (expected > 0)   {
            if (count >= expected) {
                close();
            }
        }
    }

    /**
     * Returns true if the mark is valid, false otherwise
     */
    private boolean isMarked() {

        if (markLimit < 0) {
            return false;
        }

        // mark is set, but is not valid anymore
        if (count - markedCount > markLimit) {
           return false;
        }

        // mark still holds
        return true;
    }

    public synchronized int read() throws java.io.IOException {
        if (closed) {
            return -1;
        }
        int c = in.read();
        if (c != -1) {
            justRead(1);
        } else {
            justRead(c);
        }
        return c;
    }

    public synchronized int read(byte b[], int off, int len)
                throws java.io.IOException {
        if (closed) {
            return -1;
        }
        int n = in.read(b, off, len);
        justRead(n);
        return n;
    }

    public synchronized long skip(long n) throws IOException {

        // REMIND: what does skip do on EOF????
        if (closed) {
            return 0;
        }

        if (in instanceof ChunkedInputStream) {
            n = in.skip(n);
        }
        else {
            // just skip min(n, num_bytes_left)
            long min = (n > expected - count) ? expected - count: n;
            n = in.skip(min);
        }
        justRead(n);
        return n;
    }

    public void close() throws IOException {
        if (closed) {
            return;
        }
        if (pi != null)
            pi.finishTracking();

        closed = true;
        in.close();
    }

    public synchronized int available() throws IOException {
        return closed ? 0: in.available();
    }

    public synchronized void mark(int readLimit) {
        if (closed) {
            return;
        }
        super.mark(readLimit);

        /*
         * mark the count to restore upon reset
         */
        markedCount = count;
        markLimit = readLimit;
    }

    public synchronized void reset() throws IOException {
        if (closed) {
            return;
        }

        if (!isMarked()) {
            throw new IOException ("Resetting to an invalid mark");
        }

        count = markedCount;
        super.reset();
    }

    public boolean markSupported() {
        if (closed) {
            return false;
        }
        return super.markSupported();
    }

    @SuppressWarnings("deprecation")
    protected void finalize() throws Throwable {
        try {
            close();
            if (pi != null)
                pi.close();
        }
        finally {
            // Call super class
            super.finalize();
        }
    }
}
