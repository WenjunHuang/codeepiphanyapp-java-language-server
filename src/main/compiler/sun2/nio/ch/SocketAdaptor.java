/*
 * Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.
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

package sun2.nio.ch;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketImpl;
import java.net.SocketOption;
import java.net.SocketTimeoutException;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.IllegalBlockingModeException;
import java.nio.channels.SocketChannel;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import static java.util.concurrent.TimeUnit.*;

// Make a socket channel look like a socket.
//
// The methods in this class are defined in exactly the same order as in
// java.net.Socket so as to simplify tracking future changes to that class.
//

class SocketAdaptor
    extends Socket
{
    // The channel being adapted
    private final SocketChannelImpl sc;

    // Timeout "option" value for reads
    private volatile int timeout;

    private SocketAdaptor(SocketChannelImpl sc) throws SocketException {
        super((SocketImpl) null);
        this.sc = sc;
    }

    public static Socket create(SocketChannelImpl sc) {
        try {
            return new SocketAdaptor(sc);
        } catch (SocketException e) {
            throw new InternalError("Should not reach here");
        }
    }

    public SocketChannel getChannel() {
        return sc;
    }

    // Override this method just to protect against changes in the superclass
    //
    public void connect(SocketAddress remote) throws IOException {
        connect(remote, 0);
    }

    public void connect(SocketAddress remote, int timeout) throws IOException {
        if (remote == null)
            throw new IllegalArgumentException("connect: The address can't be null");
        if (timeout < 0)
            throw new IllegalArgumentException("connect: timeout can't be negative");

        synchronized (sc.blockingLock()) {
            if (!sc.isBlocking())
                throw new IllegalBlockingModeException();

            try {
                // no timeout
                if (timeout == 0) {
                    sc.connect(remote);
                    return;
                }

                // timed connect
                sc.configureBlocking(false);
                try {
                    if (sc.connect(remote))
                        return;
                } finally {
                    try {
                        sc.configureBlocking(true);
                    } catch (ClosedChannelException e) { }
                }

                long timeoutNanos = NANOSECONDS.convert(timeout, MILLISECONDS);
                long to = timeout;
                for (;;) {
                    long startTime = System.nanoTime();
                    if (sc.pollConnected(to)) {
                        boolean connected = sc.finishConnect();
                        assert connected;
                        break;
                    }
                    timeoutNanos -= System.nanoTime() - startTime;
                    if (timeoutNanos <= 0) {
                        try {
                            sc.close();
                        } catch (IOException x) { }
                        throw new SocketTimeoutException();
                    }
                    to = MILLISECONDS.convert(timeoutNanos, NANOSECONDS);
                }

            } catch (Exception x) {
                Net.translateException(x, true);
            }
        }

    }

    public void bind(SocketAddress local) throws IOException {
        try {
            sc.bind(local);
        } catch (Exception x) {
            Net.translateException(x);
        }
    }

    public InetAddress getInetAddress() {
        InetSocketAddress remote = sc.remoteAddress();
        if (remote == null) {
            return null;
        } else {
            return remote.getAddress();
        }
    }

    public InetAddress getLocalAddress() {
        if (sc.isOpen()) {
            InetSocketAddress local = sc.localAddress();
            if (local != null) {
                return Net.getRevealedLocalAddress(local).getAddress();
            }
        }
        return new InetSocketAddress(0).getAddress();
    }

    public int getPort() {
        InetSocketAddress remote = sc.remoteAddress();
        if (remote == null) {
            return 0;
        } else {
            return remote.getPort();
        }
    }

    public int getLocalPort() {
        InetSocketAddress local = sc.localAddress();
        if (local == null) {
            return -1;
        } else {
            return local.getPort();
        }
    }

    private class SocketInputStream
        extends ChannelInputStream
    {
        private SocketInputStream() {
            super(sc);
        }

        protected int read(ByteBuffer bb)
            throws IOException
        {
            synchronized (sc.blockingLock()) {
                if (!sc.isBlocking())
                    throw new IllegalBlockingModeException();

                // no timeout
                long to = SocketAdaptor.this.timeout;
                if (to == 0)
                    return sc.read(bb);

                // timed read
                long timeoutNanos = NANOSECONDS.convert(to, MILLISECONDS);
                for (;;) {
                    long startTime = System.nanoTime();
                    if (sc.pollRead(to)) {
                        return sc.read(bb);
                    }
                    timeoutNanos -= System.nanoTime() - startTime;
                    if (timeoutNanos <= 0)
                        throw new SocketTimeoutException();
                    to = MILLISECONDS.convert(timeoutNanos, NANOSECONDS);
                }
            }
        }
    }

    private InputStream socketInputStream = null;

    public InputStream getInputStream() throws IOException {
        if (!sc.isOpen())
            throw new SocketException("Socket is closed");
        if (!sc.isConnected())
            throw new SocketException("Socket is not connected");
        if (!sc.isInputOpen())
            throw new SocketException("Socket input is shutdown");
        if (socketInputStream == null) {
            try {
                socketInputStream = AccessController.doPrivileged(
                    new PrivilegedExceptionAction<InputStream>() {
                        public InputStream run() throws IOException {
                            return new SocketInputStream();
                        }
                    });
            } catch (java.security.PrivilegedActionException e) {
                throw (IOException)e.getException();
            }
        }
        return socketInputStream;
    }

    public OutputStream getOutputStream() throws IOException {
        if (!sc.isOpen())
            throw new SocketException("Socket is closed");
        if (!sc.isConnected())
            throw new SocketException("Socket is not connected");
        if (!sc.isOutputOpen())
            throw new SocketException("Socket output is shutdown");
        OutputStream os = null;
        try {
            os = AccessController.doPrivileged(
                new PrivilegedExceptionAction<OutputStream>() {
                    public OutputStream run() throws IOException {
                        return Channels.newOutputStream(sc);
                    }
                });
        } catch (java.security.PrivilegedActionException e) {
            throw (IOException)e.getException();
        }
        return os;
    }

    private void setBooleanOption(SocketOption<Boolean> name, boolean value)
        throws SocketException
    {
        try {
            sc.setOption(name, value);
        } catch (IOException x) {
            Net.translateToSocketException(x);
        }
    }

    private void setIntOption(SocketOption<Integer> name, int value)
        throws SocketException
    {
        try {
            sc.setOption(name, value);
        } catch (IOException x) {
            Net.translateToSocketException(x);
        }
    }

    private boolean getBooleanOption(SocketOption<Boolean> name) throws SocketException {
        try {
            return sc.getOption(name).booleanValue();
        } catch (IOException x) {
            Net.translateToSocketException(x);
            return false;       // keep compiler happy
        }
    }

    private int getIntOption(SocketOption<Integer> name) throws SocketException {
        try {
            return sc.getOption(name).intValue();
        } catch (IOException x) {
            Net.translateToSocketException(x);
            return -1;          // keep compiler happy
        }
    }

    public void setTcpNoDelay(boolean on) throws SocketException {
        setBooleanOption(StandardSocketOptions.TCP_NODELAY, on);
    }

    public boolean getTcpNoDelay() throws SocketException {
        return getBooleanOption(StandardSocketOptions.TCP_NODELAY);
    }

    public void setSoLinger(boolean on, int linger) throws SocketException {
        if (!on)
            linger = -1;
        setIntOption(StandardSocketOptions.SO_LINGER, linger);
    }

    public int getSoLinger() throws SocketException {
        return getIntOption(StandardSocketOptions.SO_LINGER);
    }

    public void sendUrgentData(int data) throws IOException {
        int n = sc.sendOutOfBandData((byte) data);
        if (n == 0)
            throw new IOException("Socket buffer full");
    }

    public void setOOBInline(boolean on) throws SocketException {
        setBooleanOption(ExtendedSocketOption.SO_OOBINLINE, on);
    }

    public boolean getOOBInline() throws SocketException {
        return getBooleanOption(ExtendedSocketOption.SO_OOBINLINE);
    }

    public void setSoTimeout(int timeout) throws SocketException {
        if (timeout < 0)
            throw new IllegalArgumentException("timeout can't be negative");
        this.timeout = timeout;
    }

    public int getSoTimeout() throws SocketException {
        return timeout;
    }

    public void setSendBufferSize(int size) throws SocketException {
        // size 0 valid for SocketChannel, invalid for Socket
        if (size <= 0)
            throw new IllegalArgumentException("Invalid send size");
        setIntOption(StandardSocketOptions.SO_SNDBUF, size);
    }

    public int getSendBufferSize() throws SocketException {
        return getIntOption(StandardSocketOptions.SO_SNDBUF);
    }

    public void setReceiveBufferSize(int size) throws SocketException {
        // size 0 valid for SocketChannel, invalid for Socket
        if (size <= 0)
            throw new IllegalArgumentException("Invalid receive size");
        setIntOption(StandardSocketOptions.SO_RCVBUF, size);
    }

    public int getReceiveBufferSize() throws SocketException {
        return getIntOption(StandardSocketOptions.SO_RCVBUF);
    }

    public void setKeepAlive(boolean on) throws SocketException {
        setBooleanOption(StandardSocketOptions.SO_KEEPALIVE, on);
    }

    public boolean getKeepAlive() throws SocketException {
        return getBooleanOption(StandardSocketOptions.SO_KEEPALIVE);
    }

    public void setTrafficClass(int tc) throws SocketException {
        setIntOption(StandardSocketOptions.IP_TOS, tc);
    }

    public int getTrafficClass() throws SocketException {
        return getIntOption(StandardSocketOptions.IP_TOS);
    }

    public void setReuseAddress(boolean on) throws SocketException {
        setBooleanOption(StandardSocketOptions.SO_REUSEADDR, on);
    }

    public boolean getReuseAddress() throws SocketException {
        return getBooleanOption(StandardSocketOptions.SO_REUSEADDR);
    }

    public void close() throws IOException {
        sc.close();
    }

    public void shutdownInput() throws IOException {
        try {
            sc.shutdownInput();
        } catch (Exception x) {
            Net.translateException(x);
        }
    }

    public void shutdownOutput() throws IOException {
        try {
            sc.shutdownOutput();
        } catch (Exception x) {
            Net.translateException(x);
        }
    }

    public String toString() {
        if (sc.isConnected())
            return "Socket[addr=" + getInetAddress() +
                ",port=" + getPort() +
                ",localport=" + getLocalPort() + "]";
        return "Socket[unconnected]";
    }

    public boolean isConnected() {
        return sc.isConnected();
    }

    public boolean isBound() {
        return sc.localAddress() != null;
    }

    public boolean isClosed() {
        return !sc.isOpen();
    }

    public boolean isInputShutdown() {
        return !sc.isInputOpen();
    }

    public boolean isOutputShutdown() {
        return !sc.isOutputOpen();
    }
}
