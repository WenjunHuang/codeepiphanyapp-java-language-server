/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
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

package sun2.net.util;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.InetSocketAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;

import sun2.security.util.SecurityProperties;

public final class SocketExceptions {
    private SocketExceptions() {}

    private static final boolean enhancedExceptionText =
        SecurityProperties.includedInExceptions("hostInfo");

    /**
     * Utility which takes an exception and returns either the same exception
     * or a new exception of the same type with the same stack trace
     * and detail message enhanced with addressing information from the
     * given InetSocketAddress.
     *
     * If the system/security property "jdk2.includeInExceptions" is not
     * set or does not contain the category hostInfo,
     * then the original exception is returned.
     *
     * Only specific IOException subtypes are supported.
     */
    public static IOException of(IOException e, InetSocketAddress address) {
        if (!enhancedExceptionText || address == null)
            return e;
        int port = address.getPort();
        String host = address.getHostString();
        StringBuilder sb = new StringBuilder();
        sb.append(e.getMessage());
        sb.append(": ");
        sb.append(host);
        sb.append(':');
        sb.append(Integer.toString(port));
        String enhancedMsg = sb.toString();
        return create(e, enhancedMsg);
    }

    // return a new instance of the same type with the given detail
    // msg, or if the type doesn't support detail msgs, return given
    // instance.

    private static IOException create(IOException e, String msg) {
        return AccessController.doPrivileged(new PrivilegedAction<IOException>() {
            public IOException run() {
                try {
                    Class<?> clazz = e.getClass();
                    Constructor<?> ctor = clazz.getConstructor(String.class);
                    IOException e1 = (IOException)(ctor.newInstance(msg));
                    e1.setStackTrace(e.getStackTrace());
                    return e1;
                } catch (Exception e0) {
                    // Some eg AsynchronousCloseException have no detail msg
                    return e;
                }
            }
        });
    }
}
