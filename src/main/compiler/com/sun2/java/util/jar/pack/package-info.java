/*
 * Copyright (c) 2003, 2011, Oracle and/or its affiliates. All rights reserved.
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

/**
 * This package provides methods to read files from a JAR file and to
 * transform them to a more compact transfer format called Pack200.
 * It also provides methods to receive the transmitted data and expand
 * it into a JAR file equivalent to the original JAR file.
 *
 * <p>
 * The {@code pack} methods may be used by application developers who
 * wish to deploy large JARs on the web.  The {@code unpack} methods
 * may be used by deployment applications such as Java Web Start and
 * Java Plugin.
 *
 * <p>
 * In typical use, the packed output should be further compressed
 * using a suitable tool such as gzip or
 * {@code java.util.zip.GZIPOutputStream}.  The resulting file (with
 * a suffix ".pack.gz") should be hosted on a HTTP/1.1 compliant
 * server, which will be capable of handling "Accept-Encoding", as
 * specified by the HTTP 1.1 RFC2616 specification.
 *
 * <p>
 * <b>NOTE:</b> It is recommended that the original ".jar" file be
 * hosted in addition to the ".pack.gz" file, so that older client
 * implementations will continue to work reliably.  (On-demand
 * compression by the server is not recommended.)
 *
 * <p>
 * When a client application requests a ".jar" file (call it
 * "Large.jar"), the client will transmit the headers
 * "Content-Type=application/x-java-archive" as well as
 * "Accept-Encoding=pack200-gzip".  This indicates to the server that
 * the client application desires an version of the file encoded with
 * Pack200 and further compressed with gzip.
 *
 * <p>
 * The server implementation will typically check for the existence of
 * "Large.pack.gz".  If that file is available, the server will
 * transmit it with the headers "Content-Encoding=pack200-gzip" and
 * "Content-Type=application/x-java-archive".
 *
 * <p>
 * If the ".pack.gz" file, is not available, then the server will
 * transmit the original ".jar" with "Content-Encoding=null" and
 * "Content-Type=application/x-java-archive".
 *
 * <p>
 * A MIME type of "application/x-java-pack200" may be specified by the
 * client application to indicate a ".pack" file is required.
 * However, this has limited capability, and is not recommended.
 *
 * <h2> Package Specification</h2>
 * Network Transfer Format Specification :<a href="http://jcp.org/en/jsr/detail?id=200">
 * http://jcp.org/en/jsr/detail?id=200</a>
 *
 * <h2> Related Documentation</h2>
 * For overviews, tutorials, examples, guides, and tool documentation, please
 * see:
 * <ul>
 *
 * <li>
 * Jar File Specification :<a href="http://java.sun2.com/j2se/1.3/docs/guide/jar/jar.html">
 * http://java.sun2.com/j2se/1.3/docs/guide/jar/jar.html</a></li>
 *
 * <li>
 * Class File Specification: Chapter 4 of
 * <em>The Java&trade; Virtual Machine Specification</em>
 *
 * <li>
 * Hypertext Transfer Protocol -- HTTP/1.1 : <a href="http://www.ietf.org/rfc/rfc2616.txt">
 * http://www.ietf.org/rfc/rfc2616.txt
 * </ul>
 *
 * <li>
 * @since 1.5</li>
 */
package com.sun2.java.util.jar.pack;
