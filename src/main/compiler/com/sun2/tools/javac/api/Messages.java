/*
 * Copyright (c) 2008, 2009, Oracle and/or its affiliates. All rights reserved.
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

package com.sun2.tools.javac.api;

import java.util.Locale;
import java.util.MissingResourceException;

/**
 * This interface defines the minimum requirements in order to provide support
 * for localized formatted strings.
 *
 * <p><b>This is NOT part of any supported API.
 * If you write code that depends on this, you do so at your own risk.
 * This code and its internal interfaces are subject to change or
 * deletion without notice.</b>
 *
 * @author Maurizio Cimadamore
 */
public interface Messages {

    /**
     * Add a new resource bundle to the list that is searched for localized messages.
     * @param bundleName the name to identify the resource bundle of localized messages.
     * @throws MissingResourceException if the given resource is not found
     */
    void add(String bundleName) throws MissingResourceException;

    /**
     * Get a localized formatted string.
     * @param l locale in which the text is to be localized
     * @param key locale-independent message key
     * @param args misc message arguments
     * @return a localized formatted string
     */
    String getLocalizedString(Locale l, String key, Object... args);
}
