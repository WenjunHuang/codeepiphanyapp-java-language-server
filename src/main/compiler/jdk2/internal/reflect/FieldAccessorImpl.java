/*
 * Copyright (c) 2001, Oracle and/or its affiliates. All rights reserved.
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

package jdk2.internal.reflect;

/** Package-private implementation of the FieldAccessor interface
    which has access to all classes and all fields, regardless of
    language restrictions. See MagicAccessorImpl. */

abstract class FieldAccessorImpl extends MagicAccessorImpl
    implements FieldAccessor {
    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract Object get(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract boolean getBoolean(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract byte getByte(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract char getChar(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract short getShort(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract int getInt(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract long getLong(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract float getFloat(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract double getDouble(Object obj)
        throws IllegalArgumentException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void set(Object obj, Object value)
        throws IllegalArgumentException, IllegalAccessException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void setBoolean(Object obj, boolean z)
        throws IllegalArgumentException, IllegalAccessException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void setByte(Object obj, byte b)
        throws IllegalArgumentException, IllegalAccessException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void setChar(Object obj, char c)
        throws IllegalArgumentException, IllegalAccessException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void setShort(Object obj, short s)
        throws IllegalArgumentException, IllegalAccessException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void setInt(Object obj, int i)
        throws IllegalArgumentException, IllegalAccessException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void setLong(Object obj, long l)
        throws IllegalArgumentException, IllegalAccessException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void setFloat(Object obj, float f)
        throws IllegalArgumentException, IllegalAccessException;

    /** Matches specification in {@link java.lang.reflect.Field} */
    public abstract void setDouble(Object obj, double d)
        throws IllegalArgumentException, IllegalAccessException;
}
