/*
 * Copyright (c) 2001, 2011, Oracle and/or its affiliates. All rights reserved.
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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import jdk2.internal.misc.Unsafe;

/** Base class for jdk2.internal.misc.Unsafe-based FieldAccessors. The
    observation is that there are only nine types of fields from the
    standpoint of reflection code: the eight primitive types and
    Object. Using class Unsafe instead of generated bytecodes saves
    memory and loading time for the dynamically-generated
    FieldAccessors. */

abstract class UnsafeFieldAccessorImpl extends FieldAccessorImpl {
    static final Unsafe unsafe = Unsafe.getUnsafe();

    protected final Field   field;
    protected final long    fieldOffset;
    protected final boolean isFinal;

    UnsafeFieldAccessorImpl(Field field) {
        this.field = field;
        if (Modifier.isStatic(field.getModifiers()))
            fieldOffset = unsafe.staticFieldOffset(field);
        else
            fieldOffset = unsafe.objectFieldOffset(field);
        isFinal = Modifier.isFinal(field.getModifiers());
    }

    protected void ensureObj(Object o) {
        // NOTE: will throw NullPointerException, as specified, if o is null
        if (!field.getDeclaringClass().isAssignableFrom(o.getClass())) {
            throwSetIllegalArgumentException(o);
        }
    }

    private String getQualifiedFieldName() {
      return field.getDeclaringClass().getName() + "." +field.getName();
    }

    protected IllegalArgumentException newGetIllegalArgumentException(String type) {
        return new IllegalArgumentException(
          "Attempt to get "+field.getType().getName()+" field \"" +
          getQualifiedFieldName() + "\" with illegal data type conversion to "+type
        );
    }

    protected void throwFinalFieldIllegalAccessException(String attemptedType,
                                                         String attemptedValue)
                                                         throws IllegalAccessException {
        throw new IllegalAccessException(getSetMessage(attemptedType, attemptedValue));

    }
    protected void throwFinalFieldIllegalAccessException(Object o) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException(o != null ? o.getClass().getName() : "", "");
    }

    protected void throwFinalFieldIllegalAccessException(boolean z) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException("boolean", Boolean.toString(z));
    }

    protected void throwFinalFieldIllegalAccessException(char b) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException("char", Character.toString(b));
    }

    protected void throwFinalFieldIllegalAccessException(byte b) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException("byte", Byte.toString(b));
    }

    protected void throwFinalFieldIllegalAccessException(short b) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException("short", Short.toString(b));
    }

    protected void throwFinalFieldIllegalAccessException(int i) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException("int", Integer.toString(i));
    }

    protected void throwFinalFieldIllegalAccessException(long i) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException("long", Long.toString(i));
    }

    protected void throwFinalFieldIllegalAccessException(float f) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException("float", Float.toString(f));
    }

    protected void throwFinalFieldIllegalAccessException(double f) throws IllegalAccessException {
        throwFinalFieldIllegalAccessException("double", Double.toString(f));
    }

    protected IllegalArgumentException newGetBooleanIllegalArgumentException() {
        return newGetIllegalArgumentException("boolean");
    }

    protected IllegalArgumentException newGetByteIllegalArgumentException() {
        return newGetIllegalArgumentException("byte");
    }

    protected IllegalArgumentException newGetCharIllegalArgumentException() {
        return newGetIllegalArgumentException("char");
    }

    protected IllegalArgumentException newGetShortIllegalArgumentException() {
        return newGetIllegalArgumentException("short");
    }

    protected IllegalArgumentException newGetIntIllegalArgumentException() {
        return newGetIllegalArgumentException("int");
    }

    protected IllegalArgumentException newGetLongIllegalArgumentException() {
        return newGetIllegalArgumentException("long");
    }

    protected IllegalArgumentException newGetFloatIllegalArgumentException() {
        return newGetIllegalArgumentException("float");
    }

    protected IllegalArgumentException newGetDoubleIllegalArgumentException() {
        return newGetIllegalArgumentException("double");
    }

    protected String getSetMessage(String attemptedType, String attemptedValue) {
        String err = "Can not set";
        if (Modifier.isStatic(field.getModifiers()))
            err += " static";
        if (isFinal)
            err += " final";
        err += " " + field.getType().getName() + " field " + getQualifiedFieldName() + " to ";
        if (!attemptedValue.isEmpty()) {
            err += "(" + attemptedType + ")" + attemptedValue;
        } else {
            if (!attemptedType.isEmpty())
                err += attemptedType;
            else
                err += "null value";
        }
        return err;
    }

    protected void throwSetIllegalArgumentException(String attemptedType,
                                                    String attemptedValue) {
        throw new IllegalArgumentException(getSetMessage(attemptedType,attemptedValue));
    }

    protected void throwSetIllegalArgumentException(Object o) {
        throwSetIllegalArgumentException(o != null ? o.getClass().getName() : "", "");
    }

    protected void throwSetIllegalArgumentException(boolean b) {
        throwSetIllegalArgumentException("boolean", Boolean.toString(b));
    }

    protected void throwSetIllegalArgumentException(byte b) {
        throwSetIllegalArgumentException("byte", Byte.toString(b));
    }

    protected void throwSetIllegalArgumentException(char c) {
        throwSetIllegalArgumentException("char", Character.toString(c));
    }

    protected void throwSetIllegalArgumentException(short s) {
        throwSetIllegalArgumentException("short", Short.toString(s));
    }

    protected void throwSetIllegalArgumentException(int i) {
        throwSetIllegalArgumentException("int", Integer.toString(i));
    }

    protected void throwSetIllegalArgumentException(long l) {
        throwSetIllegalArgumentException("long", Long.toString(l));
    }

    protected void throwSetIllegalArgumentException(float f) {
        throwSetIllegalArgumentException("float", Float.toString(f));
    }

    protected void throwSetIllegalArgumentException(double d) {
        throwSetIllegalArgumentException("double", Double.toString(d));
    }

}
