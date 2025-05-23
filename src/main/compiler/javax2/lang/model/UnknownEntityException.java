/*
 * Copyright (c) 2009, 2017, Oracle and/or its affiliates. All rights reserved.
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

package javax2.lang.model;

/**
 * Superclass of exceptions which indicate that an unknown kind of
 * entity was encountered.  This situation can occur if the language
 * evolves and new kinds of constructs are introduced.  Subclasses of
 * this exception may be thrown by visitors to indicate that the
 * visitor was created for a prior version of the language.
 *
 * @apiNote A common superclass for exceptions specific to different
 * kinds of unknown entities allows a single catch block to easily
 * provide uniform handling of those related conditions.
 *
 * @author Joseph D. Darcy
 * @see javax2.lang.model.element.UnknownElementException
 * @see javax2.lang.model.element.UnknownAnnotationValueException
 * @see javax2.lang.model.type.UnknownTypeException
 * @since 1.7
 */
public class UnknownEntityException extends RuntimeException {

    private static final long serialVersionUID = 269L;

    /**
     * Creates a new {@code UnknownEntityException} with the specified
     * detail message.
     *
     * @param message the detail message
     */
    protected UnknownEntityException(String message) {
        super(message);
    }
}
