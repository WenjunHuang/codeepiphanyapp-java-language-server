/*
 * Copyright (c) 2011, 2017, Oracle and/or its affiliates. All rights reserved.
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

package javax2.lang.model.util;

import javax2.lang.model.element.*;
import javax2.annotation.processing.SupportedSourceVersion;
import javax2.lang.model.SourceVersion;
import static javax2.lang.model.SourceVersion.*;


/**
 * A scanning visitor of program elements with default behavior
 * appropriate for the {@link SourceVersion#RELEASE_8 RELEASE_8}
 * source version.  The <code>visit<i>Xyz</i></code> methods in this
 * class scan their component elements by calling {@code scan} on
 * their {@linkplain Element#getEnclosedElements enclosed elements},
 * {@linkplain ExecutableElement#getParameters parameters}, etc., as
 * indicated in the individual method specifications.  A subclass can
 * control the order elements are visited by overriding the
 * <code>visit<i>Xyz</i></code> methods.  Note that clients of a scanner
 * may get the desired behavior be invoking {@code v.scan(e, p)} rather
 * than {@code v.visit(e, p)} on the root objects of interest.
 *
 * <p>When a subclass overrides a <code>visit<i>Xyz</i></code> method, the
 * new method can cause the enclosed elements to be scanned in the
 * default way by calling <code>super.visit<i>Xyz</i></code>.  In this
 * fashion, the concrete visitor can control the ordering of traversal
 * over the component elements with respect to the additional
 * processing; for example, consistently calling
 * <code>super.visit<i>Xyz</i></code> at the start of the overridden
 * methods will yield a preorder traversal, etc.  If the component
 * elements should be traversed in some other order, instead of
 * calling <code>super.visit<i>Xyz</i></code>, an overriding visit method
 * should call {@code scan} with the elements in the desired order.
 *
 * <p> Methods in this class may be overridden subject to their
 * general contract.  Note that annotating methods in concrete
 * subclasses with {@link Override @Override} will help
 * ensure that methods are overridden as intended.
 *
 * <p> <b>WARNING:</b> The {@code ElementVisitor} interface
 * implemented by this class may have methods added to it in the
 * future to accommodate new, currently unknown, language structures
 * added to future versions of the Java&trade; programming language.
 * Therefore, methods whose names begin with {@code "visit"} may be
 * added to this class in the future; to avoid incompatibilities,
 * classes which extend this class should not declare any instance
 * methods with names beginning with {@code "visit"}.
 *
 * <p>When such a new visit method is added, the default
 * implementation in this class will be to call the {@link
 * #visitUnknown visitUnknown} method.  A new element scanner visitor
 * class will also be introduced to correspond to the new language
 * level; this visitor will have different default behavior for the
 * visit method in question.  When the new visitor is introduced, all
 * or portions of this visitor may be deprecated.
 *
 * @param <R> the return type of this visitor's methods.  Use {@link
 *            Void} for visitors that do not need to return results.
 * @param <P> the type of the additional parameter to this visitor's
 *            methods.  Use {@code Void} for visitors that do not need an
 *            additional parameter.
 *
 * @see ElementScanner6
 * @see ElementScanner7
 * @see ElementScanner9
 * @since 1.8
 */
@SupportedSourceVersion(RELEASE_8)
public class ElementScanner8<R, P> extends ElementScanner7<R, P> {
    /**
     * Constructor for concrete subclasses; uses {@code null} for the
     * default value.
     */
    protected ElementScanner8(){
        super(null);
    }

    /**
     * Constructor for concrete subclasses; uses the argument for the
     * default value.
     *
     * @param defaultValue the default value
     */
    protected ElementScanner8(R defaultValue){
        super(defaultValue);
    }
}
