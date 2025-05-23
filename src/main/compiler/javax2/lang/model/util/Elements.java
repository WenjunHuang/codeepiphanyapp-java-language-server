/*
 * Copyright (c) 2005, 2017, Oracle and/or its affiliates. All rights reserved.
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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashSet;

import javax2.lang.model.AnnotatedConstruct;
import javax2.lang.model.element.*;


/**
 * Utility methods for operating on program elements.
 *
 * <p><b>Compatibility Note:</b> Methods may be added to this interface
 * in future releases of the platform.
 *
 * @author Joseph D. Darcy
 * @author Scott Seligman
 * @author Peter von der Ah&eacute;
 * @see javax2.annotation.processing.ProcessingEnvironment#getElementUtils
 * @since 1.6
 */
public interface Elements {

    /**
     * Returns a package given its fully qualified name if the package is unique in the environment.
     * If running with modules, all modules in the modules graph are searched for matching packages.
     *
     * @param name  fully qualified package name, or an empty string for an unnamed package
     * @return the specified package, or {@code null} if it cannot be uniquely found
     */
    PackageElement getPackageElement(CharSequence name);

    /**
     * Returns a package given its fully qualified name, as seen from the given module.
     *
     * @implSpec The default implementation of this method returns
     * {@code null}.
     *
     * @param name  fully qualified package name, or an empty string for an unnamed package
     * @param module module relative to which the lookup should happen
     * @return the specified package, or {@code null} if it cannot be found
     * @see #getAllPackageElements
     * @since 9
     */
    default PackageElement getPackageElement(ModuleElement module, CharSequence name) {
        return null;
    }

    /**
     * Returns all package elements with the given canonical name.
     *
     * There may be more than one package element with the same canonical
     * name if the package elements are in different modules.
     *
     * @implSpec The default implementation of this method calls
     * {@link #getAllModuleElements() getAllModuleElements} and stores
     * the result. If the set of modules is empty, {@link
     * #getPackageElement(CharSequence) getPackageElement(name)} is
     * called passing through the name argument. If {@code
     * getPackageElement(name)} is {@code null}, an empty set of
     * package elements is returned; otherwise, a single-element set
     * with the found package element is returned. If the set of
     * modules is nonempty, the modules are iterated over and any
     * non-{@code null} results of {@link
     * #getPackageElement(ModuleElement, CharSequence)
     * getPackageElement(module, name)} are accumulated into a
     * set. The set is then returned.
     *
     * @param name  the canonical name
     * @return the package elements, or an empty set if no package with the name can be found
     * @see #getPackageElement(ModuleElement, CharSequence)
     * @since 9
     */
    default Set<? extends PackageElement> getAllPackageElements(CharSequence name) {
        Set<? extends ModuleElement> modules = getAllModuleElements();
        if (modules.isEmpty()) {
            PackageElement packageElt = getPackageElement(name);
            return (packageElt != null) ?
                Collections.singleton(packageElt):
                Collections.emptySet();
        } else {
            Set<PackageElement> result = new LinkedHashSet<>(1); // Usually expect at most 1 result
            for (ModuleElement module: modules) {
                PackageElement packageElt = getPackageElement(module, name);
                if (packageElt != null)
                    result.add(packageElt);
            }
            return Collections.unmodifiableSet(result);
        }
    }

    /**
     * Returns a type element given its canonical name if the type element is unique in the environment.
     * If running with modules, all modules in the modules graph are searched for matching
     * type elements.
     *
     * @param name  the canonical name
     * @return the named type element, or {@code null} if it cannot be uniquely found
     */
    TypeElement getTypeElement(CharSequence name);

    /**
     * Returns a type element given its canonical name, as seen from the given module.
     *
     * @implSpec The default implementation of this method returns
     * {@code null}.
     *
     * @param name  the canonical name
     * @param module module relative to which the lookup should happen
     * @return the named type element, or {@code null} if it cannot be found
     * @see #getAllTypeElements
     * @since 9
     */
    default TypeElement getTypeElement(ModuleElement module, CharSequence name) {
        return null;
    }

    /**
     * Returns all type elements with the given canonical name.
     *
     * There may be more than one type element with the same canonical
     * name if the type elements are in different modules.
     *
     * @implSpec The default implementation of this method calls
     * {@link #getAllModuleElements() getAllModuleElements} and stores
     * the result. If the set of modules is empty, {@link
     * #getTypeElement(CharSequence) getTypeElement(name)} is called
     * passing through the name argument. If {@code
     * getTypeElement(name)} is {@code null}, an empty set of type
     * elements is returned; otherwise, a single-element set with the
     * found type element is returned. If the set of modules is
     * nonempty, the modules are iterated over and any non-{@code null}
     * results of {@link #getTypeElement(ModuleElement,
     * CharSequence) getTypeElement(module, name)} are accumulated
     * into a set. The set is then returned.
     *
     * @param name  the canonical name
     * @return the type elements, or an empty set if no type with the name can be found
     * @see #getTypeElement(ModuleElement, CharSequence)
     * @since 9
     */
    default Set<? extends TypeElement> getAllTypeElements(CharSequence name) {
        Set<? extends ModuleElement> modules = getAllModuleElements();
        if (modules.isEmpty()) {
            TypeElement typeElt = getTypeElement(name);
            return (typeElt != null) ?
                Collections.singleton(typeElt):
                Collections.emptySet();
        } else {
            Set<TypeElement> result = new LinkedHashSet<>(1); // Usually expect at most 1 result
            for (ModuleElement module: modules) {
                TypeElement typeElt = getTypeElement(module, name);
                if (typeElt != null)
                    result.add(typeElt);
            }
            return Collections.unmodifiableSet(result);
        }
    }

    /**
     * Returns a module element given its fully qualified name.
     *
     * If the named module cannot be found, {@code null} is
     * returned. One situation where a module cannot be found is if
     * the environment does not include modules, such as an annotation
     * processing environment configured for a {@linkplain
     * javax2.annotation.processing.ProcessingEnvironment#getSourceVersion
     * source version} without modules.
     *
     * @implSpec The default implementation of this method returns
     * {@code null}.
     *
     * @param name  the name
     * @return the named module element, or {@code null} if it cannot be found
     * @see #getAllModuleElements
     * @since 9
     * @spec JPMS
     */
    default ModuleElement getModuleElement(CharSequence name) {
        return null;
    }

    /**
     * Returns all module elements in the current environment.
     *
     * If no modules are present, an empty set is returned. One
     * situation where no modules are present occurs when the
     * environment does not include modules, such as an annotation
     * processing environment configured for a {@linkplain
     * javax2.annotation.processing.ProcessingEnvironment#getSourceVersion
     * source version} without modules.
     *
     * @implSpec The default implementation of this method returns
     * an empty set.
     *
     * @return the known module elements, or an empty set if there are no modules
     * @see #getModuleElement(CharSequence)
     * @since 9
     */
    default Set<? extends ModuleElement> getAllModuleElements() {
        return Collections.emptySet();
    }

    /**
     * Returns the values of an annotation's elements, including defaults.
     *
     * @see AnnotationMirror#getElementValues()
     * @param a  annotation to examine
     * @return the values of the annotation's elements, including defaults
     */
    Map<? extends ExecutableElement, ? extends AnnotationValue>
            getElementValuesWithDefaults(AnnotationMirror a);

    /**
     * Returns the text of the documentation (&quot;Javadoc&quot;)
     * comment of an element.
     *
     * <p> A documentation comment of an element is a comment that
     * begins with "{@code /**}" , ends with a separate
     * "<code>*&#47;</code>", and immediately precedes the element,
     * ignoring white space.  Therefore, a documentation comment
     * contains at least three"{@code *}" characters.  The text
     * returned for the documentation comment is a processed form of
     * the comment as it appears in source code.  The leading "{@code
     * /**}" and trailing "<code>*&#47;</code>" are removed.  For lines
     * of the comment starting after the initial "{@code /**}",
     * leading white space characters are discarded as are any
     * consecutive "{@code *}" characters appearing after the white
     * space or starting the line.  The processed lines are then
     * concatenated together (including line terminators) and
     * returned.
     *
     * @param e  the element being examined
     * @return the documentation comment of the element, or {@code null}
     *          if there is none
     * @jls 3.6 White Space
     */
    String getDocComment(Element e);

    /**
     * Returns {@code true} if the element is deprecated, {@code false} otherwise.
     *
     * @param e  the element being examined
     * @return {@code true} if the element is deprecated, {@code false} otherwise
     */
    boolean isDeprecated(Element e);

    /**
     * Returns the <em>origin</em> of the given element.
     *
     * <p>Note that if this method returns {@link Origin#EXPLICIT
     * EXPLICIT} and the element was created from a class file, then
     * the element may not, in fact, correspond to an explicitly
     * declared construct in source code. This is due to limitations
     * of the fidelity of the class file format in preserving
     * information from source code. For example, at least some
     * versions of the class file format do not preserve whether a
     * constructor was explicitly declared by the programmer or was
     * implicitly declared as the <em>default constructor</em>.
     *
     * @implSpec The default implementation of this method returns
     * {@link Origin#EXPLICIT EXPLICIT}.
     *
     * @param e  the element being examined
     * @return the origin of the given element
     * @since 9
     */
    default Origin getOrigin(Element e) {
        return Origin.EXPLICIT;
    }

    /**
     * Returns the <em>origin</em> of the given annotation mirror.
     *
     * An annotation mirror is {@linkplain Origin#MANDATED mandated}
     * if it is an implicitly declared <em>container annotation</em>
     * used to hold repeated annotations of a repeatable annotation
     * type.
     *
     * <p>Note that if this method returns {@link Origin#EXPLICIT
     * EXPLICIT} and the annotation mirror was created from a class
     * file, then the element may not, in fact, correspond to an
     * explicitly declared construct in source code. This is due to
     * limitations of the fidelity of the class file format in
     * preserving information from source code. For example, at least
     * some versions of the class file format do not preserve whether
     * an annotation was explicitly declared by the programmer or was
     * implicitly declared as a <em>container annotation</em>.
     *
     * @implSpec The default implementation of this method returns
     * {@link Origin#EXPLICIT EXPLICIT}.
     *
     * @param c the construct the annotation mirror modifies
     * @param a the annotation mirror being examined
     * @return the origin of the given annotation mirror
     * @jls 9.6.3 Repeatable Annotation Types
     * @jls 9.7.5 Multiple Annotations of the Same Type
     * @since 9
     */
    default Origin getOrigin(AnnotatedConstruct c,
                             AnnotationMirror a) {
        return Origin.EXPLICIT;
    }

    /**
     * Returns the <em>origin</em> of the given module directive.
     *
     * <p>Note that if this method returns {@link Origin#EXPLICIT
     * EXPLICIT} and the module directive was created from a class
     * file, then the module directive may not, in fact, correspond to
     * an explicitly declared construct in source code. This is due to
     * limitations of the fidelity of the class file format in
     * preserving information from source code. For example, at least
     * some versions of the class file format do not preserve whether
     * a {@code uses} directive was explicitly declared by the
     * programmer or was added as a synthetic construct.
     *
     * <p>Note that an implementation may not be able to reliably
     * determine the origin status of the directive if the directive
     * is created from a class file due to limitations of the fidelity
     * of the class file format in preserving information from source
     * code.
     *
     * @implSpec The default implementation of this method returns
     * {@link Origin#EXPLICIT EXPLICIT}.
     *
     * @param m the module of the directive
     * @param directive  the module directive being examined
     * @return the origin of the given directive
     * @since 9
     */
    default Origin getOrigin(ModuleElement m,
                             ModuleElement.Directive directive) {
        return Origin.EXPLICIT;
    }

    /**
     * The <em>origin</em> of an element or other language model
     * item. The origin of an element or item models how a construct
     * in a program is declared in the source code, explicitly,
     * implicitly, etc.
     *
     * <p>Note that it is possible additional kinds of origin values
     * will be added in future versions of the platform.
     *
     * @jls 13.1 The Form of a Binary
     * @since 9
     */
    public enum Origin {
        /**
         * Describes a construct explicitly declared in source code.
         */
        EXPLICIT,

       /**
         * A mandated construct is one that is not explicitly declared
         * in the source code, but whose presence is mandated by the
         * specification. Such a construct is said to be implicitly
         * declared.
         *
         * One example of a mandated element is a <em>default
         * constructor</em> in a class that contains no explicit
         * constructor declarations.
         *
         * Another example of a mandated construct is an implicitly
         * declared <em>container annotation</em> used to hold
         * multiple annotations of a repeatable annotation type.
         *
         * @jls 8.8.9 Default Constructor
         * @jls 8.9.3 Enum Members
         * @jls 9.6.3 Repeatable Annotation Types
         * @jls 9.7.5 Multiple Annotations of the Same Type
         */
        MANDATED,

       /**
         * A synthetic construct is one that is neither implicitly nor
         * explicitly declared in the source code. Such a construct is
         * typically a translation artifact created by a compiler.
         */
        SYNTHETIC;

        /**
         * Returns {@code true} for values corresponding to constructs
         * that are implicitly or explicitly declared, {@code false}
         * otherwise.
         * @return {@code true} for {@link EXPLICIT} and {@link
         * MANDATED}, {@code false} otherwise.
         */
        public boolean isDeclared() {
            return this != SYNTHETIC;
        }
    }

    /**
     * Returns {@code true} if the executable element is a bridge
     * method, {@code false} otherwise.
     *
     * @implSpec The default implementation of this method returns {@code false}.
     *
     * @param e  the executable being examined
     * @return {@code true} if the executable element is a bridge
     * method, {@code false} otherwise
     * @since 9
     */
    default boolean isBridge(ExecutableElement e) {
        return false;
    }

    /**
     * Returns the <i>binary name</i> of a type element.
     *
     * @param type  the type element being examined
     * @return the binary name
     *
     * @see TypeElement#getQualifiedName
     * @jls 13.1 The Form of a Binary
     */
    Name getBinaryName(TypeElement type);


    /**
     * Returns the package of an element.  The package of a package is
     * itself.
     *
     * @param type the element being examined
     * @return the package of an element
     */
    PackageElement getPackageOf(Element type);

    /**
     * Returns the module of an element.  The module of a module is
     * itself.
     * If there is no module for the element, null is returned. One situation where there is
     * no module for an element is if the environment does not include modules, such as
     * an annotation processing environment configured for
     * a {@linkplain
     * javax2.annotation.processing.ProcessingEnvironment#getSourceVersion
     * source version} without modules.
     *
     * @implSpec The default implementation of this method returns
     * {@code null}.
     *
     * @param type the element being examined
     * @return the module of an element
     * @since 9
     * @spec JPMS
     */
    default ModuleElement getModuleOf(Element type) {
        return null;
    }

    /**
     * Returns all members of a type element, whether inherited or
     * declared directly.  For a class the result also includes its
     * constructors, but not local or anonymous classes.
     *
     * @apiNote Elements of certain kinds can be isolated using
     * methods in {@link ElementFilter}.
     *
     * @param type  the type being examined
     * @return all members of the type
     * @see Element#getEnclosedElements
     */
    List<? extends Element> getAllMembers(TypeElement type);

    /**
     * Returns all annotations <i>present</i> on an element, whether
     * directly present or present via inheritance.
     *
     * @param e  the element being examined
     * @return all annotations of the element
     * @see Element#getAnnotationMirrors
     * @see AnnotatedConstruct
     */
    List<? extends AnnotationMirror> getAllAnnotationMirrors(Element e);

    /**
     * Tests whether one type, method, or field hides another.
     *
     * @param hider   the first element
     * @param hidden  the second element
     * @return {@code true} if and only if the first element hides
     *          the second
     */
    boolean hides(Element hider, Element hidden);

    /**
     * Tests whether one method, as a member of a given type,
     * overrides another method.
     * When a non-abstract method overrides an abstract one, the
     * former is also said to <i>implement</i> the latter.
     *
     * <p> In the simplest and most typical usage, the value of the
     * {@code type} parameter will simply be the class or interface
     * directly enclosing {@code overrider} (the possibly-overriding
     * method).  For example, suppose {@code m1} represents the method
     * {@code String.hashCode} and {@code m2} represents {@code
     * Object.hashCode}.  We can then ask whether {@code m1} overrides
     * {@code m2} within the class {@code String} (it does):
     *
     * <blockquote>
     * {@code assert elements.overrides(m1, m2,
     *          elements.getTypeElement("java.lang.String")); }
     * </blockquote>
     *
     * A more interesting case can be illustrated by the following example
     * in which a method in type {@code A} does not override a
     * like-named method in type {@code B}:
     *
     * <blockquote>
     * {@code class A { public void m() {} } }<br>
     * {@code interface B { void m(); } }<br>
     * ...<br>
     * {@code m1 = ...;  // A.m }<br>
     * {@code m2 = ...;  // B.m }<br>
     * {@code assert ! elements.overrides(m1, m2,
     *          elements.getTypeElement("A")); }
     * </blockquote>
     *
     * When viewed as a member of a third type {@code C}, however,
     * the method in {@code A} does override the one in {@code B}:
     *
     * <blockquote>
     * {@code class C extends A implements B {} }<br>
     * ...<br>
     * {@code assert elements.overrides(m1, m2,
     *          elements.getTypeElement("C")); }
     * </blockquote>
     *
     * @param overrider  the first method, possible overrider
     * @param overridden  the second method, possibly being overridden
     * @param type   the type of which the first method is a member
     * @return {@code true} if and only if the first method overrides
     *          the second
     * @jls 8.4.8 Inheritance, Overriding, and Hiding
     * @jls 9.4.1 Inheritance and Overriding
     */
    boolean overrides(ExecutableElement overrider, ExecutableElement overridden,
                      TypeElement type);

    /**
     * Returns the text of a <i>constant expression</i> representing a
     * primitive value or a string.
     * The text returned is in a form suitable for representing the value
     * in source code.
     *
     * @param value  a primitive value or string
     * @return the text of a constant expression
     * @throws IllegalArgumentException if the argument is not a primitive
     *          value or string
     *
     * @see VariableElement#getConstantValue()
     */
    String getConstantExpression(Object value);

    /**
     * Prints a representation of the elements to the given writer in
     * the specified order.  The main purpose of this method is for
     * diagnostics.  The exact format of the output is <em>not</em>
     * specified and is subject to change.
     *
     * @param w the writer to print the output to
     * @param elements the elements to print
     */
    void printElements(java.io.Writer w, Element... elements);

    /**
     * Return a name with the same sequence of characters as the
     * argument.
     *
     * @param cs the character sequence to return as a name
     * @return a name with the same sequence of characters as the argument
     */
    Name getName(CharSequence cs);

    /**
     * Returns {@code true} if the type element is a functional interface, {@code false} otherwise.
     *
     * @param type the type element being examined
     * @return {@code true} if the element is a functional interface, {@code false} otherwise
     * @jls 9.8 Functional Interfaces
     * @since 1.8
     */
    boolean isFunctionalInterface(TypeElement type);
}
