/*
 * Copyright (c) 2003, 2018, Oracle and/or its affiliates. All rights reserved.
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

package jdk2.internal.misc;

import java.lang.annotation.Annotation;
import java.lang.module.ModuleDescriptor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.security.AccessControlContext;
import java.security.ProtectionDomain;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

import jdk2.internal.module.ServicesCatalog;
import jdk2.internal.reflect.ConstantPool;
import sun2.reflect.annotation.AnnotationType;
import sun2.nio.ch.Interruptible;

public interface JavaLangAccess {

    /**
     * Returns the list of {@code Method} objects for the declared public
     * methods of this class or interface that have the specified method name
     * and parameter types.
     */
    List<Method> getDeclaredPublicMethods(Class<?> klass, String name, Class<?>... parameterTypes);

    /**
     * Return the constant pool for a class.
     */
    ConstantPool getConstantPool(Class<?> klass);

    /**
     * Compare-And-Set the AnnotationType instance corresponding to this class.
     * (This method only applies to annotation types.)
     */
    boolean casAnnotationType(Class<?> klass, AnnotationType oldType, AnnotationType newType);

    /**
     * Get the AnnotationType instance corresponding to this class.
     * (This method only applies to annotation types.)
     */
    AnnotationType getAnnotationType(Class<?> klass);

    /**
     * Get the declared annotations for a given class, indexed by their types.
     */
    Map<Class<? extends Annotation>, Annotation> getDeclaredAnnotationMap(Class<?> klass);

    /**
     * Get the array of bytes that is the class-file representation
     * of this Class' annotations.
     */
    byte[] getRawClassAnnotations(Class<?> klass);

    /**
     * Get the array of bytes that is the class-file representation
     * of this Class' type annotations.
     */
    byte[] getRawClassTypeAnnotations(Class<?> klass);

    /**
     * Get the array of bytes that is the class-file representation
     * of this Executable's type annotations.
     */
    byte[] getRawExecutableTypeAnnotations(Executable executable);

    /**
     * Returns the elements of an enum class or null if the
     * Class object does not represent an enum type;
     * the result is uncloned, cached, and shared by all callers.
     */
    <E extends Enum<E>> E[] getEnumConstantsShared(Class<E> klass);

    /**
     * Set current thread's blocker field.
     */
    void blockedOn(Interruptible b);

    /**
     * Registers a shutdown hook.
     *
     * It is expected that this method with registerShutdownInProgress=true
     * is only used to register DeleteOnExitHook since the first file
     * may be added to the delete on exit list by the application shutdown
     * hooks.
     *
     * @param slot  the slot in the shutdown hook array, whose element
     *              will be invoked in order during shutdown
     * @param registerShutdownInProgress true to allow the hook
     *        to be registered even if the shutdown is in progress.
     * @param hook  the hook to be registered
     *
     * @throws IllegalStateException if shutdown is in progress and
     *         the slot is not valid to register.
     */
    void registerShutdownHook(int slot, boolean registerShutdownInProgress, Runnable hook);

    /**
     * Returns a new Thread with the given Runnable and an
     * inherited AccessControlContext.
     */
    Thread newThreadWithAcc(Runnable target, AccessControlContext acc);

    /**
     * Invokes the finalize method of the given object.
     */
    void invokeFinalize(Object o) throws Throwable;

    /**
     * Returns the ConcurrentHashMap used as a storage for ClassLoaderValue(s)
     * associated with the given class loader, creating it if it doesn't already exist.
     */
    ConcurrentHashMap<?, ?> createOrGetClassLoaderValueMap(ClassLoader cl);

    /**
     * Defines a class with the given name to a class loader.
     */
    Class<?> defineClass(ClassLoader cl, String name, byte[] b, ProtectionDomain pd, String source);

    /**
     * Returns a class loaded by the bootstrap class loader.
     */
    Class<?> findBootstrapClassOrNull(ClassLoader cl, String name);

    /**
     * Define a Package of the given name and module by the given class loader.
     */
    Package definePackage(ClassLoader cl, String name, Module module);

    /**
     * Invokes Long.fastUUID
     */
    String fastUUID(long lsb, long msb);

    /**
     * Record the non-exported packages of the modules in the given layer
     */
    void addNonExportedPackages(ModuleLayer layer);

    /**
     * Invalidate package access cache
     */
    void invalidatePackageAccessCache();

    /**
     * Defines a new module to the Java virtual machine. The module
     * is defined to the given class loader.
     *
     * The URI is for information purposes only, it can be {@code null}.
     */
    Module defineModule(ClassLoader loader, ModuleDescriptor descriptor, URI uri);

    /**
     * Defines the unnamed module for the given class loader.
     */
    Module defineUnnamedModule(ClassLoader loader);

    /**
     * Updates the readability so that module m1 reads m2. The new read edge
     * does not result in a strong reference to m2 (m2 can be GC'ed).
     *
     * This method is the same as m1.addReads(m2) but without a permission check.
     */
    void addReads(Module m1, Module m2);

    /**
     * Updates module m to read all unnamed modules.
     */
    void addReadsAllUnnamed(Module m);

    /**
     * Updates module m1 to export a package to module m2. The export does
     * not result in a strong reference to m2 (m2 can be GC'ed).
     */
    void addExports(Module m1, String pkg, Module m2);

    /**
     * Updates a module m to export a package to all unnamed modules.
     */
    void addExportsToAllUnnamed(Module m, String pkg);

    /**
     * Updates module m1 to open a package to module m2. Opening the
     * package does not result in a strong reference to m2 (m2 can be GC'ed).
     */
    void addOpens(Module m1, String pkg, Module m2);

    /**
     * Updates module m to open a package to all unnamed modules.
     */
    void addOpensToAllUnnamed(Module m, String pkg);

    /**
     * Updates module m to open all packages returned by the given iterator.
     */
    void addOpensToAllUnnamed(Module m, Iterator<String> packages);

    /**
     * Updates module m to use a service.
     */
    void addUses(Module m, Class<?> service);

    /**
     * Returns true if module m reflectively exports a package to other
     */
    boolean isReflectivelyExported(Module module, String pn, Module other);

    /**
     * Returns true if module m reflectively opens a package to other
     */
    boolean isReflectivelyOpened(Module module, String pn, Module other);

    /**
     * Returns the ServicesCatalog for the given Layer.
     */
    ServicesCatalog getServicesCatalog(ModuleLayer layer);

    /**
     * Returns an ordered stream of layers. The first element is the
     * given layer, the remaining elements are its parents, in DFS order.
     */
    Stream<ModuleLayer> layers(ModuleLayer layer);

    /**
     * Returns a stream of the layers that have modules defined to the
     * given class loader.
     */
    Stream<ModuleLayer> layers(ClassLoader loader);

    /**
     * Constructs a new {@code String} by decoding the specified subarray of
     * bytes using the specified {@linkplain java.nio.charset.Charset charset}.
     *
     * The caller of this method shall relinquish and transfer the ownership of
     * the byte array to the callee since the later will not make a copy.
     *
     * @param bytes the byte array source
     * @param cs the Charset
     * @return the newly created string
     * @throws CharacterCodingException for malformed or unmappable bytes
     */
    String newStringNoRepl(byte[] bytes, Charset cs) throws CharacterCodingException;

    /**
     * Encode the given string into a sequence of bytes using the specified Charset.
     *
     * This method avoids copying the String's internal representation if the input
     * is ASCII.
     *
     * This method throws CharacterCodingException instead of replacing when
     * malformed input or unmappable characters are encountered.
     *
     * @param s the string to encode
     * @param cs the charset
     * @return the encoded bytes
     * @throws CharacterCodingException for malformed input or unmappable characters
     */
    byte[] getBytesNoRepl(String s, Charset cs) throws CharacterCodingException;

    /**
     * Returns a new string by decoding from the given utf8 bytes array.
     *
     * @param off the index of the first byte to decode
     * @param len the number of bytes to decode
     * @return the newly created string
     * @throws IllegalArgumentException for malformed or unmappable bytes.
     */
    String newStringUTF8NoRepl(byte[] bytes, int off, int len);

    /**
     * Encode the given string into a sequence of bytes using utf8.
     *
     * @param s the string to encode
     * @return the encoded bytes in utf8
     * @throws IllegalArgumentException for malformed surrogates
     */
    byte[] getBytesUTF8NoRepl(String s);

    /**
     * Returns '<loader-name>' @<id> if classloader has a name
     * explicitly set otherwise <qualified-class-name> @<id>
     */
     String getLoaderNameID(ClassLoader loader);
}
