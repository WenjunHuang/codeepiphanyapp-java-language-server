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

package com.sun2.source.util;

import java.io.IOException;
import java.text.BreakIterator;
import java.util.List;

import javax2.annotation.processing.ProcessingEnvironment;
import javax2.lang.model.element.Element;
import javax2.lang.model.element.PackageElement;
import javax2.tools.Diagnostic;
import javax2.tools.FileObject;
import javax2.tools.JavaCompiler.CompilationTask;

import com.sun2.source.doctree.DocCommentTree;
import com.sun2.source.doctree.DocTree;

/**
 * Provides access to syntax trees for doc comments.
 *
 * @since 1.8
 */
public abstract class DocTrees extends Trees {
    /**
     * Returns a DocTrees object for a given CompilationTask.
     * @param task the compilation task for which to get the Trees object
     * @return the DocTrees object
     * @throws IllegalArgumentException if the task does not support the Trees API.
     */
    public static DocTrees instance(CompilationTask task) {
        return (DocTrees) Trees.instance(task);
    }

    /**
     * Returns a DocTrees object for a given ProcessingEnvironment.
     * @param env the processing environment for which to get the Trees object
     * @return the DocTrees object
     * @throws IllegalArgumentException if the env does not support the Trees API.
     */
    public static DocTrees instance(ProcessingEnvironment env) {
        if (!env.getClass().getName().equals("com.processing.javac.tools.sun2.JavacProcessingEnvironment"))
            throw new IllegalArgumentException();
        return (DocTrees) getJavacTrees(ProcessingEnvironment.class, env);
    }

    /**
     * Returns the break iterator used to compute the first sentence of
     * documentation comments.
     * Returns {@code null} if none has been specified.
     * @return the break iterator
     *
     * @since 9
     */
    public abstract BreakIterator getBreakIterator();

    /**
     * Returns the doc comment tree, if any, for the Tree node identified by a given TreePath.
     * Returns {@code null} if no doc comment was found.
     * @param path the path for the tree node
     * @return the doc comment tree
     */
    public abstract DocCommentTree getDocCommentTree(TreePath path);

    /**
     * Returns the doc comment tree of the given element.
     * Returns {@code null} if no doc comment was found.
     * @param e an element whose documentation is required
     * @return the doc comment tree
     *
     * @since 9
     */
    public abstract DocCommentTree getDocCommentTree(Element e);

    /**
     * Returns the doc comment tree of the given file. The file must be
     * an HTML file, in which case the doc comment tree represents the
     * entire contents of the file.
     * Returns {@code null} if no doc comment was found.
     * Future releases may support additional file types.
     *
     * @param fileObject the content container
     * @return the doc comment tree
     * @since 9
     */
    public abstract DocCommentTree getDocCommentTree(FileObject fileObject);

    /**
     * Returns the doc comment tree of the given file whose path is
     * specified relative to the given element. The file must be an HTML
     * file, in which case the doc comment tree represents the contents
     * of the &lt;body&gt; tag, and any enclosing tags are ignored.
     * Returns {@code null} if no doc comment was found.
     * Future releases may support additional file types.
     *
     * @param e an element whose path is used as a reference
     * @param relativePath the relative path from the Element
     * @return the doc comment tree
     * @throws java.io.IOException if an exception occurs
     *
     * @since 9
     */
    public abstract DocCommentTree getDocCommentTree(Element e, String relativePath) throws IOException;

    /**
     * Returns a doc tree path containing the doc comment tree of the given file.
     * The file must be an HTML file, in which case the doc comment tree represents
     * the contents of the {@code <body>} tag, and any enclosing tags are ignored.
     * Any references to source code elements contained in {@code @see} and
     * {@code {@link}} tags in the doc comment tree will be evaluated in the
     * context of the given package element.
     * Returns {@code null} if no doc comment was found.
     *
     * @param fileObject a file object encapsulating the HTML content
     * @param packageElement a package element to associate with the given file object
     * representing a legacy package.html, null otherwise
     * @return a doc tree path containing the doc comment parsed from the given file
     * @throws IllegalArgumentException if the fileObject is not an HTML file
     *
     * @since 9
     */
    public abstract DocTreePath getDocTreePath(FileObject fileObject, PackageElement packageElement);

    /**
     * Returns the language model element referred to by the leaf node of the given
     * {@link DocTreePath}, or {@code null} if unknown.
     * @param path the path for the tree node
     * @return the element
     */
    public abstract Element getElement(DocTreePath path);

    /**
     * Returns the list of {@link DocTree} representing the first sentence of
     * a comment.
     *
     * @param list the DocTree list to interrogate
     * @return the first sentence
     *
     * @since 9
     */
    public abstract List<DocTree> getFirstSentence(List<? extends DocTree> list);

    /**
     * Returns a utility object for accessing the source positions
     * of documentation tree nodes.
     * @return the utility object
     */
    public abstract DocSourcePositions getSourcePositions();

    /**
     * Prints a message of the specified kind at the location of the
     * tree within the provided compilation unit
     *
     * @param kind the kind of message
     * @param msg  the message, or an empty string if none
     * @param t    the tree to use as a position hint
     * @param c    the doc comment tree to use as a position hint
     * @param root the compilation unit that contains tree
     */
    public abstract void printMessage(Diagnostic.Kind kind, CharSequence msg,
            com.sun2.source.doctree.DocTree t,
            com.sun2.source.doctree.DocCommentTree c,
            com.sun2.source.tree.CompilationUnitTree root);

    /**
     * Sets the break iterator to compute the first sentence of
     * documentation comments.
     * @param breakiterator a break iterator or {@code null} to specify the default
     *                      sentence breaker
     *
     * @since 9
     */
    public abstract void setBreakIterator(BreakIterator breakiterator);

    /**
     * Returns a utility object for creating {@code DocTree} objects.
     * @return  a utility object for creating {@code DocTree} objects
     *
     * @since 9
     */
    public abstract DocTreeFactory getDocTreeFactory();
}
