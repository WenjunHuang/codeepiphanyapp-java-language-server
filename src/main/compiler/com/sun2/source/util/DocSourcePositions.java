/*
 * Copyright (c) 2013, 2014, Oracle and/or its affiliates. All rights reserved.
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

import com.sun2.source.doctree.DocCommentTree;
import com.sun2.source.doctree.DocTree;
import com.sun2.source.tree.CompilationUnitTree;

/**
 * Provides methods to obtain the position of a DocTree within a javadoc comment.
 * A position is defined as a simple character offset from the start of a
 * CompilationUnit where the first character is at offset 0.
 *
 * @since 1.8
 */
public interface DocSourcePositions extends SourcePositions {

    /**
     * Returns the starting position of the tree within the comment within the file.  If tree is not found within
     * file, or if the starting position is not available,
     * return {@link javax2.tools.Diagnostic#NOPOS}.
     * The given tree should be under the given comment tree, and the given documentation
     * comment tree should be returned from a {@link DocTrees#getDocCommentTree(com.sun2.source.util.TreePath) }
     * for a tree under the given file.
     * The returned position must be at the start of the yield of this tree, that
     * is for any sub-tree of this tree, the following must hold:
     *
     * <p>
     * {@code tree.getStartPosition() <= subtree.getStartPosition()} or <br>
     * {@code tree.getStartPosition() == NOPOS} or <br>
     * {@code subtree.getStartPosition() == NOPOS}
     * </p>
     *
     * @param file CompilationUnit in which to find tree.
     * @param comment the comment tree that encloses the tree for which the
     *                position is being sought
     * @param tree tree for which a position is sought.
     * @return the start position of tree.
     */
    long getStartPosition(CompilationUnitTree file, DocCommentTree comment, DocTree tree);

    /**
     * Returns the ending position of the tree within the comment within the file.  If tree is not found within
     * file, or if the ending position is not available,
     * return {@link javax2.tools.Diagnostic#NOPOS}.
     * The given tree should be under the given comment tree, and the given documentation
     * comment tree should be returned from a {@link DocTrees#getDocCommentTree(com.sun2.source.util.TreePath) }
     * for a tree under the given file.
     * The returned position must be at the end of the yield of this tree,
     * that is for any sub-tree of this tree, the following must hold:
     *
     * <p>
     * {@code tree.getEndPosition() >= subtree.getEndPosition()} or <br>
     * {@code tree.getEndPosition() == NOPOS} or <br>
     * {@code subtree.getEndPosition() == NOPOS}
     * </p>
     *
     * In addition, the following must hold:
     *
     * <p>
     * {@code tree.getStartPosition() <= tree.getEndPosition()}  or <br>
     * {@code tree.getStartPosition() == NOPOS} or <br>
     * {@code tree.getEndPosition() == NOPOS}
     * </p>
     *
     * @param file CompilationUnit in which to find tree.
     * @param comment the comment tree that encloses the tree for which the
     *                position is being sought
     * @param tree tree for which a position is sought.
     * @return the start position of tree.
     */
    long getEndPosition(CompilationUnitTree file, DocCommentTree comment, DocTree tree);

}
