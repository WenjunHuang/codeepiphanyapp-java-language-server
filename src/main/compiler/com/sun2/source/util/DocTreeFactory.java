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

import java.util.List;

import javax2.lang.model.element.Name;
import javax2.tools.Diagnostic;
import javax2.tools.JavaFileObject;

import com.sun2.source.doctree.AttributeTree;
import com.sun2.source.doctree.AttributeTree.ValueKind;
import com.sun2.source.doctree.AuthorTree;
import com.sun2.source.doctree.CommentTree;
import com.sun2.source.doctree.DeprecatedTree;
import com.sun2.source.doctree.DocCommentTree;
import com.sun2.source.doctree.DocRootTree;
import com.sun2.source.doctree.DocTree;
import com.sun2.source.doctree.DocTypeTree;
import com.sun2.source.doctree.EndElementTree;
import com.sun2.source.doctree.EntityTree;
import com.sun2.source.doctree.ErroneousTree;
import com.sun2.source.doctree.HiddenTree;
import com.sun2.source.doctree.IdentifierTree;
import com.sun2.source.doctree.IndexTree;
import com.sun2.source.doctree.InheritDocTree;
import com.sun2.source.doctree.LinkTree;
import com.sun2.source.doctree.LiteralTree;
import com.sun2.source.doctree.ParamTree;
import com.sun2.source.doctree.ProvidesTree;
import com.sun2.source.doctree.ReferenceTree;
import com.sun2.source.doctree.ReturnTree;
import com.sun2.source.doctree.SeeTree;
import com.sun2.source.doctree.SerialDataTree;
import com.sun2.source.doctree.SerialFieldTree;
import com.sun2.source.doctree.SerialTree;
import com.sun2.source.doctree.SinceTree;
import com.sun2.source.doctree.StartElementTree;
import com.sun2.source.doctree.SummaryTree;
import com.sun2.source.doctree.TextTree;
import com.sun2.source.doctree.ThrowsTree;
import com.sun2.source.doctree.UnknownBlockTagTree;
import com.sun2.source.doctree.UnknownInlineTagTree;
import com.sun2.source.doctree.UsesTree;
import com.sun2.source.doctree.ValueTree;
import com.sun2.source.doctree.VersionTree;

/**
 *  Factory for creating {@code DocTree} nodes.
 *
 *  @implNote The methods in an implementation of this interface may only accept {@code DocTree}
 *  nodes that have been created by the same implementation.
 *
 *  @since 9
 */
public interface DocTreeFactory {
    /**
     * Create a new {@code AttributeTree} object, to represent an HTML attribute in an HTML tag.
     * @param name  the name of the attribute
     * @param vkind the kind of attribute value
     * @param value the value, if any, of the attribute
     * @return an {@code AttributeTree} object
     */
    AttributeTree newAttributeTree(Name name, ValueKind vkind, List<? extends DocTree> value);

    /**
     * Create a new {@code AuthorTree} object, to represent an {@code {@author } } tag.
     * @param name the name of the author
     * @return an {@code AuthorTree} object
     */
    AuthorTree newAuthorTree(List<? extends DocTree> name);

    /**
     * Create a new {@code CodeTree} object, to represent a {@code {@code } } tag.
     * @param text the content of the tag
     * @return a {@code CodeTree} object
     */
    LiteralTree newCodeTree(TextTree text);

    /**
     * Create a new {@code CommentTree}, to represent an HTML comment.
     * @param text the content of the comment
     * @return a {@code CommentTree} object
     */
    CommentTree newCommentTree(String text);

    /**
     * Create a new {@code DeprecatedTree} object, to represent an {@code {@deprecated } } tag.
     * @param text the content of the tag
     * @return a {@code DeprecatedTree} object
     */
    DeprecatedTree newDeprecatedTree(List<? extends DocTree> text);

    /**
     * Create a new {@code DocCommentTree} object, to represent a complete doc comment.
     * @param fullBody the entire body of the doc comment
     * @param tags the block tags in the doc comment
     * @return a {@code DocCommentTree} object
     */
    DocCommentTree newDocCommentTree(List<? extends DocTree> fullBody, List<? extends DocTree> tags);


    /**
     * Create a new {@code DocCommentTree} object, to represent the enitire doc comment.
     * @param fullBody the entire body of the doc comment
     * @param tags the block tags in the doc comment
     * @param preamble the meta content of an html file including the body tag
     * @param postamble the meta content of an html including the closing body tag
     * @return a {@code DocCommentTree} object
     * @since 10
     */
    DocCommentTree newDocCommentTree(List<? extends DocTree> fullBody,
                                     List<? extends DocTree> tags,
                                     List<? extends DocTree> preamble,
                                     List<? extends DocTree> postamble);
    /**
     * Create a new {@code DocRootTree} object, to represent an {@code {@docroot} } tag.
     * @return a {@code DocRootTree} object
     */
    DocRootTree newDocRootTree();

    /**
     * Create a new {@code DocTypeTree}, to represent a {@code DOCTYPE} HTML declaration.
     * @param text the content of the declaration
     * @return a {@code CommentTree} object
     * @since 10
     */
    DocTypeTree newDocTypeTree(String text);

    /**
     * Create a new {@code EndElement} object, to represent the end of an HTML element.
     * @param name the name of the HTML element
     * @return an {@code EndElementTree} object
     */
    EndElementTree newEndElementTree(Name name);

    /**
     * Create a new {@code EntityTree} object, to represent an HTML entity.
     * @param name the name of the entity, representing the characters between '&lt;' and ';'
     * in the representation of the entity in an HTML document
     * @return an {@code EntityTree} object
     */
    EntityTree newEntityTree(Name name);

    /**
     * Create a new {@code ErroneousTree} object, to represent some unparseable input.
     * @param text the unparseable text
     * @param diag a diagnostic associated with the unparseable text, or null
     * @return an {@code ErroneousTree} object
     */
    ErroneousTree newErroneousTree(String text, Diagnostic<JavaFileObject> diag);

    /**
     * Create a new {@code ExceptionTree} object, to represent an {@code @exception } tag.
     * @param name the name of the exception
     * @param description a description of why the exception might be thrown
     * @return an {@code ExceptionTree} object
     */
    ThrowsTree newExceptionTree(ReferenceTree name, List<? extends DocTree> description);

    /**
     * Create a new {@code HiddenTree} object, to represent an {@code {@hidden } } tag.
     * @param text the content of the tag
     * @return a {@code HiddenTree} object
     */
    HiddenTree newHiddenTree(List<? extends DocTree> text);

    /**
     * Create a new {@code IdentifierTree} object, to represent an identifier, such as in a
     * {@code @param } tag.
     * @param name the name of the identifier
     * @return an {@code IdentifierTree} object
     */
    IdentifierTree newIdentifierTree(Name name);

    /**
     * Create a new {@code IndexTree} object, to represent an {@code {@index } } tag.
     * @param term the search term
     * @param description an optional description of the search term
     * @return an {@code IndexTree} object
     */
    IndexTree newIndexTree(DocTree term, List<? extends DocTree> description);

    /**
     * Create a new {@code InheritDocTree} object, to represent an {@code {@inheritDoc} } tag.
     * @return an {@code InheritDocTree} object
     */
    InheritDocTree newInheritDocTree();

    /**
     * Create a new {@code LinkTree} object, to represent a {@code {@link } } tag.
     * @param ref the API element being referenced
     * @param label an optional label for the link
     * @return a {@code LinkTree} object
     */
    LinkTree newLinkTree(ReferenceTree ref, List<? extends DocTree> label);

    /**
     * Create a new {@code LinkPlainTree} object, to represent a {@code {@linkplain } } tag.
     * @param ref the API element being referenced
     * @param label an optional label for the link
     * @return a {@code LinkPlainTree} object
     */
    LinkTree newLinkPlainTree(ReferenceTree ref, List<? extends DocTree> label);

    /**
     * Create a new {@code LiteralTree} object, to represent a {@code {@literal } } tag.
     * @param text the content of the tag
     * @return a {@code LiteralTree} object
     */
    LiteralTree newLiteralTree(TextTree text);

    /**
     * Create a new {@code ParamTree} object, to represent a {@code @param } tag.
     * @param isTypeParameter true if this is a type parameter, and false otherwise
     * @param name the parameter being described
     * @param description the description of the parameter
     * @return a {@code ParamTree} object
     */
    ParamTree newParamTree(boolean isTypeParameter, IdentifierTree name, List<? extends DocTree> description);

    /**
     * Create a new {@code ProvidesTree} object, to represent a {@code @provides } tag.
     * @param name the name of the service type
     * @param description a description of the service being provided
     * @return a {@code ProvidesTree} object
     */
    ProvidesTree newProvidesTree(ReferenceTree name, List<? extends DocTree> description);

    /**
     * Create a new {@code ReferenceTree} object, to represent a reference to an API element.
     *
     * @param signature the doc comment signature of the reference
     * @return a {@code ReferenceTree} object
     */
    ReferenceTree newReferenceTree(String signature);

    /**
     * Create a new {@code ReturnTree} object, to represent a {@code @return } tag.
     * @param description the description of the return value of a method
     * @return a {@code ReturnTree} object
     */
    ReturnTree newReturnTree(List<? extends DocTree> description);

    /**
     * Create a new {@code SeeTree} object, to represent a {@code @see } tag.
     * @param reference the reference
     * @return a {@code SeeTree} object
     */
    SeeTree newSeeTree(List<? extends DocTree> reference);

    /**
     * Create a new {@code SerialTree} object, to represent a {@code @serial } tag.
     * @param description the description for the tag
     * @return a {@code SerialTree} object
     */
    SerialTree newSerialTree(List<? extends DocTree> description);

    /**
     * Create a new {@code SerialDataTree} object, to represent a {@code @serialData } tag.
     * @param description the description for the tag
     * @return a {@code SerialDataTree} object
     */
    SerialDataTree newSerialDataTree(List<? extends DocTree> description);

    /**
     * Create a new {@code SerialFieldTree} object, to represent a {@code @serialField } tag.
     * @param name the name of the field
     * @param type the type of the field
     * @param description the description of the field
     * @return a {@code SerialFieldTree} object
     */
    SerialFieldTree newSerialFieldTree(IdentifierTree name, ReferenceTree type, List<? extends DocTree> description);

    /**
     * Create a new {@code SinceTree} object, to represent a {@code @since } tag.
     * @param text the content of the tag
     * @return a {@code SinceTree} object
     */
    SinceTree newSinceTree(List<? extends DocTree> text);

    /**
     * Create a new {@code StartElementTree} object, to represent the start of an HTML element.
     * @param name the name of the HTML element
     * @param attrs the attributes
     * @param selfClosing true if the start element is marked as self-closing; otherwise false
     * @return a {@code StartElementTree} object
     */
    StartElementTree newStartElementTree(Name name, List<? extends DocTree> attrs, boolean selfClosing);

    /**
     * Create a new {@code SummaryTree} object, to represent a {@code @summary } tag.
     *
     * @implSpec This implementation throws {@code UnsupportedOperationException}.
     *
     * @param summary the content of the tag
     * @return a {@code SummaryTree} object
     * @since 10
     */
    default SummaryTree newSummaryTree(List<? extends DocTree> summary) {
        throw new UnsupportedOperationException("not implemented");
    }

    /**
     * Create a new {@code TextTree} object, to represent some plain text.
     * @param text the text
     * @return a {@code TextTree} object
     */
    TextTree newTextTree(String text);

    /**
     * Create a new {@code ThrowsTree} object, to represent a {@code @throws } tag.
     * @param name the name of the exception
     * @param description a description of why the exception might be thrown
     * @return a {@code ThrowsTree} object
     */
    ThrowsTree newThrowsTree(ReferenceTree name, List<? extends DocTree> description);

    /**
     * Create a new {@code UnknownBlockTagTree} object, to represent an unrecognized block tag.
     * @param name the name of the block tag
     * @param content the content
     * @return an {@code UnknownBlockTagTree} object
     */
    UnknownBlockTagTree newUnknownBlockTagTree(Name name, List<? extends DocTree> content);

    /**
     * Create a new {@code UnknownInlineTagTree} object, to represent an unrecognized inline tag.
     * @param name the name of the inline tag
     * @param content the content
     * @return an {@code UnknownInlineTagTree} object
     */
    UnknownInlineTagTree newUnknownInlineTagTree(Name name, List<? extends DocTree> content);

    /**
     * Create a new {@code UsesTree} object, to represent a {@code @uses } tag.
     * @param name the name of the service type
     * @param description a description of how the service will be used
     * @return a {@code UsesTree} object
     */
    UsesTree newUsesTree(ReferenceTree name, List<? extends DocTree> description);

    /**
     * Create a new {@code ValueTree} object, to represent a {@code {@value } } tag.
     * @param ref a reference to the value
     * @return a {@code ValueTree} object
     */
    ValueTree newValueTree(ReferenceTree ref);

    /**
     * Create a new {@code VersionTree} object, to represent a {@code {@version } } tag.
     * @param text the content of the tag
     * @return a {@code VersionTree} object
     */
    VersionTree newVersionTree(List<? extends DocTree> text);

    /**
     * Set the position to be recorded in subsequent tree nodes created by this factory.
     * The position should be a character offset relative to the beginning of the source file
     * or {@link javax2.tools.Diagnostic#NOPOS NOPOS}.
     * @param pos the position
     * @return this object, to facilitate method chaining
     */
    DocTreeFactory at(int pos);

    /**
     * Get the first sentence contained in a list of content.
     * The determination of the first sentence is implementation specific, and may
     * involve the use of a locale-specific {@link java.text.BreakIterator BreakIterator}
     * and other heuristics.
     * The resulting list may share a common set of initial items with the input list.
     * @param list the list
     * @return a list containing the first sentence of the list.
     */
    List<DocTree> getFirstSentence(List<? extends DocTree> list);

}
