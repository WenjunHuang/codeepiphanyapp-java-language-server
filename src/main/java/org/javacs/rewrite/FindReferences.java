package org.javacs.rewrite;

import com.sun2.source.tree.IdentifierTree;
import com.sun2.source.tree.MemberReferenceTree;
import com.sun2.source.tree.MemberSelectTree;
import com.sun2.source.tree.VariableTree;
import com.sun2.source.util.*;
import java.util.function.Consumer;

class FindReferences extends TreePathScanner<Void, Consumer<TreePath>> {
    @Override
    public Void visitVariable(VariableTree node, Consumer<TreePath> forEach) {
        forEach.accept(getCurrentPath());
        return super.visitVariable(node, forEach);
    }

    @Override
    public Void visitIdentifier(IdentifierTree node, Consumer<TreePath> forEach) {
        forEach.accept(getCurrentPath());
        return super.visitIdentifier(node, forEach);
    }

    @Override
    public Void visitMemberSelect(MemberSelectTree node, Consumer<TreePath> forEach) {
        forEach.accept(getCurrentPath());
        return super.visitMemberSelect(node, forEach);
    }

    @Override
    public Void visitMemberReference(MemberReferenceTree node, Consumer<TreePath> forEach) {
        forEach.accept(getCurrentPath());
        return super.visitMemberReference(node, forEach);
    }
}
