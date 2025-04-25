package org.javacs.rewrite;

import com.sun2.source.tree.IdentifierTree;
import com.sun2.source.tree.MemberReferenceTree;
import com.sun2.source.tree.MemberSelectTree;
import com.sun2.source.tree.MethodTree;
import com.sun2.source.util.*;
import java.util.function.Consumer;

class FindMethodReferences extends TreePathScanner<Void, Consumer<TreePath>> {

    @Override
    public Void visitMethod(MethodTree t, Consumer<TreePath> forEach) {
        forEach.accept(getCurrentPath());
        return super.visitMethod(t, forEach);
    }

    @Override
    public Void visitIdentifier(IdentifierTree t, Consumer<TreePath> forEach) {
        forEach.accept(getCurrentPath());
        return super.visitIdentifier(t, forEach);
    }

    @Override
    public Void visitMemberSelect(MemberSelectTree t, Consumer<TreePath> forEach) {
        forEach.accept(getCurrentPath());
        return super.visitMemberSelect(t, forEach);
    }

    @Override
    public Void visitMemberReference(MemberReferenceTree t, Consumer<TreePath> forEach) {
        forEach.accept(getCurrentPath());
        return super.visitMemberReference(t, forEach);
    }
}
