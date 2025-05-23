package org.javacs;

import com.sun2.source.tree.CompilationUnitTree;
import com.sun2.source.util.JavacTask;

public class ParseTask {
    public final JavacTask task;
    public final CompilationUnitTree root;

    public ParseTask(JavacTask task, CompilationUnitTree root) {
        this.task = task;
        this.root = root;
    }
}
