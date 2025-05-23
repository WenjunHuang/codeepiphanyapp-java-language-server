/*
 * Copyright (c) 2015, 2017, Oracle and/or its affiliates. All rights reserved.
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

package com.sun2.tools.javac.api;

import java.io.PrintStream;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import com.sun2.source.tree.ClassTree;
import com.sun2.source.tree.CompilationUnitTree;
import com.sun2.source.util.JavacTask;
import com.sun2.source.util.TaskEvent;
import com.sun2.source.util.TaskEvent.Kind;
import com.sun2.source.util.TaskListener;
import com.sun2.source.util.TreeScanner;
import com.sun2.tools.javac.code.Kinds;
import com.sun2.tools.javac.code.Symbol;
import com.sun2.tools.javac.code.Symtab;
import com.sun2.tools.javac.code.Type;
import com.sun2.tools.javac.code.Type.ClassType;
import com.sun2.tools.javac.code.TypeTag;
import com.sun2.tools.javac.code.Types;
import com.sun2.tools.javac.comp.Annotate;
import com.sun2.tools.javac.comp.Check;
import com.sun2.tools.javac.comp.CompileStates;
import com.sun2.tools.javac.comp.Enter;
import com.sun2.tools.javac.comp.Modules;
import com.sun2.tools.javac.main.Arguments;
import com.sun2.tools.javac.main.JavaCompiler;
import com.sun2.tools.javac.tree.JCTree.JCClassDecl;

import javax2.tools.Diagnostic;
import javax2.tools.DiagnosticListener;
import javax2.tools.JavaFileManager;
import javax2.tools.JavaFileObject;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.sun2.tools.javac.model.JavacElements;
import com.sun2.tools.javac.util.Context;
import com.sun2.tools.javac.util.DefinedBy;
import com.sun2.tools.javac.util.DefinedBy.Api;
import com.sun2.tools.javac.util.Log;

/**
 * A pool of reusable JavacTasks. When a task is no valid anymore, it is returned to the pool,
 * and its Context may be reused for future processing in some cases. The reuse is achieved
 * by replacing some components (most notably JavaCompiler and Log) with reusable counterparts,
 * and by cleaning up leftovers from previous compilation.
 * <p>
 * For each combination of options, a separate task/context is created and kept, as most option
 * values are cached inside components themselves.
 * <p>
 * When the compilation redefines sensitive classes (e.g. classes in the the java.* packages), the
 * task/context is not reused.
 * <p>
 * When the task is reused, then packages that were already listed won't be listed again.
 * <p>
 * Care must be taken to only return tasks that won't be used by the original caller.
 * <p>
 * Care must also be taken when custom components are installed, as those are not cleaned when the
 * task/context is reused, and subsequent getTask may return a task based on a context with these
 * custom components.
 *
 * <p><b>This is NOT part of any supported API.
 * If you write code that depends on this, you do so at your own risk.
 * This code and its internal interfaces are subject to change or
 * deletion without notice.</b>
 */
public class JavacTaskPool {

    private static final JavacTool systemProvider = JavacTool.create();

    private final int maxPoolSize;
    private final Map<List<String>, List<ReusableContext>> options2Contexts = new HashMap<>();
    private int id;

    private int statReused = 0;
    private int statNew = 0;
    private int statPolluted = 0;
    private int statRemoved = 0;

    /**Creates the pool.
     *
     * @param maxPoolSize maximum number of tasks/context that will be kept in the pool.
     */
    public JavacTaskPool(int maxPoolSize) {
        this.maxPoolSize = maxPoolSize;
    }

    /**Creates a new task as if by {@link javax2.tools.JavaCompiler#getTask} and runs the provided
     * worker with it. The task is only valid while the worker is running. The internal structures
     * may be reused from some previous compilation.
     *
     * @param out a Writer for additional output from the compiler;
     * use {@code System.err} if {@code null}
     * @param fileManager a file manager; if {@code null} use the
     * compiler's standard filemanager
     * @param diagnosticListener a diagnostic listener; if {@code
     * null} use the compiler's default method for reporting
     * diagnostics
     * @param options compiler options, {@code null} means no options
     * @param classes names of classes to be processed by annotation
     * processing, {@code null} means no class names
     * @param compilationUnits the compilation units to compile, {@code
     * null} means no compilation units
     * @param worker that should be run with the task
     * @return an object representing the compilation
     * @throws RuntimeException if an unrecoverable error
     * occurred in a user supplied component.  The
     * {@linkplain Throwable#getCause() cause} will be the error in
     * user code.
     * @throws IllegalArgumentException if any of the options are invalid,
     * or if any of the given compilation units are of other kind than
     * {@linkplain JavaFileObject.Kind#SOURCE source}
     */
    public <Z> Z getTask(Writer out,
                         JavaFileManager fileManager,
                         DiagnosticListener<? super JavaFileObject> diagnosticListener,
                         Iterable<String> options,
                         Iterable<String> classes,
                         Iterable<? extends JavaFileObject> compilationUnits,
                         Worker<Z> worker) {
        List<String> opts =
                StreamSupport.stream(options.spliterator(), false)
                             .collect(Collectors.toCollection(ArrayList::new));

        ReusableContext ctx;

        synchronized (this) {
            List<ReusableContext> cached =
                    options2Contexts.getOrDefault(opts, Collections.emptyList());

            if (cached.isEmpty()) {
                ctx = new ReusableContext(opts);
                statNew++;
            } else {
                ctx = cached.remove(0);
                statReused++;
            }
        }

        ctx.useCount++;

        JavacTaskImpl task =
                (JavacTaskImpl) systemProvider.getTask(out, fileManager, diagnosticListener,
                                                       opts, classes, compilationUnits, ctx);

        task.addTaskListener(ctx);

        Z result = worker.withTask(task);

        //not returning the context to the pool if task crashes with an exception
        //the task/context may be in a broken state
        ctx.clear();
        if (ctx.polluted) {
            statPolluted++;
        } else {
            task.cleanup();
            synchronized (this) {
                while (cacheSize() + 1 > maxPoolSize) {
                    ReusableContext toRemove =
                            options2Contexts.values()
                                            .stream()
                                            .flatMap(Collection::stream)
                                            .sorted((c1, c2) -> c1.timeStamp < c2.timeStamp ? -1 : 1)
                                            .findFirst()
                                            .get();
                    options2Contexts.get(toRemove.arguments).remove(toRemove);
                    statRemoved++;
                }
                options2Contexts.computeIfAbsent(ctx.arguments, x -> new ArrayList<>()).add(ctx);
                ctx.timeStamp = id++;
            }
        }

        return result;
    }
    //where:
        private long cacheSize() {
            return options2Contexts.values().stream().flatMap(Collection::stream).count();
        }

    public void printStatistics(PrintStream out) {
        out.println(statReused + " reused Contexts");
        out.println(statNew + " newly created Contexts");
        out.println(statPolluted + " polluted Contexts");
        out.println(statRemoved + " removed Contexts");
    }

    public interface Worker<Z> {
        public Z withTask(JavacTask task);
    }

    static class ReusableContext extends Context implements TaskListener {

        Set<CompilationUnitTree> roots = new HashSet<>();

        List<String> arguments;
        boolean polluted = false;

        int useCount;
        long timeStamp;

        ReusableContext(List<String> arguments) {
            super();
            this.arguments = arguments;
            put(Log.logKey, ReusableLog.factory);
            put(JavaCompiler.compilerKey, ReusableJavaCompiler.factory);
        }

        void clear() {
            drop(Arguments.argsKey);
            drop(DiagnosticListener.class);
            drop(Log.outKey);
            drop(Log.errKey);
            drop(JavaFileManager.class);
            drop(JavacTask.class);
            drop(JavacTrees.class);
            drop(JavacElements.class);

            if (ht.get(Log.logKey) instanceof ReusableLog) {
                //log already inited - not first round
                ((ReusableLog)Log.instance(this)).clear();
                Enter.instance(this).newRound();
                ((ReusableJavaCompiler)ReusableJavaCompiler.instance(this)).clear();
                Types.instance(this).newRound();
                Check.instance(this).newRound();
                Modules.instance(this).newRound();
                Annotate.instance(this).newRound();
                CompileStates.instance(this).clear();
                MultiTaskListener.instance(this).clear();

                //find if any of the roots have redefined java.* classes
                Symtab syms = Symtab.instance(this);
                pollutionScanner.scan(roots, syms);
                roots.clear();
            }
        }

        /**
         * This scanner detects as to whether the shared context has been polluted. This happens
         * whenever a compiled program redefines a core class (in 'java.*' package) or when
         * (typically because of cyclic inheritance) the symbol kind of a core class has been touched.
         */
        TreeScanner<Void, Symtab> pollutionScanner = new TreeScanner<Void, Symtab>() {
            @Override @DefinedBy(Api.COMPILER_TREE)
            public Void visitClass(ClassTree node, Symtab syms) {
                Symbol sym = ((JCClassDecl)node).sym;
                if (sym != null) {
                    syms.removeClass(sym.packge().modle, sym.flatName());
                    Type sup = supertype(sym);
                    if (isCoreClass(sym) ||
                            (sup != null && isCoreClass(sup.tsym) && sup.tsym.kind != Kinds.Kind.TYP)) {
                        polluted = true;
                    }
                }
                return super.visitClass(node, syms);
            }

            private boolean isCoreClass(Symbol s) {
                return s.flatName().toString().startsWith("java.");
            }

            private Type supertype(Symbol s) {
                if (s.type == null ||
                        !s.type.hasTag(TypeTag.CLASS)) {
                    return null;
                } else {
                    ClassType ct = (ClassType)s.type;
                    return ct.supertype_field;
                }
            }
        };

        @Override @DefinedBy(Api.COMPILER_TREE)
        public void finished(TaskEvent e) {
            if (e.getKind() == Kind.PARSE) {
                roots.add(e.getCompilationUnit());
            }
        }

        @Override @DefinedBy(Api.COMPILER_TREE)
        public void started(TaskEvent e) {
            //do nothing
        }

        <T> void drop(Key<T> k) {
            ht.remove(k);
        }

        <T> void drop(Class<T> c) {
            ht.remove(key(c));
        }

        /**
         * Reusable JavaCompiler; exposes a method to clean up the component from leftovers associated with
         * previous compilations.
         */
        static class ReusableJavaCompiler extends JavaCompiler {

            final static Factory<JavaCompiler> factory = ReusableJavaCompiler::new;

            ReusableJavaCompiler(Context context) {
                super(context);
            }

            @Override
            public void close() {
                //do nothing
            }

            void clear() {
                newRound();
            }

            @Override
            protected void checkReusable() {
                //do nothing - it's ok to reuse the compiler
            }
        }

        /**
         * Reusable Log; exposes a method to clean up the component from leftovers associated with
         * previous compilations.
         */
        static class ReusableLog extends Log {

            final static Factory<Log> factory = ReusableLog::new;

            Context context;

            ReusableLog(Context context) {
                super(context);
                this.context = context;
            }

            void clear() {
                recorded.clear();
                sourceMap.clear();
                nerrors = 0;
                nwarnings = 0;
                //Set a fake listener that will lazily lookup the context for the 'real' listener. Since
                //this field is never updated when a new task is created, we cannot simply reset the field
                //or keep old value. This is a hack to workaround the limitations in the current infrastructure.
                diagListener = new DiagnosticListener<JavaFileObject>() {
                    DiagnosticListener<JavaFileObject> cachedListener;

                    @Override  @DefinedBy(Api.COMPILER)
                    @SuppressWarnings("unchecked")
                    public void report(Diagnostic<? extends JavaFileObject> diagnostic) {
                        if (cachedListener == null) {
                            cachedListener = context.get(DiagnosticListener.class);
                        }
                        cachedListener.report(diagnostic);
                    }
                };
            }
        }
    }
}
