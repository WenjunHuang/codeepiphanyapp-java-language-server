/*
 * Copyright (c) 1999, 2018, Oracle and/or its affiliates. All rights reserved.
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

package com.sun2.tools.javac.main;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.file.NoSuchFileException;
import java.security.CodeSource;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax2.tools.JavaFileManager;

import com.sun2.tools.javac.api.BasicJavacTask;
import com.sun2.tools.javac.file.CacheFSInfo;
import com.sun2.tools.javac.file.BaseFileManager;
import com.sun2.tools.javac.file.JavacFileManager;
import com.sun2.tools.javac.jvm.Target;
import com.sun2.tools.javac.main.CommandLine.UnmatchedQuote;
import com.sun2.tools.javac.platform.PlatformDescription;
import com.sun2.tools.javac.processing.AnnotationProcessingError;
import com.sun2.tools.javac.resources.CompilerProperties.Errors;
import com.sun2.tools.javac.util.*;
import com.sun2.tools.javac.util.JCDiagnostic.DiagnosticInfo;
import com.sun2.tools.javac.util.Log.PrefixKind;
import com.sun2.tools.javac.util.Log.WriterKind;

/** This class provides a command line interface to the javac compiler.
 *
 *  <p><b>This is NOT part of any supported API.
 *  If you write code that depends on this, you do so at your own risk.
 *  This code and its internal interfaces are subject to change or
 *  deletion without notice.</b>
 */
public class Main {

    /** The name of the compiler, for use in diagnostics.
     */
    String ownName;

    /** The writer to use for normal output.
     */
    PrintWriter stdOut;

    /** The writer to use for diagnostic output.
     */
    PrintWriter stdErr;

    /** The log to use for diagnostic output.
     */
    public Log log;

    /**
     * If true, certain errors will cause an exception, such as command line
     * arg errors, or exceptions in user provided code.
     */
    boolean apiMode;

    private static final String ENV_OPT_NAME = "JDK_JAVAC_OPTIONS";

    /** Result codes.
     */
    public enum Result {
        OK(0),        // Compilation completed with no errors.
        ERROR(1),     // Completed but reported errors.
        CMDERR(2),    // Bad command-line arguments
        SYSERR(3),    // System error or resource exhaustion.
        ABNORMAL(4);  // Compiler terminated abnormally

        Result(int exitCode) {
            this.exitCode = exitCode;
        }

        public boolean isOK() {
            return (exitCode == 0);
        }

        public final int exitCode;
    }

    /**
     * Construct a compiler instance.
     * @param name the name of this tool
     */
    public Main(String name) {
        this.ownName = name;
    }

    /**
     * Construct a compiler instance.
     * @param name the name of this tool
     * @param out a stream to which to write messages
     */
    public Main(String name, PrintWriter out) {
        this.ownName = name;
        this.stdOut = this.stdErr = out;
    }

    /**
     * Construct a compiler instance.
     * @param name the name of this tool
     * @param out a stream to which to write expected output
     * @param err a stream to which to write diagnostic output
     */
    public Main(String name, PrintWriter out, PrintWriter err) {
        this.ownName = name;
        this.stdOut = out;
        this.stdErr = err;
    }

    /** Report a usage error.
     */
    void reportDiag(DiagnosticInfo diag) {
        if (apiMode) {
            String msg = log.localize(diag);
            throw new PropagatedException(new IllegalStateException(msg));
        }
        reportHelper(diag);
        log.printLines(PrefixKind.JAVAC, "msg.usage", ownName);
    }

    /** Report helper.
     */
    void reportHelper(DiagnosticInfo diag) {
        String msg = log.localize(diag);
        String errorPrefix = log.localize(Errors.Error);
        msg = msg.startsWith(errorPrefix) ? msg : errorPrefix + msg;
        log.printRawLines(msg);
    }


    /**
     * Programmatic interface for main function.
     * @param args  the command line parameters
     * @return the result of the compilation
     */
    public Result compile(String[] args) {
        Context context = new Context();
        JavacFileManager.preRegister(context); // can't create it until Log has been set up
        Result result = compile(args, context);
        try {
            // A fresh context was created above, so the file manager can be safely closed:
            if (fileManager != null)
                fileManager.close();
        } catch (IOException ex) {
            bugMessage(ex);
        }
        return result;
    }

    /**
     * Internal version of compile, allowing context to be provided.
     * Note that the context needs to have a file manager set up.
     * @param argv  the command line parameters
     * @param context the context
     * @return the result of the compilation
     */
    public Result compile(String[] argv, Context context) {
        if (stdOut != null) {
            context.put(Log.outKey, stdOut);
        }

        if (stdErr != null) {
            context.put(Log.errKey, stdErr);
        }

        log = Log.instance(context);

        if (argv.length == 0) {
            OptionHelper h = new OptionHelper.GrumpyHelper(log) {
                @Override
                public String getOwnName() { return ownName; }
                @Override
                public void put(String name, String value) { }
            };
            try {
                Option.HELP.process(h, "-help");
            } catch (Option.InvalidValueException ignore) {
            }
            return Result.CMDERR;
        }

        // prefix argv with contents of environment variable and expand @-files
        try {
            argv = CommandLine.parse(ENV_OPT_NAME, argv);
        } catch (UnmatchedQuote ex) {
            reportDiag(Errors.UnmatchedQuote(ex.variableName));
            return Result.CMDERR;
        } catch (FileNotFoundException | NoSuchFileException e) {
            reportHelper(Errors.FileNotFound(e.getMessage()));
            return Result.SYSERR;
        } catch (IOException ex) {
            log.printLines(PrefixKind.JAVAC, "msg.io");
            ex.printStackTrace(log.getWriter(WriterKind.NOTICE));
            return Result.SYSERR;
        }

        Arguments args = Arguments.instance(context);
        args.init(ownName, argv);

        if (log.nerrors > 0)
            return Result.CMDERR;

        Options options = Options.instance(context);

        // init Log
        boolean forceStdOut = options.isSet("stdout");
        if (forceStdOut) {
            log.flush();
            log.setWriters(new PrintWriter(System.out, true));
        }

        // init CacheFSInfo
        // allow System property in following line as a Mustang legacy
        boolean batchMode = (options.isUnset("nonBatchMode")
                    && System.getProperty("nonBatchMode") == null);
        if (batchMode)
            CacheFSInfo.preRegister(context);

        boolean ok = true;

        // init file manager
        fileManager = context.get(JavaFileManager.class);
        JavaFileManager undel = fileManager instanceof DelegatingJavaFileManager ?
                ((DelegatingJavaFileManager) fileManager).getBaseFileManager() : fileManager;
        if (undel instanceof BaseFileManager) {
            ((BaseFileManager) undel).setContext(context); // reinit with options
            ok &= ((BaseFileManager) undel).handleOptions(args.getDeferredFileManagerOptions());
        }

        // handle this here so it works even if no other options given
        String showClass = options.get("showClass");
        if (showClass != null) {
            if (showClass.equals("showClass")) // no value given for option
                showClass = "com.javac.tools.sun2.Main";
            showClass(showClass);
        }

        ok &= args.validate();
        if (!ok || log.nerrors > 0)
            return Result.CMDERR;

        if (args.isEmpty())
            return Result.OK;

        // init Dependencies
        if (options.isSet("debug.completionDeps")) {
            Dependencies.GraphDependencies.preRegister(context);
        }

        // init plugins
        Set<List<String>> pluginOpts = args.getPluginOpts();
        if (!pluginOpts.isEmpty() || context.get(PlatformDescription.class) != null) {
            BasicJavacTask t = (BasicJavacTask) BasicJavacTask.instance(context);
            t.initPlugins(pluginOpts);
        }

        // init multi-release jar handling
        if (fileManager.isSupportedOption(Option.MULTIRELEASE.primaryName) == 1) {
            Target target = Target.instance(context);
            List<String> list = List.of(target.multiReleaseValue());
            fileManager.handleOption(Option.MULTIRELEASE.primaryName, list.iterator());
        }

        // init JavaCompiler
        JavaCompiler comp = JavaCompiler.instance(context);

        // init doclint
        List<String> docLintOpts = args.getDocLintOpts();
        if (!docLintOpts.isEmpty()) {
            BasicJavacTask t = (BasicJavacTask) BasicJavacTask.instance(context);
            t.initDocLint(docLintOpts);
        }

        if (options.get(Option.XSTDOUT) != null) {
            // Stdout reassigned - ask compiler to close it when it is done
            comp.closeables = comp.closeables.prepend(log.getWriter(WriterKind.NOTICE));
        }

        try {
            comp.compile(args.getFileObjects(), args.getClassNames(), null, List.nil());

            if (log.expectDiagKeys != null) {
                if (log.expectDiagKeys.isEmpty()) {
                    log.printRawLines("all expected diagnostics found");
                    return Result.OK;
                } else {
                    log.printRawLines("expected diagnostic keys not found: " + log.expectDiagKeys);
                    return Result.ERROR;
                }
            }

            return (comp.errorCount() == 0) ? Result.OK : Result.ERROR;

        } catch (OutOfMemoryError | StackOverflowError ex) {
            resourceMessage(ex);
            return Result.SYSERR;
        } catch (FatalError ex) {
            feMessage(ex, options);
            return Result.SYSERR;
        } catch (AnnotationProcessingError ex) {
            apMessage(ex);
            return Result.SYSERR;
        } catch (PropagatedException ex) {
            // TODO: what about errors from plugins?   should not simply rethrow the error here
            throw ex.getCause();
        } catch (IllegalAccessError iae) {
            if (twoClassLoadersInUse(iae)) {
                bugMessage(iae);
            }
            return Result.ABNORMAL;
        } catch (Throwable ex) {
            // Nasty.  If we've already reported an error, compensate
            // for buggy compiler error recovery by swallowing thrown
            // exceptions.
            if (comp == null || comp.errorCount() == 0 || options.isSet("dev"))
                bugMessage(ex);
            return Result.ABNORMAL;
        } finally {
            if (comp != null) {
                try {
                    comp.close();
                } catch (ClientCodeException ex) {
                    throw new RuntimeException(ex.getCause());
                }
            }
        }
    }

    private boolean twoClassLoadersInUse(IllegalAccessError iae) {
        String msg = iae.getMessage();
        Pattern pattern = Pattern.compile("(?i)(?<=tried to access class )([a-z_$][a-z\\d_$]*\\.)*[a-z_$][a-z\\d_$]*");
        Matcher matcher = pattern.matcher(msg);
        if (matcher.find()) {
            try {
                String otherClassName = matcher.group(0);
                Class<?> otherClass = Class.forName(otherClassName);
                ClassLoader otherClassLoader = otherClass.getClassLoader();
                ClassLoader javacClassLoader = this.getClass().getClassLoader();
                if (javacClassLoader != otherClassLoader) {
                    CodeSource otherClassCodeSource = otherClass.getProtectionDomain().getCodeSource();
                    CodeSource javacCodeSource = this.getClass().getProtectionDomain().getCodeSource();
                    if (otherClassCodeSource != null && javacCodeSource != null) {
                        log.printLines(Errors.TwoClassLoaders2(otherClassCodeSource.getLocation(),
                                javacCodeSource.getLocation()));
                    } else {
                        log.printLines(Errors.TwoClassLoaders1);
                    }
                    return true;
                }
            } catch (Throwable t) {
                return false;
            }
        }
        return false;
    }

    /** Print a message reporting an internal error.
     */
    void bugMessage(Throwable ex) {
        log.printLines(PrefixKind.JAVAC, "msg.bug", JavaCompiler.version());
        ex.printStackTrace(log.getWriter(WriterKind.NOTICE));
    }

    /** Print a message reporting a fatal error.
     */
    void feMessage(Throwable ex, Options options) {
        log.printRawLines(ex.getMessage());
        if (ex.getCause() != null && options.isSet("dev")) {
            ex.getCause().printStackTrace(log.getWriter(WriterKind.NOTICE));
        }
    }

    /** Print a message reporting an input/output error.
     */
    void ioMessage(Throwable ex) {
        log.printLines(PrefixKind.JAVAC, "msg.io");
        ex.printStackTrace(log.getWriter(WriterKind.NOTICE));
    }

    /** Print a message reporting an out-of-resources error.
     */
    void resourceMessage(Throwable ex) {
        log.printLines(PrefixKind.JAVAC, "msg.resource");
        ex.printStackTrace(log.getWriter(WriterKind.NOTICE));
    }

    /** Print a message reporting an uncaught exception from an
     * annotation processor.
     */
    void apMessage(AnnotationProcessingError ex) {
        log.printLines(PrefixKind.JAVAC, "msg.proc.annotation.uncaught.exception");
        ex.getCause().printStackTrace(log.getWriter(WriterKind.NOTICE));
    }

    /** Print a message reporting an uncaught exception from an
     * annotation processor.
     */
    void pluginMessage(Throwable ex) {
        log.printLines(PrefixKind.JAVAC, "msg.plugin.uncaught.exception");
        ex.printStackTrace(log.getWriter(WriterKind.NOTICE));
    }

    /** Display the location and checksum of a class. */
    void showClass(String className) {
        PrintWriter pw = log.getWriter(WriterKind.NOTICE);
        pw.println("javac: show class: " + className);

        URL url = getClass().getResource('/' + className.replace('.', '/') + ".class");
        if (url != null) {
            pw.println("  " + url);
        }

        try (InputStream in = getClass().getResourceAsStream('/' + className.replace('.', '/') + ".class")) {
            final String algorithm = "MD5";
            byte[] digest;
            MessageDigest md = MessageDigest.getInstance(algorithm);
            try (DigestInputStream din = new DigestInputStream(in, md)) {
                byte[] buf = new byte[8192];
                int n;
                do { n = din.read(buf); } while (n > 0);
                digest = md.digest();
            }
            StringBuilder sb = new StringBuilder();
            for (byte b: digest)
                sb.append(String.format("%02x", b));
            pw.println("  " + algorithm + " checksum: " + sb);
        } catch (NoSuchAlgorithmException | IOException e) {
            pw.println("  cannot compute digest: " + e);
        }
    }

    // TODO: update this to JavacFileManager
    private JavaFileManager fileManager;

    /* ************************************************************************
     * Internationalization
     *************************************************************************/

    public static final String javacBundleName =
            "com.sun2.tools.javac.resources.javac";
}
