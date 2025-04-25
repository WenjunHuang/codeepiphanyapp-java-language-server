package org.javacs;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.javacs.guava.ClassPath;

class ScanClassPath {

    // TODO delete this and implement findPublicTypeDeclarationInJdk some other way
    /**
     * All exported modules that are present in JDK 10 or 11
     */
    static String[] JDK_MODULES = {
            "java.activation",
            "java.base",
            "java.compiler",
            "java.corba",
            "java.datatransfer",
            "java.desktop",
            "java.instrument",
            "java.jnlp",
            "java.logging",
            "java.management",
            "java.management.rmi",
            "java.naming",
            "java.net.http",
            "java.prefs",
            "java.rmi",
            "java.scripting",
            "java.se",
            "java.se.ee",
            "java.security.jgss",
            "java.security.sasl",
            "java.smartcardio",
            "java.sql",
            "java.sql.rowset",
            "java.transaction",
            "java.transaction.xa",
            "java.xml",
            "java.xml.bind",
            "java.xml.crypto",
            "java.xml.ws",
            "java.xml.ws.annotation",
            "javafx.base",
            "javafx.controls",
            "javafx.fxml",
            "javafx.graphics",
            "javafx.media",
            "javafx.swing",
            "javafx.web",
            "jdk2.accessibility",
            "jdk2.aot",
            "jdk2.attach",
            "jdk2.charsets",
            "jdk2.compiler",
            "jdk2.crypto.cryptoki",
            "jdk2.crypto.ec",
            "jdk2.dynalink",
            "jdk2.editpad",
            "jdk2.hotspot.agent",
            "jdk2.httpserver",
            "jdk2.incubator.httpclient",
            "jdk2.internal.ed",
            "jdk2.internal.jvmstat",
            "jdk2.internal.le",
            "jdk2.internal.opt",
            "jdk2.internal.vm.ci",
            "jdk2.internal.vm.compiler",
            "jdk2.internal.vm.compiler.management",
            "jdk2.jartool",
            "jdk2.javadoc",
            "jdk2.jcmd",
            "jdk2.jconsole",
            "jdk2.jdeps",
            "jdk2.jdi",
            "jdk2.jdwp.agent",
            "jdk2.jfr",
            "jdk2.jlink",
            "jdk2.jshell",
            "jdk2.jsobject",
            "jdk2.jstatd",
            "jdk2.localedata",
            "jdk2.management",
            "jdk2.management.agent",
            "jdk2.management.cmm",
            "jdk2.management.jfr",
            "jdk2.management.resource",
            "jdk2.naming.dns",
            "jdk2.naming.rmi",
            "jdk2.net",
            "jdk2.pack",
            "jdk2.packager.services",
            "jdk2.rmic",
            "jdk2.scripting.nashorn",
            "jdk2.scripting.nashorn.shell",
            "jdk2.sctp",
            "jdk2.security.auth",
            "jdk2.security.jgss",
            "jdk2.snmp",
            "jdk2.unsupported",
            "jdk2.unsupported.desktop",
            "jdk2.xml.dom",
            "jdk2.zipfs",
    };

    static Set<String> jdkTopLevelClasses() {
        LOG.info("Searching for top-level classes in the JDK");

        var classes = new HashSet<String>();
        var fs = FileSystems.getFileSystem(URI.create("jrt:/"));
        for (var m : JDK_MODULES) {
            var moduleRoot = fs.getPath(String.format("/modules/%s/", m));
            try (var stream = Files.walk(moduleRoot)) {
                var it = stream.iterator();
                while (it.hasNext()) {
                    var classFile = it.next();
                    var relative = moduleRoot.relativize(classFile).toString();
                    if (relative.endsWith(".class") && !relative.contains("$")) {
                        var trim = relative.substring(0, relative.length() - ".class".length());
                        var qualifiedName = trim.replace(File.separatorChar, '.');
                        classes.add(qualifiedName);
                    }
                }
            } catch (IOException e) {
                // LOG.log(Level.WARNING, "Failed indexing module " + m + "(" + e.getMessage() + ")");
            }
        }

        LOG.info(String.format("Found %d classes in the java platform", classes.size()));

        return classes;
    }

    static Set<String> jdkTopLevelClassesInPath(Path rootPath) {
        LOG.info("Searching for top-level classes in the JDK");

        var classes = new HashSet<String>();

        for (var m : JDK_MODULES) {
            var moduleRoot = rootPath.resolve(String.format("./modules/%s/", m));
            try (var stream = Files.walk(moduleRoot)) {
                var it = stream.iterator();
                while (it.hasNext()) {
                    var classFile = it.next();
                    var relative = moduleRoot.relativize(classFile).toString();
                    if (relative.endsWith(".class") && !relative.contains("$")) {
                        var trim = relative.substring(0, relative.length() - ".class".length());
                        var qualifiedName = trim.replace(File.separatorChar, '.');
                        classes.add(qualifiedName);
                    }
                }
            } catch (IOException e) {
                // LOG.log(Level.WARNING, "Failed indexing module " + m + "(" + e.getMessage() + ")");
            }
        }

        LOG.info(String.format("Found %d classes in the java platform", classes.size()));

        return classes;
    }

    static Set<String> classPathTopLevelClasses(Set<Path> classPath) {
        LOG.info(String.format("Searching for top-level classes in %d classpath locations", classPath.size()));

        var urls = classPath.stream().map(ScanClassPath::toUrl).toArray(URL[]::new);
        var classLoader = new URLClassLoader(urls, null);
        ClassPath scanner;
        try {
            scanner = ClassPath.from(classLoader);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        var classes = new HashSet<String>();
        for (var c : scanner.getTopLevelClasses()) {
            classes.add(c.getName());
        }

        LOG.info(String.format("Found %d classes in classpath", classes.size()));

        return classes;
    }

    private static URL toUrl(Path p) {
        try {
            return p.toUri().toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private static final Logger LOG = Logger.getLogger("main");
}
