/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
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

package com.sun2.tools.javac.code;

import com.sun2.tools.javac.code.Lint.LintCategory;
import com.sun2.tools.javac.code.Source.Feature;
import com.sun2.tools.javac.jvm.Target;
import com.sun2.tools.javac.resources.CompilerProperties.Errors;
import com.sun2.tools.javac.resources.CompilerProperties.Warnings;
import com.sun2.tools.javac.util.Assert;
import com.sun2.tools.javac.util.Context;
import com.sun2.tools.javac.util.JCDiagnostic.DiagnosticPosition;
import com.sun2.tools.javac.util.JCDiagnostic.SimpleDiagnosticPosition;
import com.sun2.tools.javac.util.Log;
import com.sun2.tools.javac.util.MandatoryWarningHandler;
import com.sun2.tools.javac.util.Options;

import com.sun2.tools.javac.util.JCDiagnostic.Error;
import javax2.tools.JavaFileObject;
import java.util.HashMap;
import java.util.Map;

import static com.sun2.tools.javac.main.Option.PREVIEW;

/**
 * Helper class to handle preview language features. This class maps certain language features
 * (see {@link Feature} into 'preview' features; the mapping is completely ad-hoc, so as to allow
 * for maximum flexibility, which allows to migrate preview feature into supported features with ease.
 *
 * This class acts as a centralized point against which usages of preview features are reported by
 * clients (e.g. other javac classes). Internally, this class collects all such usages and generates
 * diagnostics to inform the user of such usages. Such diagnostics can be enabled using the
 * {@link LintCategory#PREVIEW} lint category, and are suppressible by usual means.
 */
public class Preview {

    /** flag: are preview featutres enabled */
    private final boolean enabled;

    /** the diag handler to manage preview feature usage diagnostics */
    private final MandatoryWarningHandler previewHandler;

    /** test flag: should all features be considered as preview features? */
    private final boolean forcePreview;

    /** a mapping from classfile numbers to Java SE versions */
    private final Map<Integer, Source> majorVersionToSource;


    private final Lint lint;
    private final Log log;

    private static final Context.Key<Preview> previewKey = new Context.Key<>();

    public static Preview instance(Context context) {
        Preview instance = context.get(previewKey);
        if (instance == null) {
            instance = new Preview(context);
        }
        return instance;
    }

    Preview(Context context) {
        context.put(previewKey, this);
        Options options = Options.instance(context);
        enabled = options.isSet(PREVIEW);
        log = Log.instance(context);
        lint = Lint.instance(context);
        this.previewHandler =
                new MandatoryWarningHandler(log, lint.isEnabled(LintCategory.PREVIEW), true, "preview", LintCategory.PREVIEW);
        forcePreview = options.isSet("forcePreview");
        majorVersionToSource = initMajorVersionToSourceMap();
    }

    private Map<Integer, Source> initMajorVersionToSourceMap() {
        Map<Integer, Source> majorVersionToSource = new HashMap<>();
        for (Target t : Target.values()) {
            int major = t.majorVersion;
            Source source = Source.lookup(t.name);
            if (source != null) {
                majorVersionToSource.put(major, source);
            }
        }
        return majorVersionToSource;
   }

    /**
     * Report usage of a preview feature. Usages reported through this method will affect the
     * set of sourcefiles with dependencies on preview features.
     * @param pos the position at which the preview feature was used.
     * @param feature the preview feature used.
     */
    public void warnPreview(int pos, Feature feature) {
        warnPreview(new SimpleDiagnosticPosition(pos), feature);
    }

    /**
     * Report usage of a preview feature. Usages reported through this method will affect the
     * set of sourcefiles with dependencies on preview features.
     * @param pos the position at which the preview feature was used.
     * @param feature the preview feature used.
     */
    public void warnPreview(DiagnosticPosition pos, Feature feature) {
        Assert.check(isEnabled());
        Assert.check(isPreview(feature));
        if (!lint.isSuppressed(LintCategory.PREVIEW)) {
            previewHandler.report(pos, feature.isPlural() ?
                    Warnings.PreviewFeatureUsePlural(feature.nameFragment()) :
                    Warnings.PreviewFeatureUse(feature.nameFragment()));
        }
    }

    /**
     * Report usage of a preview feature in classfile.
     * @param classfile the name of the classfile with preview features enabled
     * @param majorVersion the major version found in the classfile.
     */
    public void warnPreview(JavaFileObject classfile, int majorVersion) {
        Assert.check(isEnabled());
        if (!lint.isSuppressed(LintCategory.PREVIEW)) {
            previewHandler.report(null,
                    Warnings.PreviewFeatureUseClassfile(classfile, majorVersionToSource.get(majorVersion).name));
        }
    }

    /**
     * Are preview features enabled?
     * @return true, if preview features are enabled.
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Is given feature a preview feature?
     * @param feature the feature to be tested.
     * @return true, if given feature is a preview feature.
     */
    public boolean isPreview(Feature feature) {
        //Note: this is a backdoor which allows to optionally treat all features as 'preview' (for testing).
        //When real preview features will be added, this method can be implemented to return 'true'
        //for those selected features, and 'false' for all the others.
        return forcePreview;
    }

    /**
     * Generate an error key which captures the fact that a given preview feature could not be used
     * due to the preview feature support being disabled.
     * @param feature the feature for which the diagnostic has to be generated.
     * @return the diagnostic.
     */
    public Error disabledError(Feature feature) {
        Assert.check(!isEnabled());
        return feature.isPlural() ?
                Errors.PreviewFeatureDisabledPlural(feature.nameFragment()) :
                Errors.PreviewFeatureDisabled(feature.nameFragment());
    }

    /**
     * Generate an error key which captures the fact that a preview classfile cannot be loaded
     * due to the preview feature support being disabled.
     * @param classfile the name of the classfile with preview features enabled
     * @param majorVersion the major version found in the classfile.
     */
    public Error disabledError(JavaFileObject classfile, int majorVersion) {
        Assert.check(!isEnabled());
        return Errors.PreviewFeatureDisabledClassfile(classfile, majorVersionToSource.get(majorVersion).name);
    }

    /**
     * Report any deferred diagnostics.
     */
    public void reportDeferredDiagnostics() {
        previewHandler.reportDeferredDiagnostic();
    }
}
