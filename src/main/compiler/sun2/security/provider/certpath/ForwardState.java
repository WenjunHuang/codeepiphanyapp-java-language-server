/*
 * Copyright (c) 2000, 2023, Oracle and/or its affiliates. All rights reserved.
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

package sun2.security.provider.certpath;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import javax.security.auth.x500.X500Principal;

import sun2.security.util.Debug;
import sun2.security.x509.X509CertImpl;

/**
 * A specification of a forward PKIX validation state
 * which is initialized by each build and updated each time a
 * certificate is added to the current path.
 * @since       1.4
 * @author      Yassir Elley
 */
class ForwardState implements State {

    private static final Debug debug = Debug.getInstance("certpath");

    /* The issuer DN of the last cert in the path */
    X500Principal issuerDN;

    /* The last cert in the path */
    X509CertImpl cert;

    /*
     * The number of intermediate CA certs which have been traversed so
     * far in the path
     */
    int traversedCACerts;

    /* Flag indicating if state is initial (path is just starting) */
    private boolean init = true;

    /* the untrusted certificates checker */
    UntrustedChecker untrustedChecker;

    /* The list of user-defined checkers that support forward checking */
    ArrayList<PKIXCertPathChecker> forwardCheckers;

    /* Flag indicating if last cert in path is self-issued */
    boolean selfIssued;

    /**
     * Returns a boolean flag indicating if the state is initial
     * (just starting)
     *
     * @return boolean flag indicating if the state is initial (just starting)
     */
    @Override
    public boolean isInitial() {
        return init;
    }

    /**
     * Display state for debugging purposes
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("State [");
        sb.append("\n  issuerDN of last cert: ").append(issuerDN);
        sb.append("\n  traversedCACerts: ").append(traversedCACerts);
        sb.append("\n  init: ").append(String.valueOf(init));
        sb.append("\n  selfIssued: ").append
                 (String.valueOf(selfIssued));
        sb.append("]\n");
        return sb.toString();
    }

    /**
     * Initialize the state.
     *
     * @param certPathCheckers the list of user-defined PKIXCertPathCheckers
     */
    public void initState(List<PKIXCertPathChecker> certPathCheckers)
        throws CertPathValidatorException
    {
        traversedCACerts = 0;

        /*
         * Populate forwardCheckers with every user-defined checker
         * that supports forward checking and initialize the forwardCheckers
         */
        forwardCheckers = new ArrayList<PKIXCertPathChecker>();
        for (PKIXCertPathChecker checker : certPathCheckers) {
            if (checker.isForwardCheckingSupported()) {
                checker.init(true);
                forwardCheckers.add(checker);
            }
        }

        init = true;
    }

    /**
     * Update the state with the next certificate added to the path.
     *
     * @param cert the certificate which is used to update the state
     */
    @Override
    public void updateState(X509Certificate cert)
        throws CertificateException, IOException, CertPathValidatorException {

        if (cert == null)
            return;

        X509CertImpl icert = X509CertImpl.toImpl(cert);

        /* update certificate */
        this.cert = icert;

        /* update issuer DN */
        issuerDN = cert.getIssuerX500Principal();

        selfIssued = X509CertImpl.isSelfIssued(cert);
        if (!selfIssued) {

            /*
             * update traversedCACerts only if this is a non-self-issued
             * intermediate CA cert
             */
            if (!init && cert.getBasicConstraints() != -1) {
                traversedCACerts++;
            }
        }

        init = false;
    }

    /*
     * Clone current state. The state is cloned as each cert is
     * added to the path. This is necessary if backtracking occurs,
     * and a prior state needs to be restored.
     */
    @Override
    @SuppressWarnings("unchecked") // Safe casts assuming clone() works correctly
    public Object clone() {
        try {
            ForwardState clonedState = (ForwardState) super.clone();

            /* clone checkers, if cloneable */
            clonedState.forwardCheckers = (ArrayList<PKIXCertPathChecker>)
                                                forwardCheckers.clone();
            ListIterator<PKIXCertPathChecker> li =
                                clonedState.forwardCheckers.listIterator();
            while (li.hasNext()) {
                PKIXCertPathChecker checker = li.next();
                if (checker instanceof Cloneable) {
                    li.set((PKIXCertPathChecker)checker.clone());
                }
            }

            return clonedState;
        } catch (CloneNotSupportedException e) {
            throw new InternalError(e.toString(), e);
        }
    }
}
