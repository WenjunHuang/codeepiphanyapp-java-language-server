/*
 * Copyright (c) 2018, 2024, Oracle and/or its affiliates. All rights reserved.
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

package sun2.security.ssl;

import java.io.IOException;
import java.net.SocketException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;

/**
 * SSL/(D)TLS transportation context.
 */
class TransportContext implements ConnectionContext {
    final SSLTransport              transport;

    // registered plaintext consumers
    final Map<Byte, SSLConsumer>    consumers;
    final AccessControlContext      acc;

    final SSLContextImpl            sslContext;
    final SSLConfiguration          sslConfig;
    final InputRecord               inputRecord;
    final OutputRecord              outputRecord;

    // connection status
    boolean                         isUnsureMode;
    boolean                         isNegotiated = false;
    boolean                         isBroken = false;
    boolean                         isInputCloseNotified = false;
    boolean                         peerUserCanceled = false;
    Exception                       closeReason = null;
    Exception                       delegatedThrown = null;

    // negotiated security parameters
    SSLSessionImpl                  conSession;
    ProtocolVersion                 protocolVersion;
    String                          applicationProtocol= null;

    // handshake context
    HandshakeContext                handshakeContext = null;

    // connection reserved status for handshake.
    boolean                         secureRenegotiation = false;
    byte[]                          clientVerifyData;
    byte[]                          serverVerifyData;

    // connection sensitive configuration
    List<NamedGroup>                serverRequestedNamedGroups;

    CipherSuite cipherSuite;
    private static final byte[] emptyByteArray = new byte[0];

    // Please never use the transport parameter other than storing a
    // reference to this object.
    //
    // Called by SSLEngineImpl
    TransportContext(SSLContextImpl sslContext, SSLTransport transport,
            InputRecord inputRecord, OutputRecord outputRecord) {
        this(sslContext, transport, new SSLConfiguration(sslContext, false),
                inputRecord, outputRecord, true);
    }

    // Please never use the transport parameter other than storing a
    // reference to this object.
    //
    // Called by SSLSocketImpl
    TransportContext(SSLContextImpl sslContext, SSLTransport transport,
            InputRecord inputRecord, OutputRecord outputRecord,
            boolean isClientMode) {
        this(sslContext, transport,
                new SSLConfiguration(sslContext, isClientMode),
                inputRecord, outputRecord, false);
    }

    // Please never use the transport parameter other than storing a
    // reference to this object.
    //
    // Called by SSLSocketImpl with an existing SSLConfig
    TransportContext(SSLContextImpl sslContext, SSLTransport transport,
            SSLConfiguration sslConfig,
            InputRecord inputRecord, OutputRecord outputRecord) {
        this(sslContext, transport, (SSLConfiguration)sslConfig.clone(),
                inputRecord, outputRecord, false);
    }

    private TransportContext(SSLContextImpl sslContext, SSLTransport transport,
            SSLConfiguration sslConfig, InputRecord inputRecord,
            OutputRecord outputRecord, boolean isUnsureMode) {
        this.transport = transport;
        this.sslContext = sslContext;
        this.inputRecord = inputRecord;
        this.outputRecord = outputRecord;
        this.sslConfig = sslConfig;
        if (this.sslConfig.maximumPacketSize == 0) {
            this.sslConfig.maximumPacketSize = outputRecord.getMaxPacketSize();
        }
        this.isUnsureMode = isUnsureMode;

        // initial security parameters
        this.conSession = new SSLSessionImpl();
        this.protocolVersion = this.sslConfig.maximumProtocolVersion;
        this.clientVerifyData = emptyByteArray;
        this.serverVerifyData = emptyByteArray;

        this.acc = AccessController.getContext();
        this.consumers = new HashMap<>();

        if (inputRecord instanceof DTLSInputRecord) {
            DTLSInputRecord dtlsInputRecord = (DTLSInputRecord)inputRecord;
            dtlsInputRecord.setTransportContext(this);
            dtlsInputRecord.setSSLContext(this.sslContext);
        }
    }

    // Dispatch plaintext to a specific consumer.
    void dispatch(Plaintext plaintext) throws IOException {
        if (plaintext == null) {
            return;
        }

        ContentType ct = ContentType.valueOf(plaintext.contentType);
        if (ct == null) {
            throw fatal(Alert.UNEXPECTED_MESSAGE,
                "Unknown content type: " + plaintext.contentType);
        }

        switch (ct) {
            case HANDSHAKE:
                byte type = HandshakeContext.getHandshakeType(this,
                        plaintext);
                if (handshakeContext == null) {
                    if (type == SSLHandshake.KEY_UPDATE.id ||
                            type == SSLHandshake.NEW_SESSION_TICKET.id) {
                        if (!isNegotiated) {
                            throw fatal(Alert.UNEXPECTED_MESSAGE,
                                    "Unexpected unnegotiated post-handshake" +
                                            " message: " +
                                            SSLHandshake.nameOf(type));
                        }

                        if (!PostHandshakeContext.isConsumable(this, type)) {
                            throw fatal(Alert.UNEXPECTED_MESSAGE,
                                    "Unexpected post-handshake message: " +
                                    SSLHandshake.nameOf(type));
                        }

                        handshakeContext = new PostHandshakeContext(this);
                    } else {
                        handshakeContext = sslConfig.isClientMode ?
                                new ClientHandshakeContext(sslContext, this) :
                                new ServerHandshakeContext(sslContext, this);
                        outputRecord.initHandshaker();
                    }
                }
                handshakeContext.dispatch(type, plaintext);
                break;
            case ALERT:
                Alert.alertConsumer.consume(this, plaintext.fragment);
                break;
            default:
                SSLConsumer consumer = consumers.get(plaintext.contentType);
                if (consumer != null) {
                    consumer.consume(this, plaintext.fragment);
                } else {
                    throw fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unexpected content: " + plaintext.contentType);
                }
        }
    }

    void kickstart() throws IOException {
        if (isUnsureMode) {
            throw new IllegalStateException("Client/Server mode not yet set.");
        }

        // The threshold for allowing the method to continue processing
        // depends on whether we are doing a key update or kickstarting
        // a handshake.  In the former case, we only require the write-side
        // to be open where a handshake would require a full duplex connection.
        boolean isNotUsable = outputRecord.writeCipher.atKeyLimit() ?
            (outputRecord.isClosed() || isBroken) :
            (outputRecord.isClosed() || inputRecord.isClosed() || isBroken);
        if (isNotUsable) {
            if (closeReason != null) {
                throw new SSLException(
                        "Cannot kickstart, the connection is broken or closed",
                        closeReason);
            } else {
                throw new SSLException(
                        "Cannot kickstart, the connection is broken or closed");
            }
        }

        // initialize the handshaker if necessary
        if (handshakeContext == null) {
            //  TLS1.3 post-handshake
            if (isNegotiated && protocolVersion.useTLS13PlusSpec()) {
                handshakeContext = new PostHandshakeContext(this);
            } else {
                handshakeContext = sslConfig.isClientMode ?
                        new ClientHandshakeContext(sslContext, this) :
                        new ServerHandshakeContext(sslContext, this);
                outputRecord.initHandshaker();
            }
        }

        // kickstart the handshake if needed
        //
        // Need no kickstart message on server side unless the connection
        // has been established.
        if (isNegotiated || sslConfig.isClientMode) {
           handshakeContext.kickstart();
        }
    }

    boolean isPostHandshakeContext() {
        return handshakeContext != null &&
                (handshakeContext instanceof PostHandshakeContext);
    }

    // Note: Don't use this method for close_nofity, use closeNotify() instead.
    void warning(Alert alert) {
        // For initial handshaking, don't send a warning alert message to peer
        // if handshaker has not started.
        if (isNegotiated || handshakeContext != null) {
            try {
                outputRecord.encodeAlert(Alert.Level.WARNING.level, alert.id);
            } catch (IOException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning(
                        "Warning: failed to send warning alert " + alert, ioe);
                }
            }
        }
    }

    // Note: close_notify is delivered as a warning alert.
    void closeNotify(boolean isUserCanceled) throws IOException {
        // Socket transport is special because of the SO_LINGER impact.
        if (transport instanceof SSLSocketImpl) {
            ((SSLSocketImpl)transport).closeNotify(isUserCanceled);
        } else {
            // Need a lock here so that the user_canceled alert and the
            // close_notify alert can be delivered together.
            outputRecord.recordLock.lock();
            try {
                try {
                    // send a user_canceled alert if needed.
                    if (isUserCanceled) {
                        warning(Alert.USER_CANCELED);
                    }

                    // send a close_notify alert
                    warning(Alert.CLOSE_NOTIFY);
                } finally {
                    outputRecord.close();
                }
            } finally {
                outputRecord.recordLock.unlock();
            }
        }
    }

    SSLException fatal(Alert alert,
            String diagnostic) throws SSLException {
        return fatal(alert, diagnostic, null);
    }

    SSLException fatal(Alert alert, Throwable cause) throws SSLException {
        return fatal(alert, null, cause);
    }

    SSLException fatal(Alert alert,
            String diagnostic, Throwable cause) throws SSLException {
        return fatal(alert, diagnostic, false, cause);
    }

    // Note: close_notify is not delivered via fatal() methods.
    SSLException fatal(Alert alert, String diagnostic,
            boolean recvFatalAlert, Throwable cause) throws SSLException {
        // If we've already shutdown because of an error, there is nothing we
        // can do except rethrow the exception.
        //
        // Most exceptions seen here will be SSLExceptions. We may find the
        // occasional Exception which hasn't been converted to a SSLException,
        // so we'll do it here.
        if (closeReason != null) {
            if (cause == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning(
                            "Closed transport, general or untracked problem");
                }
                throw alert.createSSLException(
                        "Closed transport, general or untracked problem");
            }

            if (cause instanceof SSLException) {
                throw (SSLException)cause;
            } else {    // unlikely, but just in case.
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning(
                            "Closed transport, unexpected rethrowing", cause);
                }
                throw alert.createSSLException("Unexpected rethrowing", cause);
            }
        }

        // If we have no further information, make a general-purpose
        // message for folks to see.  We generally have one or the other.
        if (diagnostic == null) {
            if (cause == null) {
                diagnostic = "General/Untracked problem";
            } else {
                diagnostic = cause.getMessage();
            }
        }

        if (cause == null) {
            cause = alert.createSSLException(diagnostic);
        }

        // shutdown the transport
        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
            SSLLogger.severe("Fatal (" + alert + "): " + diagnostic, cause);
        }

        // remember the close reason
        if (cause instanceof SSLException) {
            closeReason = (SSLException)cause;
        } else {
            // Including RuntimeException, but we'll throw those down below.
            closeReason = alert.createSSLException(diagnostic, cause);
        }

        // close inbound
        try {
            inputRecord.close();
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("Fatal: input record closure failed", ioe);
            }

            closeReason.addSuppressed(ioe);
        }

        // invalidate the session
        if (conSession != null) {
            // In the case of a low-layer transport error, we want to prevent
            // the session from being invalidated since this is not a TLS-level
            // error event.
            if (!(cause instanceof SocketException)) {
                conSession.invalidate();
            }
        }

        if (handshakeContext != null &&
                handshakeContext.handshakeSession != null) {
            handshakeContext.handshakeSession.invalidate();
        }

        // send fatal alert
        //
        // If we haven't even started handshaking yet, or we are the recipient
        // of a fatal alert, no need to generate a fatal close alert.
        if (!recvFatalAlert && !isOutboundClosed() && !isBroken &&
                (isNegotiated || handshakeContext != null)) {
            try {
                outputRecord.encodeAlert(Alert.Level.FATAL.level, alert.id);
            } catch (IOException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning(
                        "Fatal: failed to send fatal alert " + alert, ioe);
                }

                closeReason.addSuppressed(ioe);
            }
        }

        // close outbound
        try {
            outputRecord.close();
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("Fatal: output record closure failed", ioe);
            }

            closeReason.addSuppressed(ioe);
        }

        // terminate the handshake context
        if (handshakeContext != null) {
            handshakeContext = null;
        }

        // terminate the transport
        try {
            transport.shutdown();
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("Fatal: transport closure failed", ioe);
            }

            closeReason.addSuppressed(ioe);
        } finally {
            isBroken = true;
        }

        if (closeReason instanceof SSLException) {
            throw (SSLException)closeReason;
        } else {
            throw (RuntimeException)closeReason;
        }
    }

    void setUseClientMode(boolean useClientMode) {
        // Once handshaking has begun, the mode can not be reset for the
        // life of this engine.
        if (handshakeContext != null || isNegotiated) {
            throw new IllegalArgumentException(
                    "Cannot change mode after SSL traffic has started");
        }

        /*
         * If we need to change the client mode and the enabled
         * protocols and cipher suites haven't specifically been
         * set by the user, change them to the corresponding
         * default ones.
         */
        if (sslConfig.isClientMode != useClientMode) {
            if (sslContext.isDefaultProtocolVesions(
                    sslConfig.enabledProtocols)) {
                sslConfig.enabledProtocols =
                        sslContext.getDefaultProtocolVersions(!useClientMode);
            }

            if (sslContext.isDefaultCipherSuiteList(
                    sslConfig.enabledCipherSuites)) {
                sslConfig.enabledCipherSuites =
                        sslContext.getDefaultCipherSuites(!useClientMode);
            }

            sslConfig.toggleClientMode();
        }

        isUnsureMode = false;
    }

    // The OutputRecord is closed and not buffered output record.
    boolean isOutboundDone() {
        return outputRecord.isClosed() && outputRecord.isEmpty();
    }

    // The OutputRecord is closed, but buffered output record may be still
    // waiting for delivery to the underlying connection.
    boolean isOutboundClosed() {
        return outputRecord.isClosed();
    }

    boolean isInboundClosed() {
        return inputRecord.isClosed();
    }

    // Close inbound, no more data should be delivered to the underlying
    // transportation connection.
    void closeInbound() throws SSLException {
        if (isInboundClosed()) {
            return;
        }

        try {
            // Important note: check if the initial handshake is started at
            // first so that the passiveInboundClose() implementation need not
            // to consider the case any more.
            if (!isInputCloseNotified) {
                // the initial handshake is not started
                initiateInboundClose();
            } else {
                passiveInboundClose();
            }
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("inbound closure failed", ioe);
            }
        }
    }

    // Close the connection passively.  The closure could be kickoff by
    // receiving a close_notify alert or reaching end_of_file of the socket.
    //
    // Note that this method is called only if the initial handshake has
    // started or completed.
    private void passiveInboundClose() throws IOException {
        if (!isInboundClosed()) {
            inputRecord.close();
        }

        // For TLS 1.2 and prior version, it is required to respond with
        // a close_notify alert of its own and close down the connection
        // immediately, discarding any pending writes.
        if (!isOutboundClosed()) {
            boolean needCloseNotify = SSLConfiguration.acknowledgeCloseNotify;
            if (!needCloseNotify) {
                if (isNegotiated) {
                    if (!protocolVersion.useTLS13PlusSpec()) {
                        needCloseNotify = true;
                    }
                } else if (handshakeContext != null) {  // initial handshake
                    ProtocolVersion pv = handshakeContext.negotiatedProtocol;
                    if (pv == null || (!pv.useTLS13PlusSpec())) {
                        needCloseNotify = true;
                    }
                }
            }

            if (needCloseNotify) {
                closeNotify(false);
            }
        }
    }

    // Initiate a inbound close when the handshake is not started.
    private void initiateInboundClose() throws IOException {
        if (!isInboundClosed()) {
            inputRecord.close();
        }
    }

    // Close outbound, no more data should be received from the underlying
    // transportation connection.
    void closeOutbound() {
        if (isOutboundClosed()) {
            return;
        }

        try {
             initiateOutboundClose();
        } catch (IOException ioe) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound closure failed", ioe);
            }
        }
    }

    // Initiate a close by sending a close_notify alert.
    private void initiateOutboundClose() throws IOException {
        boolean useUserCanceled = false;
        if (!isNegotiated && (handshakeContext != null) && !peerUserCanceled) {
            // initial handshake
            useUserCanceled = true;
        }

        closeNotify(useUserCanceled);
    }

    // Note; HandshakeStatus.FINISHED status is retrieved in other places.
    HandshakeStatus getHandshakeStatus() {
        if (!outputRecord.isEmpty()) {
            // If no handshaking, special case to wrap alters or
            // post-handshake messages.
            return HandshakeStatus.NEED_WRAP;
        } else if (isOutboundClosed() && isInboundClosed()) {
            return HandshakeStatus.NOT_HANDSHAKING;
        } else if (handshakeContext != null) {
            if (!handshakeContext.delegatedActions.isEmpty()) {
                return HandshakeStatus.NEED_TASK;
            } else if (!isInboundClosed()) {
                if (sslContext.isDTLS() &&
                        !inputRecord.isEmpty()) {
                    return HandshakeStatus.NEED_UNWRAP_AGAIN;
                } else {
                    return HandshakeStatus.NEED_UNWRAP;
                }
            } else if (!isOutboundClosed()) {
                // Special case that the inbound was closed, but outbound open.
                return HandshakeStatus.NEED_WRAP;
            }   // Otherwise, both inbound and outbound are closed.
        }

        return HandshakeStatus.NOT_HANDSHAKING;
    }

    HandshakeStatus finishHandshake() {
        if (protocolVersion.useTLS13PlusSpec()) {
            outputRecord.tc = this;
            inputRecord.tc = this;
            cipherSuite = handshakeContext.negotiatedCipherSuite;
            inputRecord.readCipher.baseSecret =
                    handshakeContext.baseReadSecret;
            outputRecord.writeCipher.baseSecret =
                    handshakeContext.baseWriteSecret;
        }

        handshakeContext = null;
        outputRecord.handshakeHash.finish();
        inputRecord.finishHandshake();
        outputRecord.finishHandshake();
        isNegotiated = true;

        // Tell folk about handshake completion, but do it in a separate thread.
        if (transport instanceof SSLSocket &&
                sslConfig.handshakeListeners != null &&
                !sslConfig.handshakeListeners.isEmpty()) {
            HandshakeCompletedEvent hce =
                new HandshakeCompletedEvent((SSLSocket)transport, conSession);
            Thread thread = new Thread(
                null,
                new NotifyHandshake(sslConfig.handshakeListeners, hce),
                "HandshakeCompletedNotify-Thread",
                0,
                false);
            thread.start();
        }

        return HandshakeStatus.FINISHED;
    }

    HandshakeStatus finishPostHandshake() {
        handshakeContext = null;

        // Note: May need trigger handshake completion even for post-handshake
        // authentication in the future.

        return HandshakeStatus.FINISHED;
    }

    // A separate thread is allocated to deliver handshake completion
    // events.
    private static class NotifyHandshake implements Runnable {
        private final Set<Map.Entry<HandshakeCompletedListener,
                AccessControlContext>> targets;         // who gets notified
        private final HandshakeCompletedEvent event;    // the notification

        NotifyHandshake(
                Map<HandshakeCompletedListener,AccessControlContext> listeners,
                HandshakeCompletedEvent event) {
            this.targets = new HashSet<>(listeners.entrySet());     // clone
            this.event = event;
        }

        @Override
        public void run() {
            // Don't need to synchronize, as it only runs in one thread.
            for (Map.Entry<HandshakeCompletedListener,
                    AccessControlContext> entry : targets) {
                final HandshakeCompletedListener listener = entry.getKey();
                AccessControlContext acc = entry.getValue();
                AccessController.doPrivileged(new PrivilegedAction<Void>() {
                    @Override
                    public Void run() {
                        listener.handshakeCompleted(event);
                        return null;
                    }
                }, acc);
            }
        }
    }
}
