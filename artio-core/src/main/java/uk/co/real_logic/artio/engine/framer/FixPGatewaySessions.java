/*
 * Copyright 2021 Monotonic Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modifications copyright (C) 2025 - Vermiculus Financial Technology AB
 */
package uk.co.real_logic.artio.engine.framer;

import org.agrona.ErrorHandler;
import org.agrona.concurrent.EpochClock;
import org.agrona.concurrent.UnsafeBuffer;
import uk.co.real_logic.artio.DebugLogger;
import uk.co.real_logic.artio.LogTag;
import uk.co.real_logic.artio.engine.EngineConfiguration;
import uk.co.real_logic.artio.engine.logger.SequenceNumberIndexReader;
import uk.co.real_logic.artio.fixp.AbstractFixPProxy;
import uk.co.real_logic.artio.fixp.FixPFirstMessageResponse;
import uk.co.real_logic.artio.fixp.FixPProtocolFactory;
import uk.co.real_logic.artio.fixp.InternalFixPContext;
import uk.co.real_logic.artio.messages.DisconnectReason;
import uk.co.real_logic.artio.messages.FixPProtocolType;
import uk.co.real_logic.artio.messages.InboundFixPConnectEncoder;
import uk.co.real_logic.artio.messages.MessageHeaderEncoder;
import uk.co.real_logic.artio.protocol.GatewayPublication;
import uk.co.real_logic.artio.util.CharFormatter;
import uk.co.real_logic.artio.util.MutableAsciiBuffer;
import uk.co.real_logic.artio.validation.FixPAuthenticationProxy;

import java.io.IOException;
import java.util.List;

import static uk.co.real_logic.artio.engine.framer.TcpChannel.UNKNOWN_SEQ_NUM;

public class FixPGatewaySessions extends GatewaySessions
{
    static final int ACCEPTED_HEADER_LENGTH = MessageHeaderEncoder.ENCODED_LENGTH +
        InboundFixPConnectEncoder.BLOCK_LENGTH;
    static final int FORCE_LOGOUT_MS = Integer.parseInt(FixPProtocolFactory
        .getEnvProp("fix.protocol.fixp.force_logout_ms", "1000"));

    private final CharFormatter awaitForceLogoutFormatter = new CharFormatter(
        "Await force-logout for session %s, conn %s old-conn %s");
    private final EngineConfiguration engineConfiguration;
    private final FixPContexts fixPContexts;
    private final QueryLibrariesCommand libCmd = new QueryLibrariesCommand();

    FixPGatewaySessions(
        final EpochClock epochClock,
        final GatewayPublication inboundPublication,
        final GatewayPublication outboundPublication,
        final ErrorHandler errorHandler,
        final SequenceNumberIndexReader sentSequenceNumberIndex,
        final SequenceNumberIndexReader receivedSequenceNumberIndex,
        final EngineConfiguration engineConfiguration,
        final FixPContexts fixPContexts)
    {
        super(
            epochClock,
            inboundPublication,
            outboundPublication,
            errorHandler,
            sentSequenceNumberIndex,
            receivedSequenceNumberIndex);
        this.engineConfiguration = engineConfiguration;
        this.fixPContexts = fixPContexts;
    }

    protected void setLastSequenceResetTime(final GatewaySession gatewaySession)
    {
    }

    public AcceptorLogonResult authenticate(
        final long sessionId,
        final MutableAsciiBuffer buffer,
        final int offset,
        final int messageSize,
        final FixPGatewaySession gatewaySession,
        final long connectionId,
        final TcpChannel channel,
        final Framer framer,
        final FixPProtocolType protocolType,
        final InternalFixPContext identification,
        final AbstractFixPProxy fixPProxy,
        final ReceiverEndPoint receiverEndPoint)
    {
        return new FixPPendingAcceptorLogon(
            sessionId,
            buffer,
            offset,
            messageSize,
            gatewaySession,
            connectionId,
            channel,
            framer,
            protocolType,
            identification,
            fixPProxy,
            receiverEndPoint);
    }

    public FixPContexts fixPContexts()
    {
        return fixPContexts;
    }

    class FixPPendingAcceptorLogon extends PendingAcceptorLogon implements FixPAuthenticationProxy
    {
        public static final int LINGER_TIMEOUT_IN_MS = 500;

        private final long sessionId;
        private final MutableAsciiBuffer buffer;
        private final int offset;
        private final int messageSize;
        private final FixPProtocolType protocolType;
        private final InternalFixPContext identification;
        private final AbstractFixPProxy fixPProxy;

        private FixPFirstMessageResponse fixPFirstMessageResponse;
        private Enum<?> rejectCode;
        private long forceLogoutStartTime;
        private boolean forceLogoutSent;
        private int defaultLibraryId;

        FixPPendingAcceptorLogon(
            final long sessionId,
            final MutableAsciiBuffer buffer,
            final int offset,
            final int messageSize,
            final FixPGatewaySession gatewaySession,
            final long connectionId,
            final TcpChannel channel,
            final Framer framer,
            final FixPProtocolType protocolType,
            final InternalFixPContext identification,
            final AbstractFixPProxy fixPProxy,
            final ReceiverEndPoint receiverEndPoint)
        {
            super(gatewaySession, connectionId, channel, framer, receiverEndPoint);
            this.sessionId = sessionId;
            this.buffer = buffer;
            this.offset = offset;
            this.messageSize = messageSize;
            this.protocolType = protocolType;
            this.identification = identification;
            this.fixPProxy = fixPProxy;

            final FixPFirstMessageResponse rejectReason = fixPContexts.onAcceptorLogon(
                sessionId, identification, connectionId, false);
            if (rejectReason == FixPFirstMessageResponse.OK)
            {
                authenticate(connectionId);
            }
            else
            {
                internalReject(rejectReason, null);
            }
        }

        protected void authenticate(final long connectionId)
        {
            try
            {
                engineConfiguration.fixPAuthenticationStrategy().authenticate(identification, this);
            }
            catch (final Throwable throwable)
            {
                onStrategyError("authentication", throwable, connectionId, "false",
                    identification.toString());

                if (state != AuthenticationState.REJECTED)
                {
                    reject();
                }
            }
        }

        protected void onAuthenticated()
        {
            if (!checkLogoutExisting())
            {
                return;
            }

            final FixPGatewaySession session = (FixPGatewaySession)this.session;
            session.authenticated();
            if (framer.onFixPLogonMessageReceived(session, sessionId))
            {
                setState(AuthenticationState.ACCEPTED);
            }
            else
            {
                final MessageHeaderEncoder header = new MessageHeaderEncoder();
                final InboundFixPConnectEncoder inboundFixPConnect = new InboundFixPConnectEncoder();
                final UnsafeBuffer logonBuffer = new UnsafeBuffer(new byte[ACCEPTED_HEADER_LENGTH]);
                inboundFixPConnect
                    .wrapAndApplyHeader(logonBuffer, 0, header)
                    .connection(connectionId)
                    .sessionId(sessionId)
                    .protocolType(protocolType)
                    .messageLength(messageSize);

                final long position = inboundPublication.dataPublication().offer(
                    logonBuffer, 0, ACCEPTED_HEADER_LENGTH,
                    buffer, offset, messageSize);

                if (position < 0)
                {
                    System.out.println("position = " + position); // TODO
                }
                else
                {
                    setState(AuthenticationState.ACCEPTED);
                }
            }
        }

        protected boolean checkLogoutExisting()
        {
            final GatewaySession libSess = getLibrarySession();
            if (libSess != null && !libSess.isOffline())
            {
                checkForceLogout(libSess.libraryId(), libSess.connectionId());
                return false;
            }

            final long connId = fixPContexts.onAuthenticated(sessionId, identification, connectionId);
            if (connId != connectionId)
            {
                checkForceLogout(libSess != null ? libSess.libraryId() : defaultLibraryId, connId);
                return false;
            }

            return true;
        }

        protected void checkForceLogout(final int libraryId, final long connId)
        {
            final long now = System.currentTimeMillis();
            if (forceLogoutStartTime == 0)
            {
                DebugLogger.log(LogTag.FIXP_SESSION, awaitForceLogoutFormatter,
                    sessionId, connectionId, connId);
                forceLogoutStartTime = now;
            }
            if (!forceLogoutSent && now - forceLogoutStartTime >= FORCE_LOGOUT_MS)
            {
                forceLogoutSent = true;
                framer.onRequestDisconnect(libraryId, connId, DisconnectReason.DUPLICATE_SESSION);
            }
        }

        /**
         * Return the existing library session to force disconnect.
         * Note that we cannot use GatewaySessions since it is not updated with library info!
         *
         * @return library gateway session
         */
        protected GatewaySession getLibrarySession()
        {
            // Find library for session
            final List<LibraryInfo> libs = getLibraries();
            if (libs != null)
            {
                for (int i = 0; i < libs.size(); i++)
                {
                    if (libs.get(i) instanceof LiveLibraryInfo liveLib)
                    {
                        defaultLibraryId = liveLib.libraryId();
                        final GatewaySession sess = liveLib.lookupSessionById(sessionId);
                        if (sess != null)
                        {
                            return sess;
                        }
                    }
                }
            }
            return null;
        }

        protected List<LibraryInfo> getLibraries()
        {
            final List<LibraryInfo> libs = libCmd.resultIfPresent();
            if (libs != null && libs.size() > 1)
            {
                return libs;
            }
            // Initialize lib query
            framer.onQueryLibraries(libCmd);
            return libCmd.resultIfPresent();
        }

        protected void encodeRejectMessage()
        {
            rejectEncodeBuffer = fixPProxy.encodeReject(identification, fixPFirstMessageResponse, rejectCode);
        }

        protected SendRejectResult sendReject()
        {
            try
            {
                channel.write(rejectEncodeBuffer, UNKNOWN_SEQ_NUM, false);
                return rejectEncodeBuffer.hasRemaining() ? SendRejectResult.BACK_PRESSURED : SendRejectResult.INFLIGHT;
            }
            catch (final IOException e)
            {
                return SendRejectResult.DISCONNECTED;
            }
        }

        public void reject()
        {
            reject((Enum<?>)null);
        }

        public void reject(final Enum<?> rejectCode)
        {
            internalReject(FixPFirstMessageResponse.CREDENTIALS, rejectCode);
        }

        private void internalReject(final FixPFirstMessageResponse response, final Enum<?> rejectCode)
        {
            if (rejectCode != null)
            {
                identification.validate(rejectCode);
            }

            this.reason = DisconnectReason.FAILED_AUTHENTICATION;
            this.fixPFirstMessageResponse = response;
            this.rejectCode = rejectCode;
            this.lingerTimeoutInMs = LINGER_TIMEOUT_IN_MS;
            setState(AuthenticationState.SAVING_REJECTED_LOGON_WITH_REPLY);
        }

        public String remoteAddress()
        {
            return channel.remoteAddr();
        }
    }
}
