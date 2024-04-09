/*
 * Modifications copyright (C) 2024 - Vermiculus Financial Technology AB
 */
package uk.co.real_logic.artio.library;

public class ReductSequenceReply extends LibraryReply<Boolean>
{
    private final long sessionId;
    private final boolean resetInput;

    ReductSequenceReply(final LibraryPoller libraryPoller, final long latestReplyArrivalTime,
        final long sessionId, final boolean resetInput)
    {
        super(libraryPoller, latestReplyArrivalTime);
        this.sessionId = sessionId;
        this.resetInput = resetInput;

        if (libraryPoller.isConnected())
        {
            sendMessage();
        }

    }

    @Override
    protected void sendMessage()
    {
        final long position = libraryPoller.saveReductSequenceUpdate(sessionId, resetInput);
        requiresResend = position < 0;

        if (!requiresResend)
        {
            onComplete(true);
        }
    }
}
