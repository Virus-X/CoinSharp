using System;
using System.Collections.Generic;
using CoinSharp.Common;

namespace CoinSharp.Messages
{
    /// <summary>
    /// Alerts are signed messages that are broadcast on the peer-to-peer network if they match a hard-coded signing key.
    /// The private keys are held by a small group of core Bitcoin developers, and alerts may be broadcast in the event of
    /// an available upgrade or a serious network problem. Alerts have an expiration time, data that specifies what
    /// set of software versions it matches and the ability to cancel them by broadcasting another type of alert.<p>
    /// 
    /// The right course of action on receiving an alert is usually to either ensure a human will see it (display on screen,
    /// log, email), or if you decide to use alerts for notifications that are specific to your app in some way, to parse it.
    /// For example, you could treat it as an upgrade notification specific to your app. Satoshi designed alerts to ensure
    /// that software upgrades could be distributed independently of a hard-coded website, in order to allow everything to
    /// be purely peer-to-peer. You don't have to use this of course, and indeed it often makes more sense not to.<p>
    ///     
    /// Before doing anything with an alert, you should check <seealso cref="AlertMessage#isSignatureValid()"/>.
    /// </summary>
    public class AlertMessage : Message
    {
        private const long MaxSetSize = 100;

        private byte[] content;
        private byte[] signature;

        private HashSet<long?> cancelSet;
        private HashSet<string> matchingSubVers;

        /// <summary>
        /// Returns true if the digital signature attached to the message verifies. Don't do anything with the alert if it
        /// doesn't verify, because that would allow arbitrary attackers to spam your users.
        /// </summary>
        public virtual bool IsSignatureValid
        {
            get
			{
				return EcKey.Verify(Utils.DoubleDigest(content), signature, Params.AlertSigningKey);
			}
        }

        /// <summary>
        /// The time at which the alert should stop being broadcast across the network. Note that you can still receive
        /// the alert after this time from other nodes if the alert still applies to them or to you.
        /// </summary>
        public DateTime RelayUntil { get; set; }


        /// <summary>
        /// The time at which the alert ceases to be relevant. It should not be presented to the user or app administrator
        /// after this time.
        /// </summary>
        public DateTime Expiration { get; set; }


        /// <summary>
        /// The numeric identifier of this alert. Each alert should have a unique ID, but the signer can choose any number.
        /// If an alert is broadcast with a cancel field higher than this ID, this alert is considered cancelled. </summary>
        /// <returns> uint32 </returns>
        public long Id { get; set; }


        /// <summary>
        /// A marker that results in any alerts with an ID lower than this value to be considered cancelled. </summary>
        /// <returns> uint32 </returns>
        public long Cancel { get; set; }


        /// <summary>
        /// The inclusive lower bound on software versions that are considered for the purposes of this alert. The Satoshi
        /// client compares this against a protocol version field, but as long as the subVer field is used to restrict it your
        /// alerts could use any version numbers. </summary>
        /// <returns> uint32 </returns>
        public long MinVer { get; set; }


        /// <summary>
        /// The inclusive upper bound on software versions considered for the purposes of this alert. The Satoshi
        /// client compares this against a protocol version field, but as long as the subVer field is used to restrict it your
        /// alerts could use any version numbers.
        /// @return
        /// </summary>
        public long MaxVer { get; set; }


        /// <summary>
        /// Provides an integer ordering amongst simultaneously active alerts. </summary>
        /// <returns> uint32 </returns>
        public long Priority { get; set; }


        /// <summary>
        /// This field is unused. It is presumably intended for the author of the alert to provide a justification for it
        /// visible to protocol developers but not users.
        /// </summary>
        public string Comment { get; set; }


        /// <summary>
        /// A string that is intended to display in the status bar of the official GUI client. It contains the user-visible
        /// message. English only.
        /// </summary>
        public string StatusBar { get; set; }

        /// <summary>
        /// This field is never used.
        /// </summary>
        public string Reserved { get; set; }

        public long Version { get; private set; }

        public AlertMessage(NetworkParameters netParams, byte[] payloadBytes)
            : base(netParams, payloadBytes, 0)
        {
            Version = 1;
        }

        public override string ToString()
        {
            return "ALERT: " + StatusBar;
        }

        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: void parse() throws ProtocolException
        protected override void Parse()
        {
            // Alerts are formatted in two levels. The top level contains two byte arrays: a signature, and a serialized
            // data structure containing the actual alert data.
            int startPos = Cursor;
            content = ReadByteArray();
            signature = ReadByteArray();
            // Now we need to parse out the contents of the embedded structure. Rewind back to the start of the message.
            Cursor = startPos;
            ReadVarInt(); // Skip the length field on the content array.
            // We're inside the embedded structure.
            Version = ReadUint32();
            // Read the timestamps. Bitcoin uses seconds since the epoch.
            RelayUntil = UnixTime.FromUnixTime(ReadUint64());
            Expiration = UnixTime.FromUnixTime(ReadUint64());
            Id = ReadUint32();
            Cancel = ReadUint32();
            // Sets are serialized as <len><item><item><item>....
            var cancelSetSize = ReadVarInt();
            if (cancelSetSize < 0 || cancelSetSize > MaxSetSize)
            {
                throw new ProtocolException("Bad cancel set size: " + cancelSetSize);
            }

            cancelSet = new HashSet<long?>();
            for (ulong i = 0; i < cancelSetSize; i++)
            {
                cancelSet.Add(ReadUint32());
            }

            MinVer = ReadUint32();
            MaxVer = ReadUint32();
            // Read the subver matching set.
            var subverSetSize = ReadVarInt();
            if (subverSetSize < 0 || subverSetSize > MaxSetSize)
            {
                throw new ProtocolException("Bad subver set size: " + subverSetSize);
            }
            matchingSubVers = new HashSet<string>();
            for (ulong i = 0; i < subverSetSize; i++)
            {
                matchingSubVers.Add(ReadStr());
            }

            Priority = ReadUint32();
            Comment = ReadStr();
            StatusBar = ReadStr();
            Reserved = ReadStr();
        }
    }
}
