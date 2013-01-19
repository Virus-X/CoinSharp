using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using Org.BouncyCastle.Math;

namespace CoinSharp
{
    /// <summary>
    /// <p>A TransactionConfidence object tracks data you can use to make a confidence decision about a transaction.
    /// It also contains some pre-canned rules for common scenarios: if you aren't really sure what level of confidence
    /// you need, these should prove useful. You can get a confidence object using <seealso cref="Transaction#getConfidence()"/>.
    /// They cannot be constructed directly.</p>
    /// 
    /// <p>Confidence in a transaction can come in multiple ways:</p>
    /// 
    /// <ul>
    /// <li>Because you created it yourself and only you have the necessary keys.</li>
    /// <li>Receiving it from a fully validating peer you know is trustworthy, for instance, because it's run by yourself.</li>
    /// <li>Receiving it from a peer on the network you randomly chose. If your network connection is not being
    ///     intercepted, you have a pretty good chance of connecting to a node that is following the rules.</li>
    /// <li>Receiving it from multiple peers on the network. If your network connection is not being intercepted,
    ///     hearing about a transaction from multiple peers indicates the network has accepted the transaction and
    ///     thus miners likely have too (miners have the final say in whether a transaction becomes valid or not).</li>
    /// <li>Seeing the transaction appear appear in a block on the main chain. Your confidence increases as the transaction
    ///     becomes further buried under work. Work can be measured either in blocks (roughly, units of time), or
    ///     amount of work done.</li>
    /// </ul>
    /// 
    /// <p>Alternatively, you may know that the transaction is "dead", that is, one or more of its inputs have
    /// been double spent and will never confirm unless there is another re-org.</p>
    /// 
    /// <p>TransactionConfidence is updated via the <seealso cref="TransactionConfidence#notifyWorkDone(Block)"/>
    /// method to ensure the block depth and work done are up to date.</p>
    /// To make a copy that won't be changed, use <seealso cref="TransactionConfidence#duplicate()"/>.
    /// </summary>
    public class TransactionConfidence
    {
        //// TODO use syncRoot, review the code
        
        /// <summary>
        /// The peers that have announced the transaction to us. Network nodes don't have stable identities, so we use
        /// IP address as an approximation. It's obviously vulnerable to being gamed if we allow arbitrary people to connect
        /// to us, so only peers we explicitly connected to should go here.
        /// </summary>
        private HashSet<PeerAddress> broadcastBy;

        private readonly object syncRoot = new object();

        /// <summary>
        /// The Transaction that this confidence object is associated with. </summary>
        private Transaction transaction;

        /// <summary>
        /// The depth of the transaction on the best chain in blocks. An unconfirmed block has depth 0, after one confirmation
        /// its depth is 1.
        /// </summary>
        private int depth;

        /// <summary>
        /// The cumulative work done for the blocks that bury this transaction. BigInteger.ZERO if the transaction is not
        /// on the best chain.
        /// </summary>
        private BigInteger workDone = BigInteger.Zero;

        /// <summary>
        /// <p>Called when the level of <seealso cref="TransactionConfidence"/> is updated by something, like
        /// for example a <seealso cref="Wallet"/>. You can add listeners to update your user interface or manage your order tracking
        /// system when confidence levels pass a certain threshold. <b>Note that confidence can go down as well as up.</b>
        /// For example, this can happen if somebody is doing a double-spend attack against you. Whilst it's unlikely, your
        /// code should be able to handle that in order to be correct.</p>        
        /// </summary>
        public event EventHandler<ConfidenceChangedEventArgs> ConfidenceChanged;

        /// <summary>
        /// Describes the state of the transaction in general terms. Properties can be read to learn specifics. </summary>
        public enum ConfidenceType
        {
            /// <summary>
            /// If BUILDING, then the transaction is included in the best chain and your confidence in it is increasing. </summary>
            BUILDING = 1,

            /// <summary>
            /// If NOT_SEEN_IN_CHAIN, then the transaction is pending and should be included shortly, as long as it is being
            /// announced and is considered valid by the network. A pending transaction will be announced if the containing
            /// wallet has been attached to a live <seealso cref="PeerGroup"/> using <seealso cref="PeerGroup#addWallet(Wallet)"/>.
            /// You can estimate how likely the transaction is to be included by connecting to a bunch of nodes then measuring
            /// how many announce it, using <seealso cref="TransactionConfidence#numBroadcastPeers()"/>.
            /// Or if you saw it from a trusted peer, you can assume it's valid and will get mined sooner or later as well.
            /// </summary>
            NOT_SEEN_IN_CHAIN = 2,

            /// <summary>
            /// If NOT_IN_BEST_CHAIN, then the transaction has been included in a block, but that block is on a fork. A
            /// transaction can change from BUILDING to NOT_IN_BEST_CHAIN and vice versa if a reorganization takes place,
            /// due to a split in the consensus.
            /// </summary>
            NOT_IN_BEST_CHAIN = 3,

            /// <summary>
            /// If DEAD, then it means the transaction won't confirm unless there is another re-org,
            /// because some other transaction is spending one of its inputs. Such transactions should be alerted to the user
            /// so they can take action, eg, suspending shipment of goods if they are a merchant.
            /// It can also mean that a coinbase transaction has been made dead from it being moved onto a side chain.
            /// </summary>
            DEAD = 4,

            /// <summary>
            /// If a transaction hasn't been broadcast yet, or there's no record of it, its confidence is UNKNOWN.
            /// </summary>
            UNKNOWN = 0
        }

        private ConfidenceType confidenceLevel = ConfidenceType.UNKNOWN;
        private int appearedAtChainHeight = -1;
        private Transaction overridingTransaction;

        public TransactionConfidence(Transaction tx)
        {
            // Assume a default number of peers for our set.
            broadcastBy = new HashSet<PeerAddress>();
            transaction = tx;
        }

        /// <summary>
        /// Gets or sets the chain height at which the transaction appeared if confidence type is BUILDING. </summary>
        /// <exception cref="InvalidOperationException"> if the confidence type is not BUILDING. </exception>        
        public virtual int AppearedAtChainHeight
        {
            get
            {
                lock (syncRoot)
                {
                    if (ConfidenceLevel != ConfidenceType.BUILDING)
                    {
                        throw new InvalidOperationException("Confidence type is " + ConfidenceLevel + ", not BUILDING");
                    }

                    return appearedAtChainHeight;
                }
            }

            set
            {
                if (value < 0)
                {
                    throw new ArgumentException("appearedAtChainHeight out of range");
                }

                lock (syncRoot)
                {
                    appearedAtChainHeight = value;
                    ConfidenceLevel = ConfidenceType.BUILDING;
                }
            }
        }

        /// <summary>
        /// Returns a general statement of the level of confidence you can have in this transaction.
        /// </summary>

        public virtual ConfidenceType ConfidenceLevel
        {
            get
            {
                return confidenceLevel;
            }
            set
            {
                // Don't inform the event listeners if the confidence didn't really change.
                if (value == confidenceLevel)
                {
                    return;
                }

                lock (syncRoot)
                {
                    confidenceLevel = value;
                    OnConfidenceChanged();
                }
            }
        }

        /// <summary>
        /// Called by a <seealso cref="Peer"/> when a transaction is pending and announced by a peer. The more peers announce the
        /// transaction, the more peers have validated it (assuming your internet connection is not being intercepted).
        /// If confidence is currently unknown, sets it to <seealso cref="ConfidenceLevel#NOT_SEEN_IN_CHAIN"/>. Listeners will be
        /// invoked in this case.
        /// </summary>
        /// <param name="address"> IP address of the peer, used as a proxy for identity. </param>
        public virtual void markBroadcastBy(PeerAddress address)
        {
            lock (this)
            {
                broadcastBy.Add(address);

                if (ConfidenceLevel == ConfidenceType.UNKNOWN)
                {
                    confidenceLevel = ConfidenceType.NOT_SEEN_IN_CHAIN;
                }
            }

            OnConfidenceChanged();
        }

        /// <summary>
        /// Returns how many peers have been passed to <seealso cref="TransactionConfidence#markBroadcastBy"/>.
        /// </summary>       
        public virtual int numBroadcastPeers()
        {
            return broadcastBy.Count;
        }

        /// <summary>
        /// Returns a synchronized set of <seealso cref="PeerAddress"/>es that announced the transaction.
        /// </summary>

        public virtual HashSet<PeerAddress> BroadcastBy
        {
            get
            {
                return broadcastBy;
            }
        }


        public override string ToString()
        {
            var builder = new StringBuilder();
            int peers = numBroadcastPeers();
            if (peers > 0)
            {
                builder.Append("Seen by ");
                builder.Append(peers);
                if (peers > 1)
                {
                    builder.Append(" peers. ");
                }
                else
                {
                    builder.Append(" peer. ");
                }
            }

            switch (confidenceLevel)
            {
                case ConfidenceType.UNKNOWN:
                    builder.Append("Unknown confidence level.");
                    break;
                case ConfidenceType.DEAD:
                    builder.Append("Dead: overridden by double spend and will not confirm.");
                    break;
                case ConfidenceType.NOT_IN_BEST_CHAIN:
                    builder.Append("Seen in side chain but not best chain.");
                    break;
                case ConfidenceType.NOT_SEEN_IN_CHAIN:
                    builder.Append("Not seen in chain.");
                    break;
                case ConfidenceType.BUILDING:
                    builder.AppendFormat("Appeared in best chain at height {0:D}, depth {1:D}, work done {2}.", AppearedAtChainHeight, DepthInBlocks, workDone.LongValue);
                    break;
            }
            return builder.ToString();
        }

        /// <summary>
        /// Called by the wallet when the tx appears on the best chain and a new block is added to the top.
        /// Updates the internal counter that tracks how deeply buried the block is.
        /// Work is the value of block.getWork().
        /// </summary>
        //JAVA TO C# CONVERTER WARNING: Method 'throws' clauses are not available in .NET:
        //ORIGINAL LINE: public synchronized void notifyWorkDone(Block block) throws VerificationException

        public virtual void notifyWorkDone(Block block)
        {
            if (ConfidenceLevel == ConfidenceType.BUILDING)
            {
                this.depth++;
                this.workDone = this.workDone.Add(block.GetWork());
                OnConfidenceChanged();
            }
        }

        /// <summary>
        /// Depth in the chain is an approximation of how much time has elapsed since the transaction has been confirmed. On
        /// average there is supposed to be a new block every 10 minutes, but the actual rate may vary. The reference
        /// (Satoshi) implementation considers a transaction impractical to reverse after 6 blocks, but as of EOY 2011 network
        /// security is high enough that often only one block is considered enough even for high value transactions. For low
        /// value transactions like songs, or other cheap items, no blocks at all may be necessary.
        ///     
        /// If the transaction appears in the top block, the depth is one. If the transaction does not appear in the best
        /// chain yet, throws InvalidOperationException, so use <seealso cref="TransactionConfidence#getConfidenceType()"/>
        /// to check first.
        /// </summary>
        /// <exception cref="InvalidOperationException"> if confidence type != BUILDING. </exception>
        /// <returns> depth </returns>

        public virtual int DepthInBlocks
        {
            get
            {
                if (ConfidenceLevel != ConfidenceType.BUILDING)
                {
                    throw new InvalidOperationException("Confidence type is not BUILDING");
                }
                return depth;
            }
            set
            {
                this.depth = value;
            }
        }

        /*
         * Set the depth in blocks. Having one block confirmation is a depth of one.
         */


        /// <summary>
        /// Returns the estimated amount of work (number of hashes performed) on this transaction. Work done is a measure of
        /// security that is related to depth in blocks, but more predictable: the network will always attempt to produce six
        /// blocks per hour by adjusting the difficulty target. So to know how much real computation effort is needed to
        /// reverse a transaction, counting blocks is not enough.
        /// </summary>
        /// <exception cref="InvalidOperationException"> if confidence type is not BUILDING </exception>
        /// <returns> estimated number of hashes needed to reverse the transaction. </returns>

        public virtual BigInteger WorkDone
        {
            get
            {
                if (ConfidenceLevel != ConfidenceType.BUILDING)
                {
                    throw new InvalidOperationException("Confidence type is not BUILDING");
                }
                return workDone;
            }
            set
            {
                this.workDone = value;
            }
        }



        /// <summary>
        /// If this transaction has been overridden by a double spend (is dead), this call returns the overriding transaction.
        /// Note that this call <b>can return null</b> if you have migrated an old wallet, as pre-Jan 2012 wallets did not
        /// store this information.
        /// </summary>
        /// <returns> the transaction that double spent this one </returns>
        /// <exception cref="InvalidOperationException"> if confidence type is not OVERRIDDEN_BY_DOUBLE_SPEND. </exception>

        public virtual Transaction OverridingTransaction
        {
            get
            {
                if (ConfidenceLevel != ConfidenceType.DEAD)
                {
                    throw new InvalidOperationException("Confidence type is " + ConfidenceLevel + ", not OVERRIDDEN_BY_DOUBLE_SPEND");
                }
                return overridingTransaction;
            }
            set
            {
                this.overridingTransaction = value;
                ConfidenceLevel = ConfidenceType.DEAD;
            }
        }

        /// <summary>
        /// Called when the transaction becomes newly dead, that is, we learn that one of its inputs has already been spent
        /// in such a way that the double-spending transaction takes precedence over this one. It will not become valid now
        /// unless there is a re-org. Automatically sets the confidence type to DEAD.
        /// </summary>


        /// <summary>
        /// Returns a copy of this object. Event listeners are not duplicated. </summary>

        public virtual TransactionConfidence duplicate()
        {
            var c = new TransactionConfidence(transaction)
                                          {
                                              confidenceLevel = confidenceLevel,
                                              overridingTransaction = overridingTransaction,
                                              appearedAtChainHeight = appearedAtChainHeight
                                          };
            foreach (var peerAddress in broadcastBy)
            {
                c.broadcastBy.Add(peerAddress);
            }

            return c;
        }

        private void OnConfidenceChanged()
        {
            if (ConfidenceChanged != null)
            {
                ConfidenceChanged(this, new ConfidenceChangedEventArgs(transaction));
            }
        }
    }

    public class ConfidenceChangedEventArgs : EventArgs
    {
        public Transaction Transaction { get; private set; }

        public ConfidenceChangedEventArgs(Transaction transaction)
        {
            Transaction = transaction;
        }
    }
}
