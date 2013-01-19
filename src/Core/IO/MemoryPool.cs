using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CoinSharp.Common;
using log4net;

namespace CoinSharp.IO
{
    /// <summary>
    /// <p>Tracks transactions that are being announced across the network. Typically one is created for you by a
    /// <seealso cref="PeerGroup"/> and then given to each Peer to update. The current purpose is to let Peers update the confidence
    /// (number of peers broadcasting). It helps address an attack scenario in which a malicious remote peer (or several)
    /// feeds you invalid transactions, eg, ones that spend coins which don't exist. If you don't see most of the peers
    /// announce the transaction within a reasonable time, it may be that the TX is not valid. Alternatively, an attacker
    /// may control your entire internet connection: in this scenario counting broadcasting peers does not help you.</p>
    /// 
    /// <p>It is <b>not</b> at this time directly equivalent to the Satoshi clients memory pool, which tracks
    /// all transactions not currently included in the best chain - it's simply a cache.</p>
    /// </summary>
    public class MemoryPool
    {
////        private static readonly ILog Log = Logger.GetLoggerForDeclaringType();

////        // For each transaction we may have seen:
////        //   - only its hash in an inv packet
////        //   - the full transaction itself, if we asked for it to be sent to us (or a peer sent it regardless)
////        //
////        // Before we see the full transaction, we need to track how many peers advertised it, so we can estimate its
////        // confidence pre-chain inclusion assuming an un-tampered with network connection. After we see the full transaction
////        // we need to switch from tracking that data in the Entry to tracking it in the TransactionConfidence object itself.
////        private class WeakTransactionReference
////        {
////            public Sha256Hash hash;
////            public WeakTransactionReference(Transaction tx)
////            {
////                hash = tx.Hash;
////            }
////        }

////        private class Entry
////        {
////            // Invariants: one of the two fields must be null, to indicate which is used.
////            internal Set<PeerAddress> addresses;
////            // We keep a weak reference to the transaction. This means that if no other bit of code finds the transaction
////            // worth keeping around it will drop out of memory and we will, at some point, forget about it, which means
////            // both addresses and tx.get() will be null. When this happens the WeakTransactionReference appears in the queue
////            // allowing us to delete the associated entry (the tx itself has already gone away).
////            internal WeakTransactionReference tx;
////        }

////        private Dictionary<Sha256Hash, Entry> memoryPool;

////        // This ReferenceQueue gets entries added to it when they are only weakly reachable, ie, the MemoryPool is the
////        // only thing that is tracking the transaction anymore. We check it from time to time and delete memoryPool entries
////        // corresponding to expired transactions. In this way memory usage of the system is in line with however many
////        // transactions you actually care to track the confidence of. We can still end up with lots of hashes being stored
////        // if our peers flood us with invs but the MAX_SIZE param caps this.
////        private ReferenceQueue<Transaction> referenceQueue;

////        /// <summary>
////        /// The max size of a memory pool created with the no-args constructor. </summary>
////        public const int MAX_SIZE = 1000;

////        /// <summary>
////        /// Creates a memory pool that will track at most the given number of transactions (allowing you to bound memory
////        /// usage). </summary>
////        /// <param name="size"> Max number of transactions to track. The pool will fill up to this size then stop growing. </param>
////        //JAVA TO C# CONVERTER WARNING: 'final' parameters are not allowed in .NET:
////        //ORIGINAL LINE: public MemoryPool(final int size)
////        public MemoryPool(int size)
////        {
////            //JAVA TO C# CONVERTER TODO TASK: Anonymous inner classes are not converted to C# if the base type is not defined in the code being converted:
////            //			memoryPool = new java.util.LinkedHashMap<Sha256Hash, Entry>()
////            //		{
////            //			@Override protected boolean removeEldestEntry(Map.Entry<Sha256Hash, Entry> entry)
////            //			{
////            //				// An arbitrary choice to stop the memory used by tracked transactions getting too huge in the event
////            //				// of some kind of DoS attack.
////            //				return size() > size;
////            //			}
////            //		};
////            referenceQueue = new ReferenceQueue<Transaction>();
////        }

////        /// <summary>
////        /// Creates a memory pool that will track at most <seealso cref="MemoryPool#MAX_SIZE"/> entries. You should normally use
////        /// this constructor.
////        /// </summary>
////        public MemoryPool()
////            : this(MAX_SIZE)
////        {
////        }

////        /// <summary>
////        /// If any transactions have expired due to being only weakly reachable through us, go ahead and delete their
////        /// memoryPool entries - it means we downloaded the transaction and sent it to various event listeners, none of
////        /// which bothered to keep a reference. Typically, this is because the transaction does not involve any keys that
////        /// are relevant to any of our wallets.
////        /// </summary>
////        [MethodImpl(MethodImplOptions.Synchronized)]
////        private void cleanPool()
////        {
//////JAVA TO C# CONVERTER TODO TASK: Java wildcard generics are not converted to .NET:
//////ORIGINAL LINE: java.lang.ref.Reference<? extends Transaction> ref;
////            Reference<?> @ref;
////            while ((@ref = referenceQueue.poll()) != null)
////            {
////                // Find which transaction got deleted by the GC.
////                WeakTransactionReference txRef = (WeakTransactionReference) @ref;
////                // And remove the associated map entry so the other bits of memory can also be reclaimed.
////                memoryPool.remove(txRef.hash);
////            }
////        }

////        /// <summary>
////        /// Returns the number of peers that have seen the given hash recently.
////        /// </summary>
////        [MethodImpl(MethodImplOptions.Synchronized)]
////        public virtual int numBroadcastPeers(Sha256Hash txHash)
////        {
////            cleanPool();
////            Entry entry = memoryPool.get(txHash);
////            if (entry == null)
////            {
////                // No such TX known.
////                return 0;
////            }
////            else if (entry.tx == null)
////            {
////                // We've seen at least one peer announce with an inv.
////                Preconditions.checkNotNull(entry.addresses);
////                return entry.addresses.size();
////            }
////            else if (entry.tx.get() == null)
////            {
////                // We previously downloaded this transaction, but nothing cared about it so the garbage collector threw
////                // it away. We also deleted the set that tracked which peers had seen it. Treat this case as a zero and
////                // just delete it from the map.
////                memoryPool.remove(txHash);
////                return 0;
////            }
////            else
////            {
////                Preconditions.checkState(entry.addresses == null);
////                return entry.tx.get().Confidence.numBroadcastPeers();
////            }
////        }

////        /// <summary>
////        /// Called by peers when they receive a "tx" message containing a valid serialized transaction. </summary>
////        /// <param name="tx"> The TX deserialized from the wire. </param>
////        /// <param name="byPeer"> The Peer that received it. </param>
////        /// <returns> An object that is semantically the same TX but may be a different object instance. </returns>
////        [MethodImpl(MethodImplOptions.Synchronized)]
////        public virtual Transaction seen(Transaction tx, PeerAddress byPeer)
////        {
////            cleanPool();
////            Entry entry = memoryPool.get(tx.Hash);
////            if (entry != null)
////            {
////                // This TX or its hash have been previously announced.
////                if (entry.tx != null)
////                {
////                    // We already downloaded it.
////                    Preconditions.checkState(entry.addresses == null);
////                    // We only want one canonical object instance for a transaction no matter how many times it is
////                    // deserialized.
////                    Transaction transaction = entry.tx.get();
////                    if (transaction == null)
////                    {
////                        // We previously downloaded this transaction, but the garbage collector threw it away because
////                        // no other part of the system cared enough to keep it around (it's not relevant to us).
////                        // Given the lack of interest last time we probably don't need to track it this time either.
////                        log.info("{}: Provided with a transaction that we previously threw away: {}", byPeer, tx.Hash);
////                    }
////                    else
////                    {
////                        // We saw it before and kept it around. Hand back the canonical copy.
////                        tx = transaction;
////                        log.info("{}: Provided with a transaction downloaded before: [{}] {}", new object[] { byPeer, tx.Confidence.numBroadcastPeers(), tx.Hash });
////                    }
////                    tx.Confidence.markBroadcastBy(byPeer);
////                    return tx;
////                }
////                else
////                {
////                    // We received a transaction that we have previously seen announced but not downloaded until now.
////                    Preconditions.checkNotNull(entry.addresses);
////                    entry.tx = new WeakTransactionReference(tx, referenceQueue);
////                    // Copy the previously announced peers into the confidence and then clear it out.
////                    TransactionConfidence confidence = tx.Confidence;
////                    foreach (PeerAddress a in entry.addresses)
////                    {
////                        confidence.markBroadcastBy(a);
////                    }
////                    entry.addresses = null;
////                    log.debug("{}: Adding tx [{}] {} to the memory pool", new object[] { byPeer, confidence.numBroadcastPeers(), tx.HashAsString });
////                    return tx;
////                }
////            }
////            else
////            {
////                log.info("{}: Provided with a downloaded transaction we didn't see announced yet: {}", byPeer, tx.HashAsString);
////                entry = new Entry();
////                entry.tx = new WeakTransactionReference(tx, referenceQueue);
////                memoryPool.put(tx.Hash, entry);
////                tx.Confidence.markBroadcastBy(byPeer);
////                return tx;
////            }
////        }

////        /// <summary>
////        /// Called by peers when they see a transaction advertised in an "inv" message. It either will increase the
////        /// confidence of the pre-existing transaction or will just keep a record of the address for future usage.
////        /// </summary>
////        [MethodImpl(MethodImplOptions.Synchronized)]
////        public virtual void seen(Sha256Hash hash, PeerAddress byPeer)
////        {
////            cleanPool();
////            Entry entry = memoryPool.get(hash);
////            if (entry != null)
////            {
////                // This TX or its hash have been previously announced.
////                if (entry.tx != null)
////                {
////                    Preconditions.checkState(entry.addresses == null);
////                    Transaction tx = entry.tx.get();
////                    if (tx != null)
////                    {
////                        tx.Confidence.markBroadcastBy(byPeer);
////                        log.debug("{}: Announced transaction we have seen before [{}] {}", new object[] { byPeer, tx.Confidence.numBroadcastPeers(), tx.HashAsString });
////                    }
////                    else
////                    {
////                        // The inv is telling us about a transaction that we previously downloaded, and threw away because
////                        // nothing found it interesting enough to keep around. So do nothing.
////                    }
////                }
////                else
////                {
////                    Preconditions.checkNotNull(entry.addresses);
////                    entry.addresses.add(byPeer);
////                    log.debug("{}: Announced transaction we have seen announced before [{}] {}", new object[] { byPeer, entry.addresses.size(), hash });
////                }
////            }
////            else
////            {
////                // This TX has never been seen before.
////                entry = new Entry();
////                // TODO: Using hashsets here is inefficient compared to just having an array.
////                entry.addresses = new HashSet<PeerAddress>();
////                entry.addresses.add(byPeer);
////                memoryPool.put(hash, entry);
////                log.info("{}: Announced new transaction [1] {}", byPeer, hash);
////            }
////        }

////        /// <summary>
////        /// Returns the <seealso cref="Transaction"/> for the given hash if we have downloaded it, or null if that hash is unknown or
////        /// we only saw advertisements for it yet or it has been downloaded but garbage collected due to nowhere else
////        /// holding a reference to it.
////        /// </summary>
////        [MethodImpl(MethodImplOptions.Synchronized)]
////        public virtual Transaction get(Sha256Hash hash)
////        {
////            Entry entry = memoryPool.get(hash);
////            if (entry == null) // Unknown.
////            {
////                return null;
////            }
////            if (entry.tx == null) // Seen but only in advertisements.
////            {
////                return null;
////            }
////            if (entry.tx.get() == null) // Was downloaded but garbage collected.
////            {
////                return null;
////            }
////            Transaction tx = entry.tx.get();
////            Preconditions.checkNotNull(tx);
////            return tx;
////        }

////        /// <summary>
////        /// Returns true if the TX identified by hash has been seen before (ie, in an inv). Note that a transaction that
////        /// was broadcast, downloaded and nothing kept a reference to it will eventually be cleared out by the garbage
////        /// collector and wasSeen() will return false - it does not keep a permanent record of every hash ever broadcast.
////        /// </summary>
////        [MethodImpl(MethodImplOptions.Synchronized)]
////        public virtual bool maybeWasSeen(Sha256Hash hash)
////        {
////            Entry entry = memoryPool.get(hash);
////            return entry != null;
////        }
    }
}
