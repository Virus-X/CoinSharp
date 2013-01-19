/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using CoinSharp.Discovery;
using CoinSharp.Store;
using CoinSharp.Util;
using log4net;

namespace CoinSharp
{
    // TODO 
    // 1. Use Timer for checking 
    //


    /// <summary>
    /// Maintain a number of connections to peers.
    /// </summary>
    /// <remarks>
    /// PeerGroup tries to maintain a constant number of connections to a set of distinct peers.
    /// Each peer runs a network listener in its own thread. When a connection is lost, a new peer
    /// will be tried after a delay as long as the number of connections less than the maximum.
    /// 
    /// <p/>Connections are made to addresses from a provided list. When that list is exhausted,
    /// we start again from the head of the list.
    /// 
    /// <p/>The PeerGroup can broadcast a transaction to the currently connected set of peers. It can
    /// also handle download of the block chain from peers, restarting the process when peers die.
    /// 
    /// @author miron@google.com (Miron Cuperman a.k.a devrandom)
    /// </remarks>
    public class PeerGroup
    {
        private const int MaxPeerConnections = 4;

        private const int PeerGroupTimerInterval = 10000;

        private static readonly ILog Log = Common.Logger.GetLoggerForDeclaringType();

        /// <summary>
        /// Addresses to try to connect to, excluding active peers
        /// </summary>
        private readonly ConcurrentQueue<PeerAddress> _inactives;

        private readonly IThreadWorkerPool peerConnectionPool;

        private readonly SingleEntryTimer peerGroupTimer;

        private readonly object syncRoot = new object();

        /// <summary>
        /// True if the connection initiation thread should be running
        /// </summary>
        private bool _running;

        /// <summary>
        /// Currently active peers
        /// </summary>
        private readonly ICollection<Peer> _peers;

        /// <summary>
        /// The peer we are currently downloading the chain from
        /// </summary>
        private Peer _downloadPeer;

        /// <summary>
        /// Callback for events related to chain download
        /// </summary>
        private IPeerEventListener _downloadListener;

        /// <summary>
        /// Peer discovery sources, will be polled occasionally if there aren't enough in-actives.
        /// </summary>
        private readonly ICollection<IPeerDiscovery> _peerDiscoverers;

        private readonly NetworkParameters networkParams;
        private readonly IBlockStore _blockStore;
        private readonly BlockChain _chain;

        /// <summary>
        /// Creates a PeerGroup with the given parameters. The connectionDelayMillis parameter controls how long the
        /// PeerGroup will wait between attempts to connect to nodes or read from any added peer discovery sources.
        /// </summary>
        public PeerGroup(IBlockStore blockStore, NetworkParameters networkNetworkParams, BlockChain chain)
        {
            _blockStore = blockStore;
            this.networkParams = networkNetworkParams;
            _chain = chain;

            peerConnectionPool = new ThreadWorkerPool(MaxPeerConnections);

            _inactives = new ConcurrentQueue<PeerAddress>();
            _peers = new List<Peer>();
            _peerDiscoverers = new List<IPeerDiscovery>();
            peerGroupTimer = new SingleEntryTimer(PeerGroupTimerCallback);
        }

        /// <summary>
        /// Called when a peer is connected.
        /// </summary>
        public event EventHandler<PeerConnectedEventArgs> PeerConnected;

        /// <summary>
        /// Called when a peer is disconnected.
        /// </summary>
        public event EventHandler<PeerDisconnectedEventArgs> PeerDisconnected;

        /// <summary>
        /// Add an address to the list of potential peers to connect to.
        /// </summary>
        public void AddAddress(PeerAddress peerAddress)
        {
            // TODO(miron) consider de-duplication
            _inactives.Enqueue(peerAddress);
        }

        /// <summary>
        /// Add addresses from a discovery source to the list of potential peers to connect to.
        /// </summary>
        public void AddPeerDiscovery(IPeerDiscovery peerDiscovery)
        {
            _peerDiscoverers.Add(peerDiscovery);
        }

        /// <summary>
        /// Starts the background thread that makes connections.
        /// </summary>
        public void Start()
        {
            lock (syncRoot)
            {
                _running = true;
                peerGroupTimer.Change(0, PeerGroupTimerInterval);
            }
        }

        /// <summary>
        /// Stop this PeerGroup.
        /// </summary>
        /// <remarks>
        /// The peer group will be asynchronously shut down. After it is shut down
        /// all peers will be disconnected and no threads will be running.
        /// </remarks>
        public void Stop()
        {
            lock (syncRoot)
            {
                if (_running)
                {
                    _running = false;
                    peerGroupTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        /// <summary>
        /// Broadcast a transaction to all connected peers.
        /// </summary>
        /// <returns>Whether we sent to at least one peer.</returns>
        public bool BroadcastTransaction(Transaction tx)
        {
            var success = false;
            lock (_peers)
            {
                foreach (var peer in _peers)
                {
                    try
                    {
                        peer.BroadcastTransaction(tx);
                        success = true;
                    }
                    catch (IOException e)
                    {
                        Log.Error("failed to broadcast to " + peer, e);
                    }
                }
            }
            return success;
        }

        /// <summary>
        /// Repeatedly get the next peer address from the inactive queue
        /// and try to connect.
        /// </summary>
        /// <remarks>
        /// We can be terminated with Thread.interrupt. When an interrupt is received,
        /// we will ask the executor to shutdown and ask each peer to disconnect. At that point
        /// no threads or network connections will be active.
        /// </remarks>
        public void PeerGroupTimerCallback(object state)
        {
            try
            {
                if (peerConnectionPool.IsFull)
                {
                    return;
                }

                if (_inactives.Count == 0)
                {
                    DiscoverPeers();
                }

                AllocateNextPeer();
            }
            catch (Exception ex)
            {
                Log.ErrorFormat("Unhandled exception in PeerGroupTimer", ex);
            }
        }

        private void DiscoverPeers()
        {
            foreach (var peerDiscovery in _peerDiscoverers)
            {
                IEnumerable<EndPoint> addresses;
                try
                {
                    addresses = peerDiscovery.GetPeers();
                }
                catch (PeerDiscoveryException e)
                {
                    // Will try again later.
                    Log.Error("Failed to discover peer addresses from discovery source", e);
                    continue;
                }

                foreach (var address in addresses)
                {
                    _inactives.Enqueue(new PeerAddress((IPEndPoint)address));
                }

                if (_inactives.Count > 0) break;
            }
        }

        /// <summary>
        /// Try connecting to a peer. If we exceed the number of connections, delay and try
        /// again.
        /// </summary>
        /// <exception cref="ThreadInterruptedException"/>
        private void AllocateNextPeer()
        {
            PeerAddress address;
            if (!_inactives.TryDequeue(out address))
            {
                return;
            }

            try
            {
                var peer = new Peer(networkParams, address, _blockStore.GetChainHead().Height, _chain);
                var workerAllocated = peerConnectionPool.TryAllocateWorker(token => ConnectAndRun(peer, token));

                if (!workerAllocated)
                {
                    _inactives.Enqueue(address);
                    return;
                }
            }
            catch (BlockStoreException e)
            {
                // Fatal error
                Log.Error("Block store corrupt?", e);
                _running = false;
                throw new Exception(e.Message, e);
            }
        }

        private void ConnectAndRun(Peer peer, CancellationToken token)
        {
            try
            {
                Log.Info("Connecting to " + peer);
                peer.Connect();
                HandleNewPeer(peer);
                peer.Run(token);
            }
            catch (PeerException ex)
            {
                // Do not propagate PeerException - log and try next peer. Suppress stack traces for
                // exceptions we expect as part of normal network behaviour.
                var cause = ex.InnerException;
                if (cause is SocketException)
                {
                    if (((SocketException)cause).SocketErrorCode == SocketError.TimedOut)
                    {
                        Log.Info("Timeout talking to " + peer + ": " + cause.Message);
                    }
                    else
                    {
                        Log.Info("Could not connect to " + peer + ": " + cause.Message);
                    }
                }
                else if (cause is IOException)
                {
                    Log.Info("Error talking to " + peer + ": " + cause.Message);
                }
                else
                {
                    Log.Error("Unexpected exception whilst talking to " + peer, ex);
                }
            }
            finally
            {
                peer.Disconnect();
                HandlePeerDeath(peer);
            }
        }

        /// <summary>
        /// Start downloading the block chain from the first available peer.
        /// </summary>
        /// <remarks>
        /// If no peers are currently connected, the download will be started
        /// once a peer starts. If the peer dies, the download will resume with another peer.
        /// </remarks>
        /// <param name="listener">A listener for chain download events, may not be null.</param>
        public void StartBlockChainDownload(IPeerEventListener listener)
        {
            lock (syncRoot)
            {
                _downloadListener = listener;
                // TODO be more nuanced about which peer to download from. We can also try
                // downloading from multiple peers and handle the case when a new peer comes along
                // with a longer chain after we thought we were done.
                lock (_peers)
                {
                    var firstPeer = _peers.FirstOrDefault();
                    if (firstPeer != null)
                        StartBlockChainDownloadFromPeer(firstPeer);
                }
            }
        }

        /// <summary>
        /// Download the block chain from peers.
        /// </summary>
        /// <remarks>
        /// This method wait until the download is complete. "Complete" is defined as downloading
        /// from at least one peer all the blocks that are in that peer's inventory.
        /// </remarks>
        public void DownloadBlockChain()
        {
            var listener = new DownloadListener();
            StartBlockChainDownload(listener);
            listener.Await();
        }

        protected void HandleNewPeer(Peer peer)
        {
            lock (syncRoot)
            {
                _peers.Add(peer);

                if (_downloadListener != null && _downloadPeer == null)
                {
                    StartBlockChainDownloadFromPeer(peer);
                }

                if (PeerConnected != null)
                {
                    PeerConnected(this, new PeerConnectedEventArgs(_peers.Count));
                }
            }
        }

        protected void HandlePeerDeath(Peer peer)
        {
            lock (syncRoot)
            {
                lock (_peers)
                {
                    _peers.Remove(peer);
                }

                if (peer == _downloadPeer)
                {
                    _downloadPeer = null;
                    lock (_peers)
                    {
                        var firstPeer = _peers.FirstOrDefault();
                        if (_downloadListener != null && firstPeer != null)
                        {
                            StartBlockChainDownloadFromPeer(firstPeer);
                        }
                    }
                }

                if (PeerDisconnected != null)
                {
                    PeerDisconnected(this, new PeerDisconnectedEventArgs(_peers.Count));
                }
            }
        }

        private void StartBlockChainDownloadFromPeer(Peer peer)
        {
            lock (syncRoot)
            {
                peer.BlocksDownloaded += (sender, e) => _downloadListener.OnBlocksDownloaded((Peer)sender, e.Block, e.BlocksLeft);
                peer.ChainDownloadStarted += (sender, e) => _downloadListener.OnChainDownloadStarted((Peer)sender, e.BlocksLeft);
                try
                {
                    peer.StartBlockChainDownload();
                }
                catch (IOException e)
                {
                    Log.Error("failed to start block chain download from " + peer, e);
                    return;
                }
                _downloadPeer = peer;
            }
        }
    }

    /// <summary>
    /// Called when a peer is connected.
    /// </summary>
    public class PeerConnectedEventArgs : EventArgs
    {
        /// <summary>
        /// The total number of connected peers.
        /// </summary>
        public int PeerCount { get; private set; }

        public PeerConnectedEventArgs(int peerCount)
        {
            PeerCount = peerCount;
        }
    }

    /// <summary>
    /// Called when a peer is disconnected.
    /// </summary>
    public class PeerDisconnectedEventArgs : EventArgs
    {
        /// <summary>
        /// The total number of connected peers.
        /// </summary>
        public int PeerCount { get; private set; }

        public PeerDisconnectedEventArgs(int peerCount)
        {
            PeerCount = peerCount;
        }
    }
}