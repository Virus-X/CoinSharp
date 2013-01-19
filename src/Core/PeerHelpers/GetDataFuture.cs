using System;
using System.Diagnostics;
using System.Threading;

namespace CoinSharp
{
    internal sealed class GetDataFuture<T> : IAsyncResult, IDisposable
    {
        private readonly InventoryItem item;
        private readonly AsyncCallback callback;
        private readonly object state;
        private readonly ManualResetEventSlim completedEvent;        
        private T result;

        internal GetDataFuture(InventoryItem item, AsyncCallback callback, object state)
        {
            this.item = item;
            this.callback = callback;
            this.state = state;
            completedEvent = new ManualResetEventSlim(false);
        }

        public bool IsCompleted
        {
            get { return !Equals(result, default(T)); }
        }

        public WaitHandle AsyncWaitHandle
        {
            get { return completedEvent.WaitHandle; }
        }

        public object AsyncState
        {
            get { return state; }
        }

        public bool CompletedSynchronously
        {
            get { return false; }
        }

        internal T Result
        {
            get
            {
                completedEvent.Wait();
                Debug.Assert(!Equals(result, default(T)));
                return result;
            }
        }

        internal InventoryItem Item
        {
            get { return item; }
        }

        /// <summary>
        /// Called by the Peer when the result has arrived. Completes the task.
        /// </summary>
        internal void SetResult(T result)
        {
            // This should be called in the network loop thread for this peer
            this.result = result;
            // Now release the thread that is waiting. We don't need to synchronize here as the latch establishes
            // a memory barrier.
            completedEvent.Set();
            if (callback != null)
            {
                callback(this);
            }            
        }

        public void Dispose()
        {
            completedEvent.Dispose();
        }
    }
}