using System;
using System.Threading;
using System.Threading.Tasks;
using CoinSharp.Common;
using log4net;

namespace CoinSharp.Util
{
    /// <summary>
    /// Uses worker threads from main thread pool, but has local thread limit.
    /// </summary>
    public interface IThreadWorkerPool
    {
        bool IsFull { get; }
        void Shutdown();
        bool TryAllocateWorker(Action<CancellationToken> action);
    }

    /// <summary>
    /// Uses worker threads from main thread pool, but has local thread limit.
    /// </summary>
    public class ThreadWorkerPool : IThreadWorkerPool
    {
        private static readonly ILog Log = Logger.GetLoggerForDeclaringType();

        private readonly SemaphoreSlim threadCount;

        private readonly CancellationTokenSource cts = new CancellationTokenSource();

        public bool IsFull
        {
            get { return threadCount.CurrentCount == 0; }
        }

        public ThreadWorkerPool(int maxThreads)
        {
            threadCount = new SemaphoreSlim(maxThreads, maxThreads);
        }

        public void Shutdown()
        {
            cts.Cancel();
        }

        public bool TryAllocateWorker(Action<CancellationToken> action)
        {
            if (cts.IsCancellationRequested)
            {
                return false;
            }

            if (!threadCount.Wait(0))
            {
                return false;
            }

            Task.Factory
                .StartNew(() => action(cts.Token), cts.Token)
                .ContinueWith(t =>
                                  {
                                      threadCount.Release();
                                      if (t.IsFaulted && t.Exception != null)
                                      {
                                          Log.Error("Unhandled exception in worker thread", t.Exception.InnerException);
                                      }
                                  });
            return true;
        }
    }
}
