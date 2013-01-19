using System;
using System.Threading;

namespace CoinSharp.Util
{
    /// <summary>
    /// Timer that executes callback only in 1 thread simultaniously.
    /// </summary>
    public class SingleEntryTimer : IDisposable
    {
        private readonly TimerCallback callback;

        private readonly object timerLocker = new object();

        private readonly Timer internalTimer;

        public SingleEntryTimer(TimerCallback callback)
        {
            this.callback = callback;
            internalTimer = new Timer(TimerCallback);
        }

        public void Dispose()
        {
            internalTimer.Dispose();
        }        

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            return internalTimer.Change(dueTime, period);
        }        

        public bool Change(long dueTime, long period)
        {
            return internalTimer.Change(dueTime, period);
        }

        private void TimerCallback(object state)
        {
            if (!Monitor.TryEnter(timerLocker, 0))
            {
                return;
            }

            try
            {
                callback(state);
            }
            finally
            {
                Monitor.Exit(timerLocker);
            }
        }
    }
}
