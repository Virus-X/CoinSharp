using System;
using System.Diagnostics;
using log4net;

namespace CoinSharp.Common
{
    public static class Logger
    {
        public static ILog GetLoggerForDeclaringType()
        {
            var frame = new StackFrame(1);
            var method = frame.GetMethod();
            var type = method.DeclaringType;
            return GetLogger(type);
        }

        public static ILog GetLogger(Type type)
        {
            return LogManager.GetLogger(type);
        }
    }    
}
