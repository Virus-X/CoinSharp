using System;
using System.Diagnostics;
using log4net;
using log4net.Appender;
using log4net.Core;
using log4net.Repository.Hierarchy;

namespace CoinSharp.Common
{
    public static class Logger
    {
        private const string DefaultPatternLayout = "%date{HH:mm:ss} [%level] %logger{2} (%thread) - %m%n";

        private static bool consoleAppenderAdded;

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

        public static void AddConsoleAppender(bool colored)
        {
            if (consoleAppenderAdded)
            {
                return;
            }

            IAppender appender;

            if (colored)
            {
                appender = CreateColoredAppender(DefaultPatternLayout);
            }
            else
            {
                appender = CreateNormalAppender(DefaultPatternLayout);
            }

            Hierarchy repository = (Hierarchy)log4net.LogManager.GetRepository();
            repository.Root.AddAppender(appender);

            repository.Configured = true;
            repository.RaiseConfigurationChanged(EventArgs.Empty);
            consoleAppenderAdded = true;
        }

        private static ColoredConsoleAppender CreateColoredAppender(string layout)
        {
            ColoredConsoleAppender appender = new ColoredConsoleAppender
            {
                Name = "ConsoleDebugAppender",
                Layout = new log4net.Layout.PatternLayout(layout),
                Threshold = Level.All
            };

            appender.AddMapping(
                new ColoredConsoleAppender.LevelColors() { Level = Level.Debug, ForeColor = ColoredConsoleAppender.Colors.Green });
            appender.AddMapping(
                new ColoredConsoleAppender.LevelColors()
                {
                    Level = Level.Info,
                    ForeColor = ColoredConsoleAppender.Colors.Cyan | ColoredConsoleAppender.Colors.HighIntensity
                });
            appender.AddMapping(
                new ColoredConsoleAppender.LevelColors()
                {
                    Level = Level.Warn,
                    ForeColor = ColoredConsoleAppender.Colors.Yellow | ColoredConsoleAppender.Colors.HighIntensity
                });

            appender.AddMapping(
                new ColoredConsoleAppender.LevelColors()
                {
                    Level = Level.Error,
                    ForeColor = ColoredConsoleAppender.Colors.Red | ColoredConsoleAppender.Colors.HighIntensity
                });

            appender.AddMapping(
                new ColoredConsoleAppender.LevelColors()
                {
                    Level = Level.Fatal,
                    ForeColor = ColoredConsoleAppender.Colors.Purple | ColoredConsoleAppender.Colors.HighIntensity
                });

            appender.ActivateOptions();
            return appender;
        }

        private static ConsoleAppender CreateNormalAppender(string layout)
        {
            ConsoleAppender appender = new ConsoleAppender
            {
                Name = "ConsoleDebugAppender",
                Layout = new log4net.Layout.PatternLayout(layout),
                Threshold = Level.All
            };

            appender.ActivateOptions();
            return appender;
        }
    }    
}
