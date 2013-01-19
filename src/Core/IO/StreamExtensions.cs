using System;
using System.IO;

namespace CoinSharp.IO
{
    internal static class StreamExtensions
    {
        public static int Read(this Stream stream, byte[] buffer)
        {
            return stream.Read(buffer, 0, buffer.Length);
        }

        public static void Write(this Stream stream, byte[] buffer)
        {
            stream.Write(buffer, 0, buffer.Length);
        }

        public static void WriteLittleEndian(this Stream stream, uint val)
        {
            stream.WriteByte((byte)(val >> 0));
            stream.WriteByte((byte)(val >> 8));
            stream.WriteByte((byte)(val >> 16));
            stream.WriteByte((byte)(val >> 24));
        }

        public static void WriteLittleEndian(this Stream stream, ulong val)
        {
            var bytes = BitConverter.GetBytes(val);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            stream.Write(bytes);
        }
    }
}