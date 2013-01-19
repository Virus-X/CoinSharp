namespace CoinSharp.TransactionScript
{
    internal class ScriptChunk
    {
        public bool IsOpCode { get; private set; }
        public byte[] Data { get; private set; }
        public int StartLocationInProgram { get; private set; }

        public ScriptChunk(bool isOpCode, byte[] data, int startLocationInProgram)
        {
            IsOpCode = isOpCode;
            Data = data;
            StartLocationInProgram = startLocationInProgram;
        }

        public bool EqualsOpCode(OpCode opCode)
        {
            return IsOpCode && Data.Length == 1 && (OpCode)(0xFF & Data[0]) == opCode;
        }
    }
}