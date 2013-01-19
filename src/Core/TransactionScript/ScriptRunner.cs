using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;

namespace CoinSharp.TransactionScript
{
    public class ScriptRunner
    {
        /// <summary>
        /// Convince method to get the int value of OpCode.OP_N
        /// </summary>
        public static int GetOpNValue(OpCode opcode)
        {
            if (opcode == OpCode.OP_0)
            {
                return 0;
            }
            if (opcode < OpCode.OP_1 || opcode > OpCode.OP_16) // This should absolutely never happen
            {
                throw new ScriptException("GetOpNValue called on non OpCode.OP_N opcode");
            }
            return opcode + 1 - OpCode.OP_1;
        }

        /// <summary>
        /// Returns the script bytes of inputScript with all instances of the specified script object removed
        /// </summary>
        public static byte[] RemoveAllInstancesOf(byte[] inputScript, byte[] chunkToRemove)
        {
            // We usually don't end up removing anything
            using (var bos = new MemoryStream(inputScript.Length))
            {

                int cursor = 0;
                while (cursor < inputScript.Length)
                {
                    bool skip = EqualsRange(inputScript, cursor, chunkToRemove);

                    var opcode = (OpCode)(inputScript[cursor++] & 0xFF);
                    int additionalBytes = 0;
                    if (opcode >= 0 && opcode < OpCode.OP_PUSHDATA1)
                    {
                        additionalBytes = (int)opcode;
                    }
                    else if (opcode == OpCode.OP_PUSHDATA1)
                    {
                        additionalBytes = inputScript[cursor] + 1;
                    }
                    else if (opcode == OpCode.OP_PUSHDATA2)
                    {
                        additionalBytes = ((0xFF & inputScript[cursor]) | ((0xFF & inputScript[cursor + 1]) << 8)) + 2;
                    }
                    else if (opcode == OpCode.OP_PUSHDATA4)
                    {
                        additionalBytes = ((0xFF & inputScript[cursor]) | ((0xFF & inputScript[cursor + 1]) << 8) |
                                           ((0xFF & inputScript[cursor + 1]) << 16) |
                                           ((0xFF & inputScript[cursor + 1]) << 24)) + 4;
                    }

                    if (!skip)
                    {
                        bos.WriteByte((byte)opcode);
                        bos.Write(inputScript, cursor, cursor + additionalBytes);
                    }
                    cursor += additionalBytes;
                }

                return bos.ToArray();
            }
        }

        public static bool CastToBool(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                if (data[i] != 0)
                {
                    // "Can be negative zero" -reference client (see OpenSSL's BN_bn2mpi)
                    if (i == data.Length - 1 && (data[i] & 0xFF) == 0x80)
                    {
                        return false;
                    }

                    return true;
                }
            }
            return false;
        }

        public static BigInteger CastToBigInteger(byte[] chunk)
        {
            if (chunk.Length > 4)
            {
                throw new ScriptException("Script attempted to use an integer larger than 4 bytes");
            }

            return Utils.DecodeMpi(Utils.ReverseBytes(chunk), false);
        }

        public static void ExecuteScript(Transaction txContainingThis, long index, Script script, Stack<byte[]> stack)
        {
            int opCount = 0;
            int lastCodeSepLocation = 0;

            Stack<byte[]> altstack = new Stack<byte[]>();
            Stack<bool?> ifStack = new Stack<bool?>();

            foreach (ScriptChunk chunk in script.chunks)
            {
                bool shouldExecute = !ifStack.Contains(false);

                if (!chunk.IsOpCode)
                {
                    if (chunk.Data.Length > 520)
                    {
                        throw new ScriptException("Attempted to push a data string larger than 520 bytes");
                    }

                    if (!shouldExecute)
                    {
                        continue;
                    }

                    stack.Push(chunk.Data);
                }
                else
                {
                    var opcode = (OpCode)(0xFF & chunk.Data[0]);
                    if (opcode > OpCode.OP_16)
                    {
                        opCount++;
                        if (opCount > 201)
                        {
                            throw new ScriptException("More script operations than is allowed");
                        }
                    }

                    if (opcode == OpCode.OP_VERIF || opcode == OpCode.OP_VERNOTIF)
                    {
                        throw new ScriptException("Script included OpCode.OP_VERIF or OpCode.OP_VERNOTIF");
                    }

                    if (opcode == OpCode.OP_CAT || opcode == OpCode.OP_SUBSTR || opcode == OpCode.OP_LEFT || opcode == OpCode.OP_RIGHT || opcode == OpCode.OP_INVERT || opcode == OpCode.OP_AND || opcode == OpCode.OP_OR || opcode == OpCode.OP_XOR || opcode == OpCode.OP_2MUL || opcode == OpCode.OP_2DIV || opcode == OpCode.OP_MUL || opcode == OpCode.OP_DIV || opcode == OpCode.OP_MOD || opcode == OpCode.OP_LSHIFT || opcode == OpCode.OP_RSHIFT)
                    {
                        throw new ScriptException("Script included a disabled Script Op.");
                    }

                    switch (opcode)
                    {
                        case OpCode.OP_IF:
                            if (!shouldExecute)
                            {
                                ifStack.Push(false);
                                continue;
                            }
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_IF on an empty stack");
                            }
                            ifStack.Push(CastToBool(stack.Pop()));
                            continue;
                        case OpCode.OP_NOTIF:
                            if (!shouldExecute)
                            {
                                ifStack.Push(false);
                                continue;
                            }
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_NOTIF on an empty stack");
                            }
                            ifStack.Push(!CastToBool(stack.Pop()));
                            continue;
                        case OpCode.OP_ELSE:
                            if (ifStack.Count == 0)
                            {
                                throw new ScriptException("Attempted OpCode.OP_ELSE without OpCode.OP_IF/NOTIF");
                            }
                            ifStack.Push(!ifStack.Pop());
                            continue;
                        case OpCode.OP_ENDIF:
                            if (ifStack.Count == 0)
                            {
                                throw new ScriptException("Attempted OpCode.OP_ENDIF without OpCode.OP_IF/NOTIF");
                            }
                            ifStack.Pop();
                            continue;
                    }

                    if (!shouldExecute)
                    {
                        continue;
                    }

                    switch (opcode)
                    {
                            //case OpCode.OP_0: dont know why this isnt also here in the reference client
                        case OpCode.OP_1NEGATE:
                            stack.Push(Utils.ReverseBytes(Utils.EncodeMpi(BigInteger.One.Negate(), false)));
                            break;
                        case OpCode.OP_1:
                        case OpCode.OP_2:
                        case OpCode.OP_3:
                        case OpCode.OP_4:
                        case OpCode.OP_5:
                        case OpCode.OP_6:
                        case OpCode.OP_7:
                        case OpCode.OP_8:
                        case OpCode.OP_9:
                        case OpCode.OP_10:
                        case OpCode.OP_11:
                        case OpCode.OP_12:
                        case OpCode.OP_13:
                        case OpCode.OP_14:
                        case OpCode.OP_15:
                        case OpCode.OP_16:
                            stack.Push(Utils.ReverseBytes(Utils.EncodeMpi(BigInteger.ValueOf(GetOpNValue(opcode)), false)));
                            break;
                        case OpCode.OP_NOP:
                            break;
                        case OpCode.OP_VERIFY:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_VERIFY on an empty stack");
                            }
                            if (!CastToBool(stack.Pop()))
                            {
                                throw new ScriptException("OpCode.OP_VERIFY failed");
                            }
                            break;
                        case OpCode.OP_RETURN:
                            throw new ScriptException("Script called OpCode.OP_RETURN");
                        case OpCode.OP_TOALTSTACK:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_TOALTSTACK on an empty stack");
                            }
                            altstack.Push(stack.Pop());
                            break;
                        case OpCode.OP_FROMALTSTACK:
                            if (altstack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_TOALTSTACK on an empty altstack");
                            }
                            stack.Push(altstack.Pop());
                            break;
                        case OpCode.OP_2DROP:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_2DROP on a stack with size < 2");
                            }
                            stack.Pop();
                            stack.Pop();
                            break;
                        case OpCode.OP_2DUP:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_2DUP on a stack with size < 2");
                            }

                            byte[] OP2DUPtmpChunk2 = stack.ElementAt(0);
                            stack.Push(stack.ElementAt(1));
                            stack.Push(OP2DUPtmpChunk2);
                            break;
                        case OpCode.OP_3DUP:
                            if (stack.Count < 3)
                            {
                                throw new ScriptException("Attempted OpCode.OP_3DUP on a stack with size < 3");
                            }

                            byte[] OP3DUPtmpChunk3 = stack.ElementAt(0);
                            byte[] OP3DUPtmpChunk2 = stack.ElementAt(1);
                            stack.Push(stack.ElementAt(2));
                            stack.Push(OP3DUPtmpChunk2);
                            stack.Push(OP3DUPtmpChunk3);
                            break;
                        case OpCode.OP_2OVER:
                            if (stack.Count < 4)
                            {
                                throw new ScriptException("Attempted OpCode.OP_2OVER on a stack with size < 4");
                            }

                            byte[] OP2OVERtmpChunk2 = stack.ElementAt(2);
                            stack.Push(stack.ElementAt(3));
                            stack.Push(OP2OVERtmpChunk2);
                            break;
                        case OpCode.OP_2ROT:
                            if (stack.Count < 6)
                            {
                                throw new ScriptException("Attempted OpCode.OP_2ROT on a stack with size < 6");
                            }
                            byte[] OP2ROTtmpChunk6 = stack.Pop();
                            byte[] OP2ROTtmpChunk5 = stack.Pop();
                            byte[] OP2ROTtmpChunk4 = stack.Pop();
                            byte[] OP2ROTtmpChunk3 = stack.Pop();
                            byte[] OP2ROTtmpChunk2 = stack.Pop();
                            byte[] OP2ROTtmpChunk1 = stack.Pop();
                            stack.Push(OP2ROTtmpChunk3);
                            stack.Push(OP2ROTtmpChunk4);
                            stack.Push(OP2ROTtmpChunk5);
                            stack.Push(OP2ROTtmpChunk6);
                            stack.Push(OP2ROTtmpChunk1);
                            stack.Push(OP2ROTtmpChunk2);
                            break;
                        case OpCode.OP_2SWAP:
                            if (stack.Count < 4)
                            {
                                throw new ScriptException("Attempted OpCode.OP_2SWAP on a stack with size < 4");
                            }
                            byte[] OP2SWAPtmpChunk4 = stack.Pop();
                            byte[] OP2SWAPtmpChunk3 = stack.Pop();
                            byte[] OP2SWAPtmpChunk2 = stack.Pop();
                            byte[] OP2SWAPtmpChunk1 = stack.Pop();
                            stack.Push(OP2SWAPtmpChunk3);
                            stack.Push(OP2SWAPtmpChunk4);
                            stack.Push(OP2SWAPtmpChunk1);
                            stack.Push(OP2SWAPtmpChunk2);
                            break;
                        case OpCode.OP_IFDUP:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_IFDUP on an empty stack");
                            }
                            if (CastToBool(stack.Peek()))
                            {
                                stack.Push(stack.Peek());
                            }
                            break;
                        case OpCode.OP_DEPTH:
                            stack.Push(Utils.ReverseBytes(Utils.EncodeMpi(BigInteger.ValueOf(stack.Count), false)));
                            break;
                        case OpCode.OP_DROP:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_DROP on an empty stack");
                            }
                            stack.Pop();
                            break;
                        case OpCode.OP_DUP:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_DUP on an empty stack");
                            }
                            stack.Push(stack.Peek());
                            break;
                        case OpCode.OP_NIP:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_NIP on a stack with size < 2");
                            }
                            byte[] OPNIPtmpChunk = stack.Pop();
                            stack.Pop();
                            stack.Push(OPNIPtmpChunk);
                            break;
                        case OpCode.OP_OVER:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_OVER on a stack with size < 2");
                            }
                            stack.Push(stack.ElementAt(1));
                            break;
                        case OpCode.OP_PICK:
                        case OpCode.OP_ROLL:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_PICK/OpCode.OP_ROLL on an empty stack");
                            }
                            long val = CastToBigInteger(stack.Pop()).LongValue;
                            if (val < 0 || val >= stack.Count)
                            {
                                throw new ScriptException("OpCode.OP_PICK/OpCode.OP_ROLL attempted to get data deeper than stack size");
                            }

                            byte[] OPROLLtmpChunk = stack.ElementAt((int)val);
                            if (opcode == OpCode.OP_ROLL)
                            {
                                stack.RemoveAt((int)(val + 1));
                            }

                            stack.Push(OPROLLtmpChunk);
                            break;
                        case OpCode.OP_ROT:
                            if (stack.Count < 3)
                            {
                                throw new ScriptException("Attempted OpCode.OP_ROT on a stack with size < 3");
                            }
                            byte[] OPROTtmpChunk3 = stack.Pop();
                            byte[] OPROTtmpChunk2 = stack.Pop();
                            byte[] OPROTtmpChunk1 = stack.Pop();
                            stack.Push(OPROTtmpChunk2);
                            stack.Push(OPROTtmpChunk3);
                            stack.Push(OPROTtmpChunk1);
                            break;
                        case OpCode.OP_SWAP:
                        case OpCode.OP_TUCK:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_SWAP on a stack with size < 2");
                            }
                            byte[] OPSWAPtmpChunk2 = stack.Pop();
                            byte[] OPSWAPtmpChunk1 = stack.Pop();
                            stack.Push(OPSWAPtmpChunk2);
                            stack.Push(OPSWAPtmpChunk1);
                            if (opcode == OpCode.OP_TUCK)
                            {
                                stack.Push(OPSWAPtmpChunk2);
                            }
                            break;
                        case OpCode.OP_CAT:
                        case OpCode.OP_SUBSTR:
                        case OpCode.OP_LEFT:
                        case OpCode.OP_RIGHT:
                            throw new ScriptException("Attempted to use disabled Script Op.");
                        case OpCode.OP_SIZE:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_SIZE on an empty stack");
                            }
                            stack.Push(Utils.ReverseBytes(Utils.EncodeMpi(BigInteger.ValueOf(stack.Peek().Length), false)));
                            break;
                        case OpCode.OP_INVERT:
                        case OpCode.OP_AND:
                        case OpCode.OP_OR:
                        case OpCode.OP_XOR:
                            throw new ScriptException("Attempted to use disabled Script Op.");
                        case OpCode.OP_EQUAL:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_EQUALVERIFY on a stack with size < 2");
                            }
                            stack.Push(Equals(stack.Pop(), stack.Pop()) ? new byte[] { 1 } : new byte[] { 0 });
                            break;
                        case OpCode.OP_EQUALVERIFY:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_EQUALVERIFY on a stack with size < 2");
                            }
                            if (!Equals(stack.Pop(), stack.Pop()))
                            {
                                throw new ScriptException("OpCode.OP_EQUALVERIFY: non-equal data");
                            }
                            break;
                        case OpCode.OP_1ADD:
                        case OpCode.OP_1SUB:
                        case OpCode.OP_NEGATE:
                        case OpCode.OP_ABS:
                        case OpCode.OP_NOT:
                        case OpCode.OP_0NOTEQUAL:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted a numeric op on an empty stack");
                            }
                            BigInteger numericOPnum = CastToBigInteger(stack.Pop());

                            switch (opcode)
                            {
                                case OpCode.OP_1ADD:
                                    numericOPnum = numericOPnum.Add(BigInteger.One);
                                    break;
                                case OpCode.OP_1SUB:
                                    numericOPnum = numericOPnum.Subtract(BigInteger.One);
                                    break;
                                case OpCode.OP_NEGATE:
                                    numericOPnum = numericOPnum.Negate();
                                    break;
                                case OpCode.OP_ABS:
                                    numericOPnum = numericOPnum.Abs();
                                    break;
                                case OpCode.OP_NOT:
                                    numericOPnum = numericOPnum.Equals(BigInteger.Zero) ?
                                                                                            BigInteger.One :
                                                                                                               BigInteger.Zero;
                                    break;
                                case OpCode.OP_0NOTEQUAL:
                                    numericOPnum =
                                        numericOPnum.Equals(BigInteger.Zero) ?
                                                                                 BigInteger.Zero :
                                                                                                     BigInteger.One;
                                    break;
                            }

                            stack.Push(Utils.ReverseBytes(Utils.EncodeMpi(numericOPnum, false)));
                            break;
                        case OpCode.OP_2MUL:
                        case OpCode.OP_2DIV:
                            throw new ScriptException("Attempted to use disabled Script Op.");
                        case OpCode.OP_ADD:
                        case OpCode.OP_SUB:
                        case OpCode.OP_BOOLAND:
                        case OpCode.OP_BOOLOR:
                        case OpCode.OP_NUMEQUAL:
                        case OpCode.OP_NUMNOTEQUAL:
                        case OpCode.OP_LESSTHAN:
                        case OpCode.OP_GREATERTHAN:
                        case OpCode.OP_LESSTHANOREQUAL:
                        case OpCode.OP_GREATERTHANOREQUAL:
                        case OpCode.OP_MIN:
                        case OpCode.OP_MAX:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted a numeric op on a stack with size < 2");
                            }
                            BigInteger numericOPnum2 = CastToBigInteger(stack.Pop());
                            BigInteger numericOPnum1 = CastToBigInteger(stack.Pop());

                            BigInteger numericOPresult;
                            switch (opcode)
                            {
                                case OpCode.OP_ADD:
                                    numericOPresult = numericOPnum1.Add(numericOPnum2);
                                    break;
                                case OpCode.OP_SUB:
                                    numericOPresult = numericOPnum1.Subtract(numericOPnum2);
                                    break;
                                case OpCode.OP_BOOLAND:
                                    if (!numericOPnum1.Equals(BigInteger.Zero) && !numericOPnum2.Equals(BigInteger.Zero))
                                    {
                                        numericOPresult = BigInteger.One;
                                    }
                                    else
                                    {
                                        numericOPresult = BigInteger.Zero;
                                    }
                                    break;
                                case OpCode.OP_BOOLOR:
                                    if (!numericOPnum1.Equals(BigInteger.Zero) || !numericOPnum2.Equals(BigInteger.Zero))
                                    {
                                        numericOPresult = BigInteger.One;
                                    }
                                    else
                                    {
                                        numericOPresult = BigInteger.Zero;
                                    }
                                    break;
                                case OpCode.OP_NUMEQUAL:
                                    if (numericOPnum1.Equals(numericOPnum2))
                                    {
                                        numericOPresult = BigInteger.One;
                                    }
                                    else
                                    {
                                        numericOPresult = BigInteger.Zero;
                                    }
                                    break;
                                case OpCode.OP_NUMNOTEQUAL:
                                    if (!numericOPnum1.Equals(numericOPnum2))
                                    {
                                        numericOPresult = BigInteger.One;
                                    }
                                    else
                                    {
                                        numericOPresult = BigInteger.Zero;
                                    }
                                    break;
                                case OpCode.OP_LESSTHAN:
                                    if (numericOPnum1.CompareTo(numericOPnum2) < 0)
                                    {
                                        numericOPresult = BigInteger.One;
                                    }
                                    else
                                    {
                                        numericOPresult = BigInteger.Zero;
                                    }
                                    break;
                                case OpCode.OP_GREATERTHAN:
                                    if (numericOPnum1.CompareTo(numericOPnum2) > 0)
                                    {
                                        numericOPresult = BigInteger.One;
                                    }
                                    else
                                    {
                                        numericOPresult = BigInteger.Zero;
                                    }
                                    break;
                                case OpCode.OP_LESSTHANOREQUAL:
                                    if (numericOPnum1.CompareTo(numericOPnum2) <= 0)
                                    {
                                        numericOPresult = BigInteger.One;
                                    }
                                    else
                                    {
                                        numericOPresult = BigInteger.Zero;
                                    }
                                    break;
                                case OpCode.OP_GREATERTHANOREQUAL:
                                    if (numericOPnum1.CompareTo(numericOPnum2) >= 0)
                                    {
                                        numericOPresult = BigInteger.One;
                                    }
                                    else
                                    {
                                        numericOPresult = BigInteger.Zero;
                                    }
                                    break;
                                case OpCode.OP_MIN:
                                    if (numericOPnum1.CompareTo(numericOPnum2) < 0)
                                    {
                                        numericOPresult = numericOPnum1;
                                    }
                                    else
                                    {
                                        numericOPresult = numericOPnum2;
                                    }
                                    break;
                                case OpCode.OP_MAX:
                                    if (numericOPnum1.CompareTo(numericOPnum2) > 0)
                                    {
                                        numericOPresult = numericOPnum1;
                                    }
                                    else
                                    {
                                        numericOPresult = numericOPnum2;
                                    }
                                    break;
                                default:
                                    throw new Exception("Opcode switched at runtime?");
                            }

                            stack.Push(Utils.ReverseBytes(Utils.EncodeMpi(numericOPresult, false)));
                            break;
                        case OpCode.OP_MUL:
                        case OpCode.OP_DIV:
                        case OpCode.OP_MOD:
                        case OpCode.OP_LSHIFT:
                        case OpCode.OP_RSHIFT:
                            throw new ScriptException("Attempted to use disabled Script Op.");
                        case OpCode.OP_NUMEQUALVERIFY:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_NUMEQUALVERIFY on a stack with size < 2");
                            }
                            BigInteger OPNUMEQUALVERIFYnum2 = CastToBigInteger(stack.Pop());
                            BigInteger OPNUMEQUALVERIFYnum1 = CastToBigInteger(stack.Pop());

                            if (!OPNUMEQUALVERIFYnum1.Equals(OPNUMEQUALVERIFYnum2))
                            {
                                throw new ScriptException("OpCode.OP_NUMEQUALVERIFY failed");
                            }
                            break;
                        case OpCode.OP_WITHIN:
                            if (stack.Count < 3)
                            {
                                throw new ScriptException("Attempted OpCode.OP_WITHIN on a stack with size < 3");
                            }
                            BigInteger OPWITHINnum3 = CastToBigInteger(stack.Pop());
                            BigInteger OPWITHINnum2 = CastToBigInteger(stack.Pop());
                            BigInteger OPWITHINnum1 = CastToBigInteger(stack.Pop());
                            if (OPWITHINnum2.CompareTo(OPWITHINnum1) <= 0 && OPWITHINnum1.CompareTo(OPWITHINnum3) < 0)
                            {
                                stack.Push(Utils.ReverseBytes(Utils.EncodeMpi(BigInteger.One, false)));
                            }
                            else
                            {
                                stack.Push(Utils.ReverseBytes(Utils.EncodeMpi(BigInteger.Zero, false)));
                            }
                            break;
                        case OpCode.OP_RIPEMD160:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_RIPEMD160 on an empty stack");
                            }

                            stack.Push(Utils.ComputeDigest(new RipeMD160Digest(), stack.Pop()));
                            break;
                        case OpCode.OP_SHA1:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_SHA1 on an empty stack");
                            }

                            stack.Push(Utils.ComputeDigest(new Sha1Digest(), stack.Pop()));

                            break;
                        case OpCode.OP_SHA256:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_SHA256 on an empty stack");
                            }
                            stack.Push(Utils.ComputeDigest(new Sha256Digest(), stack.Pop()));
                            break;
                        case OpCode.OP_HASH160:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_HASH160 on an empty stack");
                            }
                            stack.Push(Utils.Sha256Hash160(stack.Pop()));
                            break;
                        case OpCode.OP_HASH256:
                            if (stack.Count < 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_SHA256 on an empty stack");
                            }
                            stack.Push(Utils.DoubleDigest(stack.Pop()));
                            break;
                        case OpCode.OP_CODESEPARATOR:
                            lastCodeSepLocation = chunk.StartLocationInProgram + 1;
                            break;
                        case OpCode.OP_CHECKSIG:
                        case OpCode.OP_CHECKSIGVERIFY:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_CHECKSIG(VERIFY) on a stack with size < 2");
                            }
                            byte[] CHECKSIGpubKey = stack.Pop();
                            byte[] CHECKSIGsig = stack.Pop();

                            byte[] CHECKSIGconnectedScript = Utils.CopyArray(script.program, lastCodeSepLocation, script.program.Length);

                            using (var OPCHECKSIGOutStream = new MemoryStream())
                            {
                                Script.WriteBytes(OPCHECKSIGOutStream, CHECKSIGsig);
                                CHECKSIGconnectedScript = RemoveAllInstancesOf(CHECKSIGconnectedScript,
                                                                               OPCHECKSIGOutStream.ToArray());
                            }

                            // TODO: Use int for indexes everywhere, we can't have that many inputs/outputs
                            Sha256Hash CHECKSIGhash = txContainingThis.HashTransactionForSignature((Transaction.SigHash)CHECKSIGsig[CHECKSIGsig.Length - 1], (int)index, CHECKSIGconnectedScript);



                            bool CHECKSIGsigValid;
                            try
                            {
                                CHECKSIGsigValid = EcKey.Verify(CHECKSIGhash.Bytes, Utils.CopyArray(CHECKSIGsig, 0, CHECKSIGsig.Length - 2), CHECKSIGpubKey);
                            }
                            catch (Exception e1)
                            {
                                // There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
                                // Because I can't verify there aren't more, we use a very generic Exception catch
                                CHECKSIGsigValid = false;
                            }

                            if (opcode == OpCode.OP_CHECKSIG)
                            {
                                stack.Push(CHECKSIGsigValid ? new byte[] { 1 } : new byte[] { 0 });
                            }
                            else if (opcode == OpCode.OP_CHECKSIGVERIFY)
                            {
                                if (!CHECKSIGsigValid)
                                {
                                    throw new ScriptException("Script failed OpCode.OP_CHECKSIGVERIFY");
                                }
                            }
                            break;
                        case OpCode.OP_CHECKMULTISIG:
                        case OpCode.OP_CHECKMULTISIGVERIFY:
                            if (stack.Count < 2)
                            {
                                throw new ScriptException("Attempted OpCode.OP_CHECKMULTISIG(VERIFY) on a stack with size < 2");
                            }
                            int CHECKMULTISIGpubKeyCount = CastToBigInteger(stack.Pop()).IntValue;
                            if (CHECKMULTISIGpubKeyCount < 0 || CHECKMULTISIGpubKeyCount > 20)
                            {
                                throw new ScriptException("OpCode.OP_CHECKMULTISIG(VERIFY) with pubkey count out of range");
                            }
                            opCount += CHECKMULTISIGpubKeyCount;
                            if (opCount > 201)
                            {
                                throw new ScriptException("Total op count > 201 during OpCode.OP_CHECKMULTISIG(VERIFY)");
                            }
                            if (stack.Count < CHECKMULTISIGpubKeyCount + 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + 2");
                            }

                            Stack<byte[]> CHECKMULTISIGpubkeys = new Stack<byte[]>();
                            for (int i = 0; i < CHECKMULTISIGpubKeyCount; i++)
                            {
                                CHECKMULTISIGpubkeys.Push(stack.Pop());
                            }

                            int CHECKMULTISIGsigCount = CastToBigInteger(stack.Pop()).IntValue;
                            if (CHECKMULTISIGsigCount < 0 || CHECKMULTISIGsigCount > CHECKMULTISIGpubKeyCount)
                            {
                                throw new ScriptException("OpCode.OP_CHECKMULTISIG(VERIFY) with sig count out of range");
                            }
                            if (stack.Count < CHECKMULTISIGsigCount + 1)
                            {
                                throw new ScriptException("Attempted OpCode.OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + num_of_signatures + 3");
                            }

                            Stack<byte[]> CHECKMULTISIGsigs = new Stack<byte[]>();
                            for (int i = 0; i < CHECKMULTISIGsigCount; i++)
                            {
                                CHECKMULTISIGsigs.Push(stack.Pop());
                            }

                            byte[] CHECKMULTISIGconnectedScript = Utils.CopyArray(script.program, lastCodeSepLocation, script.program.Length);

                            foreach (byte[] CHECKMULTISIGsig in CHECKMULTISIGsigs)
                            {
                                using (var OPCHECKMULTISIGOutStream = new MemoryStream())
                                {

                                    Script.WriteBytes(OPCHECKMULTISIGOutStream, CHECKMULTISIGsig);

                                    CHECKMULTISIGconnectedScript = RemoveAllInstancesOf(CHECKMULTISIGconnectedScript,
                                                                                        OPCHECKMULTISIGOutStream.
                                                                                            ToArray());
                                }
                            }

                            bool CHECKMULTISIGValid = true;
                            while (CHECKMULTISIGsigs.Count > 0)
                            {
                                byte[] CHECKMULTISIGsig = CHECKMULTISIGsigs.ElementAt(CHECKMULTISIGsigs.Count - 1);
                                byte[] CHECKMULTISIGpubKey = CHECKMULTISIGpubkeys.RemoveAt(CHECKMULTISIGpubkeys.Count - 1);

                                // We could reasonably move this out of the loop,
                                // but because signature verification is significantly more expensive than hashing, its not a big deal
                                Sha256Hash CHECKMULTISIGhash = txContainingThis.HashTransactionForSignature((Transaction.SigHash)CHECKMULTISIGsig[CHECKMULTISIGsig.Length - 1], (int)index, CHECKMULTISIGconnectedScript);
                                try
                                {
                                    if (EcKey.Verify(CHECKMULTISIGhash.Bytes, Utils.CopyArray(CHECKMULTISIGsig, 0, CHECKMULTISIGsig.Length - 2), CHECKMULTISIGpubKey))
                                    {
                                        CHECKMULTISIGsigs.RemoveAt(CHECKMULTISIGsigs.Count - 1);
                                    }
                                }
                                catch (Exception e)
                                {
                                    // There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
                                    // Because I can't verify there aren't more, we use a very generic Exception catch
                                }

                                if (CHECKMULTISIGsigs.Count > CHECKMULTISIGpubkeys.Count)
                                {
                                    CHECKMULTISIGValid = false;
                                    break;
                                }
                            }

                            // We uselessly remove a stack object to emulate a reference client bug
                            stack.Pop();

                            if (opcode == OpCode.OP_CHECKMULTISIG)
                            {
                                stack.Push(CHECKMULTISIGValid ? new byte[] { 1 } : new byte[] { 0 });
                            }
                            else if (opcode == OpCode.OP_CHECKMULTISIGVERIFY)
                            {
                                if (!CHECKMULTISIGValid)
                                {
                                    throw new ScriptException("Script failed OpCode.OP_CHECKMULTISIGVERIFY");
                                }
                            }
                            break;
                        case OpCode.OP_NOP1:
                        case OpCode.OP_NOP2:
                        case OpCode.OP_NOP3:
                        case OpCode.OP_NOP4:
                        case OpCode.OP_NOP5:
                        case OpCode.OP_NOP6:
                        case OpCode.OP_NOP7:
                        case OpCode.OP_NOP8:
                        case OpCode.OP_NOP9:
                        case OpCode.OP_NOP10:
                            break;

                        default:
                            throw new ScriptException("Script used a reserved Op Code");
                    }
                }

                if (stack.Count + altstack.Count > 1000 || stack.Count + altstack.Count < 0)
                {
                    throw new ScriptException("Stack size exceeded range");
                }
            }

            if (ifStack.Count != 0)
            {
                throw new ScriptException("OpCode.OP_IF/OpCode.OP_NOTIF without OpCode.OP_ENDIF");
            }
        }

        private static bool EqualsRange(byte[] a, int start, byte[] b)
        {
            if (start + b.Length > a.Length)
            {
                return false;
            }

            for (int i = 0; i < b.Length; i++)
            {
                if (a[i + start] != b[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
