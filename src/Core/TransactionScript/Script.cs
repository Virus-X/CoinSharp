using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CoinSharp.TransactionScript
{
    /// <summary>
    /// <p>Instructions for redeeming a payment.</p>
    /// 
    /// <p>Bitcoin transactions don't specify what they do directly. Instead <a href="https://en.bitcoin.it/wiki/Script">a
    /// small binary stack language</a> is used to define programs that when evaluated return whether the transaction
    /// "accepts" or rejects the other transactions connected to it.</p>
    /// 
    /// <p>In SPV mode, scripts are not run, because that would require all transactions to be available and lightweight
    /// clients don't have that data. In full mode, this class is used to run the interpreted language. It also has
    /// static methods for building scripts.</p>
    /// </summary>
    public class Script
    {
        internal byte[] program;
        private int cursor;

        // The program is a set of byte[]s where each element is either [opcode] or [data, data, data ...]
        internal IList<ScriptChunk> chunks;
        private readonly NetworkParameters netParams;

        /// <summary>
        /// Returns true if this transaction is of a format that means it was a direct IP to IP transaction. These
        /// transactions are deprecated and no longer used, support for creating them has been removed from the official
        /// client.
        /// </summary>
        public bool IsSentToIp
        {
            get { return chunks.Count == 2 && ((OpCode)chunks[1].Data[0] == OpCode.OP_CHECKSIG && chunks[0].Data.Length > 1); }
        }

        // Only for internal use
        private Script()
        {
            netParams = null;
        }

        /// <summary>
        /// Construct a Script using the given network parameters and a range of the programBytes array.
        /// </summary>
        /// <param name="netParams">       Network parameters. </param>
        /// <param name="programBytes"> Array of program bytes from a transaction. </param>
        /// <param name="offset">       How many bytes into programBytes to start reading from. </param>
        /// <param name="length">       How many bytes to read. </param>
        /// <exception cref="ScriptException"> </exception>
        public Script(NetworkParameters netParams, byte[] programBytes, int offset, int length)
        {
            this.netParams = netParams;
            Parse(programBytes, offset, length);
        }

        /// <summary>
        /// Returns the program opcodes as a string, for example "[1234] DUP HAHS160"
        /// </summary>
        public override string ToString()
        {
            StringBuilder buf = new StringBuilder();
            foreach (ScriptChunk chunk in chunks)
            {
                if (chunk.IsOpCode)
                {
                    buf.Append(GetOpCodeName(chunk.Data[0]));
                    buf.Append(" ");
                }
                else
                {
                    // Data chunk
                    buf.Append("[");
                    buf.Append(Utils.BytesToHexString(chunk.Data));
                    buf.Append("] ");
                }
            }
            return buf.ToString();
        }

        /// <summary>
        /// Converts the given OpCode into a string (eg "0", "PUSHDATA", or "NON_OP(10)")
        /// </summary>
        public static string GetOpCodeName(byte opCode)
        {
            int opcode = opCode & 0xff;
            if (Enum.IsDefined(typeof(OpCode), opcode))
            {
                return ((OpCode)opcode).ToString().ToUpper();
            }

            return string.Format("NON_OP({0})", opcode);
        }

        private byte[] GetData(int len)
        {
            if (len > program.Length - cursor)
            {
                throw new ScriptException("Failed read of " + len + " bytes");
            }

            try
            {
                byte[] buf = new byte[len];
                Array.Copy(program, cursor, buf, 0, len);
                cursor += len;
                return buf;
            }
            catch (System.IndexOutOfRangeException e)
            {
                // We want running out of data in the array to be treated as a handleable script parsing exception,
                // not something that abnormally terminates the app.
                throw new ScriptException("Failed read of " + len + " bytes", e);
            }
        }

        private int ReadByte()
        {
            try
            {
                return 0xFF & program[cursor++];
            }
            catch (System.IndexOutOfRangeException e)
            {
                throw new ScriptException("Attempted to read outside of script boundaries");
            }
        }

        /// <summary>
        /// To run a script, first we parse it which breaks it up into chunks representing pushes of
        /// data or logical opcodes. Then we can run the parsed chunks.
        /// <p/>
        /// The reason for this split, instead of just interpreting directly, is to make it easier
        /// to reach into a programs structure and pull out bits of data without having to run it.
        /// This is necessary to render the to/from addresses of transactions in a user interface.
        /// The official client does something similar.
        /// </summary>
        private void Parse(byte[] programBytes, int offset, int length)
        {
            // TODO: this is inefficient
            program = new byte[length];
            Array.Copy(programBytes, offset, program, 0, length);

            offset = 0;
            chunks = new List<ScriptChunk>(10); // Arbitrary choice of initial size.
            cursor = offset;
            while (cursor < offset + length)
            {
                int startLocationInProgram = cursor - offset;
                var opcode = (OpCode)ReadByte();
                if (opcode >= 0 && opcode < OpCode.OP_PUSHDATA1)
                {
                    // Read some bytes of data, where how many is the opcode value itself.
                    chunks.Add(new ScriptChunk(false, GetData((int)opcode), startLocationInProgram)); // opcode == len here.
                }
                else if (opcode == OpCode.OP_PUSHDATA1)
                {
                    int len = ReadByte();
                    chunks.Add(new ScriptChunk(false, GetData(len), startLocationInProgram));
                }
                else if (opcode == OpCode.OP_PUSHDATA2)
                {
                    // Read a short, then read that many bytes of data.
                    int len = ReadByte() | (ReadByte() << 8);
                    chunks.Add(new ScriptChunk(false, GetData(len), startLocationInProgram));
                }
                else if (opcode == OpCode.OP_PUSHDATA4)
                {
                    // Read a uint32, then read that many bytes of data.
                    // Though this is allowed, because its value cannot be > 520, it should never actually be used
                    long len = ReadByte() | (ReadByte() << 8) | (ReadByte() << 16) | (ReadByte() << 24);
                    chunks.Add(new ScriptChunk(false, GetData((int)len), startLocationInProgram));
                }
                else
                {
                    chunks.Add(new ScriptChunk(true, new[] { (byte)opcode }, startLocationInProgram));
                }
            }
        }

        /// <summary>
        /// Returns true if this script is of the form [sig] OpCode.OP_CHECKSIG. This form was originally intended for transactions
        /// where the peers talked to each other directly via TCP/IP, but has fallen out of favor with time due to that mode
        /// of operation being susceptible to man-in-the-middle attacks. It is still used in coinbase outputs and can be
        /// useful more exotic types of transaction, but today most payments are to addresses.
        /// </summary>
        public virtual bool SentToRawPubKey
        {
            get
            {
                if (chunks.Count != 2)
                {
                    return false;
                }
                return chunks[1].EqualsOpCode(OpCode.OP_CHECKSIG) && !chunks[0].IsOpCode && chunks[0].Data.Length > 1;
            }
        }

        /// <summary>
        /// Returns true if this script is of the form DUP HASH160 [pubkey hash] EQUALVERIFY CHECKSIG, ie, payment to an
        /// address like 1VayNert3x1KzbpzMGt2qdqrAThiRovi8. This form was originally intended for the case where you wish
        /// to send somebody money with a written code because their node is offline, but over time has become the standard
        /// way to make payments due to the short and recognizable base58 form addresses come in.
        /// </summary>
        public virtual bool SentToAddress
        {
            get
            {
                if (chunks.Count != 5)
                {
                    return false;
                }
                return chunks[0].EqualsOpCode(OpCode.OP_DUP) && chunks[1].EqualsOpCode(OpCode.OP_HASH160) && chunks[2].Data.Length == Address.Length && chunks[3].EqualsOpCode(OpCode.OP_EQUALVERIFY) && chunks[4].EqualsOpCode(OpCode.OP_CHECKSIG);
            }
        }

        /// <summary>
        /// If a program matches the standard template DUP HASH160 [pubkey hash] EQUALVERIFY CHECKSIG
        /// then this function retrieves the third element, otherwise it throws a ScriptException.
        /// 
        /// This is useful for fetching the destination address of a transaction.
        /// </summary>
        public virtual byte[] PubKeyHash
        {
            get
            {
                if (!SentToAddress)
                {
                    throw new ScriptException("Script not in the standard scriptPubKey form");
                }
                // Otherwise, the third element is the hash of the public key, ie the bitcoin address.
                return chunks[2].Data;
            }
        }

        /// <summary>
        /// Returns the public key in this script. If a script contains two constants and nothing else, it is assumed to
        /// be a scriptSig (input) for a pay-to-address output and the second constant is returned (the first is the
        /// signature). If a script contains a constant and an OpCode.OP_CHECKSIG opcode, the constant is returned as it is
        /// assumed to be a direct pay-to-key scriptPubKey (output) and the first constant is the public key.
        /// </summary>
        /// <exception cref="ScriptException"> if the script is none of the named forms. </exception>
        public virtual byte[] PubKey
        {
            get
            {
                if (chunks.Count != 2)
                {
                    throw new ScriptException("Script not of right size, expecting 2 but got " + chunks.Count);
                }
                if (chunks[0].Data.Length > 2 && chunks[1].Data.Length > 2)
                {
                    // If we have two large constants assume the input to a pay-to-address output.
                    return chunks[1].Data;
                }
                if (chunks[1].Data.Length == 1 && chunks[1].EqualsOpCode(OpCode.OP_CHECKSIG) && chunks[0].Data.Length > 2)
                {
                    // A large constant followed by an OpCode.OP_CHECKSIG is the key.
                    return chunks[0].Data;
                }

                throw new ScriptException("Script did not match expected form: " + ToString());
            }
        }

        /// <summary>
        /// Convenience wrapper around getPubKey. Only works for scriptSigs.
        /// </summary>
        public virtual Address FromAddress
        {
            get
            {
                return new Address(netParams, Utils.Sha256Hash160(PubKey));
            }
        }

        /// <summary>
        /// Gets the destination address from this script, if it's in the required form (see getPubKey).
        /// </summary>
        /// <exception cref="ScriptException"> </exception>
        public virtual Address ToAddress
        {
            get
            {
                return new Address(netParams, PubKeyHash);
            }
        }

        #region Interface for writing scripts from scratch

        /// <summary>
        /// Writes out the given byte buffer to the output stream with the correct opcode prefix
        /// </summary>
        internal static void WriteBytes(Stream os, byte[] buf)
        {
            if (buf.Length < (int)OpCode.OP_PUSHDATA1)
            {
                os.WriteByte((byte)buf.Length);
            }
            else if (buf.Length < 256)
            {
                os.WriteByte((byte)OpCode.OP_PUSHDATA1);
                os.WriteByte((byte)buf.Length);
            }
            else if (buf.Length < 65536)
            {
                os.WriteByte((byte)OpCode.OP_PUSHDATA2);
                os.WriteByte((byte)buf.Length);
                os.WriteByte((byte)(buf.Length >> 8));
            }
            else
            {
                throw new NotSupportedException();
            }

            os.Write(buf, 0, buf.Length);
        }

        public static byte[] CreateOutputScript(Address to)
        {
            using (var bits = new MemoryStream())
            {
                // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
                bits.WriteByte((byte)OpCode.OP_DUP);
                bits.WriteByte((byte)OpCode.OP_HASH160);
                WriteBytes(bits, to.Hash160);
                bits.WriteByte((byte)OpCode.OP_EQUALVERIFY);
                bits.WriteByte((byte)OpCode.OP_CHECKSIG);
                return bits.ToArray();
            }
        }

        /// <summary>
        /// Create a script that sends coins directly to the given public key (eg in a coinbase transaction).
        /// </summary>
        public static byte[] CreateOutputScript(byte[] pubkey)
        {
            using (var bits = new MemoryStream())
            {
                WriteBytes(bits, pubkey);
                bits.WriteByte((byte)OpCode.OP_CHECKSIG);
                return bits.ToArray();
            }
        }

        /// <summary>
        /// Creates a script that sends coins directly to the given public key. Same as
        /// <seealso cref="Script#CreateOutputScript(byte[])"/> but more type safe.
        /// </summary>
        public static byte[] CreateOutputScript(EcKey pubkey)
        {
            return CreateOutputScript(pubkey.PubKey);
        }

        public static byte[] CreateInputScript(byte[] signature, byte[] pubkey)
        {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            using (var bits = new MemoryStream())
            {
                WriteBytes(bits, signature);
                WriteBytes(bits, pubkey);
                return bits.ToArray();
            }
        }

        #endregion

        #region Interface used during verification of transactions/blocks

        private static int GetSigOpCount(IList<ScriptChunk> chunks, bool accurate)
        {
            int sigOps = 0;
            var lastOpCode = OpCode.OP_INVALIDOPCODE;
            foreach (ScriptChunk chunk in chunks)
            {
                if (chunk.IsOpCode)
                {
                    var opcode = (OpCode)(0xFF & chunk.Data[0]);
                    switch (opcode)
                    {
                        case OpCode.OP_CHECKSIG:
                        case OpCode.OP_CHECKSIGVERIFY:
                            sigOps++;
                            break;
                        case OpCode.OP_CHECKMULTISIG:
                        case OpCode.OP_CHECKMULTISIGVERIFY:
                            if (accurate && lastOpCode >= OpCode.OP_1 && lastOpCode <= OpCode.OP_16)
                            {
                                sigOps += ScriptRunner.GetOpNValue(lastOpCode);
                            }
                            else
                            {
                                sigOps += 20;
                            }
                            break;
                    }

                    lastOpCode = opcode;
                }
            }
            return sigOps;
        }

        /// <summary>
        /// Gets the count of regular SigOps in the script program (counting multisig ops as 20)
        /// </summary>
        public static int GetSigOpCount(byte[] program)
        {
            var script = new Script();
            try
            {
                script.Parse(program, 0, program.Length);
            }
            catch (ScriptException)
            {
                // Ignore errors and count up to the parse-able length
            }
            return GetSigOpCount(script.chunks, false);
        }

        /// <summary>
        /// Gets the count of P2SH Sig Ops in the Script scriptSig
        /// </summary>
        public static long GetP2SHSigOpCount(byte[] scriptSig)
        {
            Script script = new Script();
            try
            {
                script.Parse(scriptSig, 0, scriptSig.Length);
            }
            catch (ScriptException e)
            {
                // Ignore errors and count up to the parse-able length
            }
            for (int i = script.chunks.Count - 1; i >= 0; i--)
            {
                if (!script.chunks[i].IsOpCode)
                {
                    Script subScript = new Script();
                    subScript.Parse(script.chunks[i].Data, 0, script.chunks[i].Data.Length);
                    return GetSigOpCount(subScript.chunks, true);
                }
            }
            return 0;
        }

        /// <summary>
        /// <p>Whether or not this is a scriptPubKey representing a pay-to-script-hash output. In such outputs, the logic that
        /// controls reclamation is not actually in the output at all. Instead there's just a hash, and it's up to the
        /// spending input to provide a program matching that hash. This rule is "soft enforced" by the network as it does
        /// not exist in Satoshis original implementation. It means blocks containing P2SH transactions that don't match
        /// correctly are considered valid, but won't be mined upon, so they'll be rapidly re-orgd out of the chain. This
        /// logic is defined by <a href="https://en.bitcoin.it/wiki/BIP_0016">BIP 16</a>.</p>
        /// 
        /// <p>bitcoinj does not support creation of P2SH transactions today. The goal of P2SH is to allow short addresses
        /// even for complex scripts (eg, multi-sig outputs) so they are convenient to work with in things like QRcodes or
        /// with copy/paste, and also to minimize the size of the unspent output set (which improves performance of the
        /// Bitcoin system).</p>
        /// </summary>
        public virtual bool PayToScriptHash
        {
            get
            {
                return program.Length == 23 && (OpCode)(program[0] & 0xff) == OpCode.OP_HASH160 && (program[1] & 0xff) == 0x14 && (OpCode)(program[22] & 0xff) == OpCode.OP_EQUAL;
            }
        }

        /// <summary>
        /// Returns the script bytes of inputScript with all instances of the given op code removed
        /// </summary>
        public static byte[] RemoveAllInstancesOfOp(byte[] inputScript, int opCode)
        {
            return ScriptRunner.RemoveAllInstancesOf(inputScript, new byte[] { (byte)opCode });
        }

        #endregion

        #region Script verification and helpers

        /// <summary>
        /// Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey. </summary>
        /// <param name="txContainingThis"> The transaction in which this input scriptSig resides. </param>
        /// <param name="scriptSigIndex"> The index in txContainingThis of the scriptSig (note: NOT the index of the scriptPubKey). </param>
        /// <param name="scriptPubKey"> The connected scriptPubKey containing the conditions needed to claim the value. </param>
        /// <param name="enforceP2SH"> Whether "pay to script hash" rules should be enforced. If in doubt, set to true. </param>
        /// <exception cref="VerificationException"> if this script does not correctly spend the scriptPubKey </exception>
        public virtual void CorrectlySpends(Transaction txContainingThis, long scriptSigIndex, Script scriptPubKey, bool enforceP2SH)
        {
            if (program.Length > 10000 || scriptPubKey.program.Length > 10000)
            {
                throw new ScriptException("Script larger than 10,000 bytes");
            }

            Stack<byte[]> stack = new Stack<byte[]>();
            Stack<byte[]> p2shStack = null;

            ScriptRunner.ExecuteScript(txContainingThis, scriptSigIndex, this, stack);
            if (enforceP2SH)
            {
                p2shStack = new Stack<byte[]>(stack);
            }
            ScriptRunner.ExecuteScript(txContainingThis, scriptSigIndex, scriptPubKey, stack);

            if (stack.Count == 0)
            {
                throw new ScriptException("Stack empty at end of script execution.");
            }

            if (!ScriptRunner.CastToBool(stack.Pop()))
            {
                throw new ScriptException("Script resulted in a non-true stack");
            }

            // P2SH is pay to script hash. It means that the scriptPubKey has a special form which is a valid
            // program but it has "useless" form that if evaluated as a normal program always returns true.
            // Instead, miners recognize it as special based on its template - it provides a hash of the real scriptPubKey
            // and that must be provided by the input. The goal of this bizarre arrangement is twofold:
            //
            // (1) You can sum up a large, complex script (like a CHECKMULTISIG script) with an address that's the same
            //     size as a regular address. This means it doesn't overload scannable QR codes/NFC tags or become
            //     un-wieldy to copy/paste.
            // (2) It allows the working set to be smaller: nodes perform best when they can store as many unspent outputs
            //     in RAM as possible, so if the outputs are made smaller and the inputs get bigger, then it's better for
            //     overall scalability and performance.

            // TODO: Check if we can take out enforceP2SH if there's a checkpoint at the enforcement block.
            if (enforceP2SH && scriptPubKey.PayToScriptHash)
            {
                foreach (ScriptChunk chunk in chunks)
                {
                    if (chunk.IsOpCode && (OpCode)(chunk.Data[0] & 0xff) > OpCode.OP_16)
                    {
                        throw new ScriptException("Attempted to spend a P2SH scriptPubKey with a script that contained script ops");
                    }
                }

                byte[] scriptPubKeyBytes = p2shStack.Pop();
                var scriptPubKeyP2SH = new Script(netParams, scriptPubKeyBytes, 0, scriptPubKeyBytes.Length);

                ScriptRunner.ExecuteScript(txContainingThis, scriptSigIndex, scriptPubKeyP2SH, p2shStack);

                if (p2shStack.Count == 0)
                {
                    throw new ScriptException("P2SH stack empty at end of script execution.");
                }

                if (!ScriptRunner.CastToBool(p2shStack.Pop()))
                {
                    throw new ScriptException("P2SH script execution resulted in a non-true stack");
                }
            }
        }

        #endregion
    }
}
