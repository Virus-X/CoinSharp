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
using System.Collections.Generic;
using NUnit.Framework;

namespace CoinSharp.Test
{
    [TestFixture]
    public class UtilsTest
    {
        [Test]
        public void TestToNanoCoins()
        {
            // string version
            Assert.AreEqual(Utils.Cent, Utils.ToNanoCoins("0.01"));
            Assert.AreEqual(Utils.Cent, Utils.ToNanoCoins("1E-2"));
            Assert.AreEqual(Utils.Coin + Utils.Cent, Utils.ToNanoCoins("1.01"));
            try
            {
                Utils.ToNanoCoins("2E-20");
                Assert.Fail("should not have accepted fractional nanocoins");
            }
            catch (ArithmeticException)
            {
            }

            // int version
            Assert.AreEqual(Utils.Cent, Utils.ToNanoCoins(0, 1));
        }

        [Test]
        public void TestFormatting()
        {
            Assert.AreEqual("1.23", Utils.BitcoinValueToFriendlystring(Utils.ToNanoCoins(1, 23)));
            Assert.AreEqual("-1.23", Utils.BitcoinValueToFriendlystring(-(long) Utils.ToNanoCoins(1, 23)));
        }

        [Test]
        public void TestStackRemoveAt()
        {
            Stack<int> stack = new Stack<int>();
            stack.Push(1);
            stack.Push(2);
            stack.Push(3);
            Assert.AreEqual(2, stack.RemoveAt(1));
            Assert.AreEqual(2, stack.Count);
            Assert.AreEqual(3, stack.Pop());
            Assert.AreEqual(1, stack.Pop());
        }
    }
}