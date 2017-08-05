using System;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using AntiCSRF.Config;

namespace AntiCSRF.Tests {
    [TestClass]
    public class UnitTests {
        private const string username = "jqpublic";
        private const string key = "super top secret";

        private const string unicode_username = "那只猫";
        private const string unicode_key = "我的秘密";

        [TestMethod]
        public void CreateAndVerifyToken() {
            var token = AntiCSRFToken.GenerateToken(username, key);
            Assert.IsNotNull(token, "Token should not be empty or null.");

            var isValid = AntiCSRFToken.ValidateToken(token, key, username);
            Assert.IsTrue(isValid, "isValid should be true.");
        }

        [TestMethod]
        public void CreateAndVerifyUnicode() {
            var token = AntiCSRFToken.GenerateToken(unicode_username, unicode_key);
            Assert.IsNotNull(token, "Token should not be empty or null.");

            var isValid = AntiCSRFToken.ValidateToken(token, unicode_key, unicode_username);
            Assert.IsTrue(isValid, "isValid should be true.");
        }

        [TestMethod]
        public void CreateAndExpireToken() {
            var c = new AntiCSRFConfig {
                expiryInSeconds = 1
            };

            var token = AntiCSRFToken.GenerateToken(username, key, c);
            Assert.IsNotNull(token, "Token should not be empty or null.");

            Thread.Sleep(1001);

            var isValid = AntiCSRFToken.ValidateToken(token, key, username, c);
            Assert.IsFalse(isValid, "isValid should be false.");
        }

        [TestMethod]
        public void CreateTokenAndChangeUser() {
            var token = AntiCSRFToken.GenerateToken(username, key);
            Assert.IsNotNull(token, "Token should not be empty or null.");

            var arr = username.ToCharArray();
            Array.Reverse(arr);
            var emanresu = new string(arr);

            var isValid = AntiCSRFToken.ValidateToken(token, key, emanresu);
            Assert.IsFalse(isValid, "isValid should be false.");
        }

        [TestMethod]
        public void CreateAndVerifyToken_HMACSHA512() {
            var c = new AntiCSRFConfig {
                hmac_alg = "SHA512"
            };
            var token = AntiCSRFToken.GenerateToken(username, key, c);
            Assert.IsNotNull(token, "Token should not be empty or null.");

            var isValid = AntiCSRFToken.ValidateToken(token, key, username, c);
            Assert.IsTrue(isValid, "isValid should be true.");
        }

        [TestMethod]
        public void CreateAndVerifyToken_NoBase64() {
            var c = new AntiCSRFConfig {
                useBase64 = false
            };
            var token = AntiCSRFToken.GenerateToken(username, key, c);
            Assert.IsNotNull(token, "Token should not be empty or null.");

            var isValid = AntiCSRFToken.ValidateToken(token, key, username, c);
            Assert.IsTrue(isValid, "isValid should be true.");
        }

        [TestMethod]
        public void CreateToken_BadDataSize() {
            var c = new AntiCSRFConfig {
                dataSize = -1
            };

            Assert.ThrowsException<ArgumentOutOfRangeException>(() => {
                AntiCSRFToken.GenerateToken(username, key, c);
            });
        }

        [TestMethod]
        public void CreateToken_BadExpiry() {
            var c = new AntiCSRFConfig {
                expiryInSeconds = -1
            };

            Assert.ThrowsException<ArgumentOutOfRangeException>(() => {
                AntiCSRFToken.GenerateToken(username, key, c);
            });
        }
    }
}