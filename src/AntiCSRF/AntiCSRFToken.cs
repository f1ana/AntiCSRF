using System;
using System.Security.Cryptography;
using System.Text;

namespace AntiCSRF {
    public static class AntiCSRFToken {
        public static string GenerateToken(string userId, string key) {
            var c = new AntiCSRFConfig();
            return GenerateToken(userId, key, c);
        }

        public static string GenerateToken(string userId, string key, AntiCSRFConfig config) {
            if (config.dataSize <= 0) {
                throw new ArgumentOutOfRangeException("config.dataSize");
            }
            if (config.expiryInSeconds <= 0) {
                throw new ArgumentOutOfRangeException("config.expiryInSeconds");
            }

            var data = new byte[config.dataSize];
            using (var rnd = new RNGCryptoServiceProvider()) {
                rnd.GetBytes(data);
            }

            var expires = DateTime.UtcNow.AddSeconds(config.expiryInSeconds).Ticks;
            var raw = BitConverter.ToString(data).Replace("-", "") + config.split +
                      userId + config.split + expires;

            string signature;
            using (var hmac = HMAC.Create($"HMAC{config.hmac_alg}")) {
                hmac.Key = Encoding.UTF8.GetBytes(key);
                var braw = Encoding.UTF8.GetBytes(raw);

                signature = BitConverter.ToString(hmac.ComputeHash(braw)).Replace("-", "");
            }
            if (signature.Length < 1) {
                throw new Exception("Could not generate signature.");
            }

            var retVal = $"{raw}{config.split}{signature}";
            if (config.useBase64) {
                var retValb = Encoding.UTF8.GetBytes(retVal);
                return Convert.ToBase64String(retValb);
            }
            return retVal;
        }

        public static bool ValidateToken(string token, string key, string userId) {
            var c = new AntiCSRFConfig();
            return ValidateToken(token, key, userId, c);
        }

        public static bool ValidateToken(string token, string key, string userId, AntiCSRFConfig config) {
            if (config.useBase64) {
                var bToken = Convert.FromBase64String(token);
                token = Encoding.UTF8.GetString(bToken);
            }

            var parts = token.Split(config.split);

            var raw = $"{parts[0]}{config.split}{parts[1]}{config.split}{parts[2]}";

            string signature;
            using (var hmac = HMAC.Create($"HMAC{config.hmac_alg}")) {
                hmac.Key = Encoding.UTF8.GetBytes(key);
                var braw = Encoding.UTF8.GetBytes(raw);

                signature = BitConverter.ToString(hmac.ComputeHash(braw)).Replace("-", "");
            }

            var s1 = signature;
            var s2 = parts[3];

            if (s1.Length != s2.Length) {
                return false;
            }

            if (!string.Equals(s1, s2, StringComparison.InvariantCulture)) {
                return false;
            }
            var currentTicks = Convert.ToInt64(parts[2]);
            var nowTicks = DateTime.UtcNow.Ticks;
            if (currentTicks < nowTicks) {
                return false;
            }
            if (parts[1] != userId) {
                return false;
            }

            return true;
        }
    }
}