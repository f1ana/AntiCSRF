using System;
using System.Security.Cryptography;

namespace AntiCSRF.Factory {
    /// <summary>
    /// Factory pattern for generating HMAC instances
    /// </summary>
    public static class HMACGenerator {
        /// <summary>
        /// Factory method for generating HMAC instances
        /// </summary>
        /// <param name="algorithm">HMAC Algorithm</param>
        /// <returns>HMAC Instance</returns>
        public static HMAC Create(string algorithm) {
            switch (algorithm.ToLowerInvariant()) {
                case "sha1":
                    return new HMACSHA1();
                case "md5":
                    return new HMACMD5();
                case "sha256":
                    return new HMACSHA256();
                case "sha384":
                    return new HMACSHA384();
                case "sha512":
                    return new HMACSHA512();
                default:
                    throw new NotSupportedException($"{algorithm} is not a supported algorithm.");
            }
        }
    }
}