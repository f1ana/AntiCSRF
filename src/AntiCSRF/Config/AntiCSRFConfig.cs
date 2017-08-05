namespace AntiCSRF.Config {
    /// <summary>
    /// Configuration class for AntiCSRF classes
    /// </summary>
    public class AntiCSRFConfig {
        /// <summary>
        /// Size (in bytes) of random data contained within the token
        /// </summary>
        public int dataSize = 16;
        /// <summary>
        /// Expiry (in seconds) for the token
        /// </summary>
        public int expiryInSeconds = 3600;
        /// <summary>
        /// HMAC Algorithm for the token.  "HMAC" is already prefixed, the following are valid options:
        /// SHA1, MD5, SHA256, SHA384, SHA512
        /// </summary>
        public string hmac_alg = "SHA256";
        /// <summary>
        /// Character used to split pieces of the token
        /// </summary>
        public char split = '\n';
        /// <summary>
        /// Determines if token should be encoded (or decoded) as base64
        /// </summary>
        public bool useBase64 = true;
    }
}