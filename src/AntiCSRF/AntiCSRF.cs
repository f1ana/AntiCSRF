namespace AntiCSRF {
    public class AntiCSRF {
        private readonly AntiCSRFConfig _config;

        public AntiCSRF() {
            _config = new AntiCSRFConfig();
        }

        public AntiCSRF(AntiCSRFConfig config) {
            _config = config;
        }

        public string GenerateToken(string userId, string key) {
            return AntiCSRFToken.GenerateToken(userId, key, _config);
        }

        public bool ValidateToken(string token, string key, string userId) {
            return AntiCSRFToken.ValidateToken(token, key, userId, _config);
        }
    }
}