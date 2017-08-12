# AntiCSRF
Simple CSRF token using HMAC for authentication and integrity.

**What does this do?**

This is intended as an alternative to Microsoft's AntiForgeryToken, but not necessarily a drop-in replacement.  

**Why would I use this?**

As you may or may not know, validating an AntiForgeryToken requires that the MachineKey be synchronized across all servers.  This might not be desirable or possible from a configuration standpoint, and crypto can be computationally expensive.
This library generates a token that will work across different or random machine keys and should not require a lot of power to validate.

**Token Format**

The token format looks something like this:

    (random data)(split)(userId)(split)(expiryTime)(split)(hmac of previous data)
Finally, the token is converted to Base64 so it can be passed through however you like as a developer.
The value *userId* may not map to an userId in your application.  It could be a user name, Guid, etc.

**Examples**

This package allows you to create an instance or simply invoke statically.  Here's an example of each:

*Static*

    string token = AntiCSRFToken.GenerateToken(username, key);
    bool isValid = AntiCSRFToken.ValidateToken(token, key, username);

*Instance*

    var instance = new AntiCSRF();
    string token = instance.GenerateToken(username, key);
    bool isValid = instance.ValidateToken(token, key, username);

Each method can also accept a discrete configuration as a parameter, represented by the AntiCSRFConfig class.  This allows you to set the token expiry time, HMAC algorithm, split character, or disable Base64 conversion.

**Contributions**

I welcome any and all suggestions or improvements to the codebase.  Thanks for dropping by and hope you find a good use for this library!
