package com.sphenon.basics.security;

/****************************************************************************
  Copyright 2001-2018 Sphenon GmbH

  Licensed under the Apache License, Version 2.0 (the "License"); you may not
  use this file except in compliance with the License. You may obtain a copy
  of the License at http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  License for the specific language governing permissions and limitations
  under the License.
*****************************************************************************/

import com.sphenon.basics.context.*;
import com.sphenon.basics.context.classes.*;
import com.sphenon.basics.message.*;
import com.sphenon.basics.exception.*;
import com.sphenon.basics.notification.*;
import com.sphenon.basics.customary.*;
import com.sphenon.basics.configuration.*;
import com.sphenon.basics.expression.*;

import com.sphenon.basics.security.returncodes.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.regex.*;

abstract public class UserBaseImpl implements User {
    static final public Class _class = UserBaseImpl.class;

    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(_class); };

    static protected Configuration config;
    static protected int security_version;
    static {
        CallContext context = RootContext.getInitialisationContext();
        config = Configuration.create(context, _class);
        security_version = config.get(context, "SecurityVersion", 1);
    };

    protected boolean             is_valid;

    public UserBaseImpl (CallContext context) {
    }

    /**
     * Checks validity of user instance. If parameters are invalid, the user instance
     * will be invalid, too. This condition should be checked before the user instance
     * is used.
     * @param name                     user name
     * @param permissions              permissions
     * @param encrypted_password       encrypted password
     * @param need_to_change_password  whether new password is required before first login
     * @param user_manager             is used to delegate password changes to, and to inform
     *                                 about modification of the security database
     */
    protected void check (CallContext context) {
        if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Checking user data object..."); }

        if (this.getName(context) == null || this.getPermissions(context) == null || this.getEncryptedPassword(context) == null) {
            if (this.getName(context) == null) {
                if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendWarning(context, "Invalid user, name invalid or null"); }
            }
            if (this.getPermissions(context) == null) {
                if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendWarning(context, "Invalid user, permissions invalid or null"); }
            }
            if (this.getEncryptedPassword(context) == null) {
                if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendWarning(context, "Invalid user, password invalid or null"); }
            }
            this.is_valid                = false;

            if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "User data object NOT valid."); }
        } else {
            this.is_valid = true;
            if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "User data object valid."); }
        }
    }

    abstract public String getName(CallContext context);

    abstract public String getEncryptedPassword (CallContext context);

    abstract public boolean needToChangePassword (CallContext context);

    abstract public Permissions getPermissions (CallContext context);

    abstract protected void updatePassword(CallContext context, String new_digest) throws InvalidNewPassword;

    public void confirmPassword(CallContext context, String cleartext_password, String new_password) throws PasswordChangeRequired, AccessDenied, InvalidNewPassword {
        if (this.isValid(context) == false) {
            if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Invalid user object '%(name)'", "name", this.getName(context)); }
            AccessDenied.createAndThrow(context, "");
            throw (AccessDenied) null;
        }

        boolean nothing_found = false;

        String stored_digest = this.getEncryptedPassword(context);

        if (stored_digest == null) {
            // we do the calculations anyway, so the hacker cannot determine from
            // the response time whether a user was found or not
            nothing_found = true;
            stored_digest = (security_version >= 2 ? DUMMY_STORED_2 : DUMMY_DIGEST_1);
        }

        byte[] salt = null;
        if (security_version >= 2) {
            String stored_salt = stored_digest.substring(0, SALTSIZE * 2);
            salt = convertToBytes(context, stored_salt);
        }

        String digest = this.getDigest(context, cleartext_password, salt);
        if (    nothing_found
             || cleartext_password == null
             || stored_digest.equalsIgnoreCase(digest) == false
            ) {
            if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Digests do not match, configured '%(configdigest)', calculated from user input '%(inputdigest)'", "configdigest", stored_digest, "inputdigest", digest); }
            AccessDenied.createAndThrow(context, "");
            throw (AccessDenied) null;
        }

        if (new_password != null) {
            String new_digest = this.getDigest(context, new_password, createSalt(context));

            if (stored_digest.equalsIgnoreCase(new_digest)) {
                if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendCaution(context, "Invalid new password: same as before, new password is rejected"); }
                if (this.needToChangePassword(context)) {
                    PasswordChangeRequired.createAndThrow(context, InvalidNewPassword.createInvalidNewPassword(context, "Invalid new password: same as before, new password is rejected"), "Password ok, but password change required before login");
                    throw (PasswordChangeRequired) null;
                } else {
                    InvalidNewPassword.createAndThrow(context, "Invalid new password: same as before, new password is rejected");
                    throw (InvalidNewPassword) null;
                }
            }

            this.updatePassword(context, new_digest);

            if (    this.getEncryptedPassword(context) == null
                 || this.getEncryptedPassword(context).equalsIgnoreCase(new_digest) == false
               ) {
                if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendCaution(context, "Inconsistency: after successful password change, new password is rejected"); }
                if (this.needToChangePassword(context)) {
                    PasswordChangeRequired.createAndThrow(context, InvalidNewPassword.createInvalidNewPassword(context, "Inconsistency: after successful password change, new password is rejected"), "Password ok, but password change required before login");
                    throw (PasswordChangeRequired) null;
                } else {
                    InvalidNewPassword.createAndThrow(context, "Inconsistency: after successful password change, new password is rejected");
                    throw (InvalidNewPassword) null;
                }
            }

            // really only inconsistency check - updatePassword should throw something if problem
            if (this.needToChangePassword(context)) {
                if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendCaution(context, "Inconsistency: after successful password change, password change is still required"); }
            }
        }

        if (this.needToChangePassword(context)) {
            if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Password ok, but password change required before login"); }
            PasswordChangeRequired.createAndThrow(context, "Password ok, but password change required before login");
            throw (PasswordChangeRequired) null;
        }

        // we're fine
    }

    public boolean isValid (CallContext context) {
        return this.is_valid;
    }

    private static final char HEX_CHARS[] = new char[] {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    static public String getDigest(CallContext context, String password) {
        if (security_version >= 2) {
            CustomaryContext.create((Context)context).throwConfigurationError(context, "The package is configured for security version '%(version)', the invoked method is not any longer available since version 2.", "version", security_version);
            throw (ExceptionConfigurationError) null; // compiler insists
        }
        return getDigest(context, password, null);
    }

    private final static int    ITERATIONS     = 1000;
    private final static int    SALTSIZE       = 8; // bytes
    private final static String DUMMY_DIGEST_1 = new String(new char[40]).replace('\0', '0');
    private final static String DUMMY_DIGEST_2 = new String(new char[512]).replace('\0', '0');
    private final static String DUMMY_SALT     = new String(new char[SALTSIZE * 2]).replace('\0', '0');
    private final static String DUMMY_STORED_2 = DUMMY_SALT + DUMMY_DIGEST_2;

    static public String getDigest(CallContext context, String password, byte[] salt) {
        // see https://www.owasp.org/index.php/Hashing_Java
        // for recommendations on algorithm
        MessageDigest md;
        String algorithm = null;
        try {
            algorithm = (security_version >= 2 ? "SHA-512" : "SHA1");
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException nsae) {
            CustomaryContext.create(Context.create(context)).throwConfigurationError(context, "MessageDigest algorithm '%(algorithm)' not available", "algorithm", algorithm);
            throw (ExceptionConfigurationError) null; // compiler insists
        }

        if (security_version >= 2) {
            md.reset();
            md.update(salt);
        }

        byte[] bytes = md.digest(password.getBytes());

        if (security_version >= 2) {
            for (int i = 0; i < ITERATIONS; i++) {
                md.reset();
                bytes = md.digest(bytes);
            }
        }

        String s1 = (security_version >= 2 ? convertToHexString(context, salt) : "");
        String s2 = convertToHexString(context, bytes);

        return s1 + s2;
   }

    static protected String convertToHexString(CallContext context, byte[] bytes) {
        int i, n;
        char[] chars = new char[bytes.length*2];
        for (i = bytes.length - 1; i >= 0; i--) {
            n = (int)bytes[i] & 0xFF;
            chars[i*2]   = HEX_CHARS[n/16];
            chars[i*2+1] = HEX_CHARS[n%16];
        }
        return new String(chars);
    }

    static protected byte[] convertToBytes(CallContext context, String hex_string) {
        int size = hex_string.length() / 2;
        byte[] bytes = new byte[size];
        hex_string = hex_string.toUpperCase();
        for (int i=0, j=0; i < size; i+=2, j++) {
            char c1 = hex_string.charAt(i);
            char c2 = hex_string.charAt(i+1);
            char c = (char) ((c1 - (c1 > 64 ? 55 : 48)) * 16 + (c2 - (c2 > 64 ? 55 : 48)));
            bytes[j] = (byte) c;
        }
        return bytes;
    }

    static public byte[] createSalt(CallContext context) {
        SecureRandom random = null;
        String algorithm = "SHA1PRNG";
        try {
            random = SecureRandom.getInstance(algorithm);
        } catch (NoSuchAlgorithmException nsae) {
            CustomaryContext.create(Context.create(context)).throwConfigurationError(context, "SecureRandom algorithm '%(algorithm)' not available", "algorithm", algorithm);
            throw (ExceptionConfigurationError) null; // compiler insists
        }
        byte[] salt = new byte[SALTSIZE];
        random.nextBytes(salt);
        return salt;
    }
}
