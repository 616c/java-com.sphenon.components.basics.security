package com.sphenon.basics.security;

/****************************************************************************
  Copyright 2001-2024 Sphenon GmbH

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
import com.sphenon.basics.system.*;
import com.sphenon.basics.encryption.*;

import com.sphenon.basics.security.returncodes.*;

/* ================================================================================================

 [Related: PermissionsBaseImpl.java
           UserBaseImpl.java
           .security.properties
           /workspace/sphenon/projects/components/basics/security/...  (java files)
           /workspace/ee/software/components/domains/basics/actors/... (model and java files)
           .../company/units/organisation/howto.d/manage_emos_keys.howto
           .../projects/components/ui/frontends/jsp/v0001/origin/source/webapp/WEB-INF/.sirface_auth
 ]

 ================================================================================================== */

abstract public class UserBaseImpl implements User {
    static final public Class _class = UserBaseImpl.class;

    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(_class); };

    static protected Configuration config;
    static {
        CallContext context = RootContext.getInitialisationContext();
        config = Configuration.create(context, _class);
        // security_version = config.get(context, "SecurityVersion", 1);
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

    private final static int    DIGEST_LENGTH_1 = 40;
    private final static int    DIGEST_LENGTH_2 = 128;
    private final static String DUMMY_DIGEST_1  = new String(new char[DIGEST_LENGTH_1]).replace('\0', '0');
    private final static String DUMMY_DIGEST_2  = new String(new char[DIGEST_LENGTH_2]).replace('\0', '0');
    private final static String DUMMY_SALT      = new String(new char[EncryptionUtilities.SALT_SIZE * 2]).replace('\0', '0');
    private final static String DUMMY_STORED_2  = DUMMY_SALT + DUMMY_DIGEST_2;
    private final static int    STORED_LENGTH_1 = DIGEST_LENGTH_1;
    private final static int    STORED_LENGTH_2 = (EncryptionUtilities.SALT_SIZE * 2) + DIGEST_LENGTH_2;

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
            stored_digest = DUMMY_STORED_2; // (security_version >= 2 ? DUMMY_STORED_2 : DUMMY_DIGEST_1);
        }

        byte[] salt = null;

        int security_version = (stored_digest.length() == STORED_LENGTH_2 ? 2 : 1);

        if (security_version >= 2) {
            String stored_salt = stored_digest.substring(0, EncryptionUtilities.SALT_SIZE * 2);
            salt = EncryptionUtilities.convertToBytes(context, stored_salt);
        }

        String digest = this.getDigest(context, cleartext_password, salt, security_version);
        if (    nothing_found
             || cleartext_password == null
             || stored_digest.equalsIgnoreCase(digest) == false
            ) {
            if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Digests do not match, configured '%(configdigest)', calculated from user input '%(inputdigest)'", "configdigest", stored_digest, "inputdigest", digest); }
            AccessDenied.createAndThrow(context, "");
            throw (AccessDenied) null;
        }

        if (new_password != null) {
            String new_digest                = this.getDigest(context, new_password, EncryptionUtilities.createSalt(context), 2);
            String new_digest_for_comparison = security_version == 2
                                                ? new_digest
                                                : this.getDigest(context, new_password, EncryptionUtilities.createSalt(context), security_version);

            if (stored_digest.equalsIgnoreCase(new_digest_for_comparison)) {
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

        // we're fine (i.e. authorised)
        // ---------------------------------------------------------------------------------------------------

        // now trying to set user specific decryption key for this session

        String decryption_key_salt = this.getPermissions(context).getVaultEntry(context, "User", "!DecryptionKeySalt!");
        if (decryption_key_salt != null) {
            byte[] key_salt = EncryptionUtilities.convertToBytes(context, decryption_key_salt);
            String key_digest = this.getDigest(context, cleartext_password, key_salt, 2);
            this.getPermissions(context).setDecryptionKey(context, key_digest);
        }

    }

    public boolean isValid (CallContext context) {
        return this.is_valid;
    }

    static public String getDigest(CallContext context, String password, byte[] salt) {
        return getDigest(context, password, salt, 2);
    }

    static public String getDigest(CallContext context, String password, byte[] salt, int security_version) {
        return EncryptionUtilities.getDigest(context, password, salt, 0, 0, security_version);
    }
}
