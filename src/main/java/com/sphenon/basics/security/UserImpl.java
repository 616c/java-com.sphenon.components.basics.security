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

import java.util.regex.*;

public class UserImpl extends UserBaseImpl {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.UserImpl"); };

    static protected RegularExpression linere   = new RegularExpression("([^:]*):([^:]*):(.*)");

    static public UserImpl create(CallContext context, String name, String user_data_string, UserManagerImpl user_manager) {
        if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Creating user data object..."); }

        String      encrypted_password = null;
        boolean     need_to_change_password = false;
        Permissions permissions = null;

        Matcher m1 = null;
        if (    user_data_string == null
             || ! (m1 = linere.getMatcher(context, user_data_string)).find()) {

            if (user_data_string == null) {
                if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendWarning(context, "Invalid user, data is null"); }
            } else {
                if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendWarning(context, "Invalid security property '%(entry)' - expected 'Password:[INITIAL]:[SecurityClass=[AccessType,...]:...]'", "entry", user_data_string); }
            }
            name = null;
        } else {
            permissions = PermissionsImpl.create(context, m1.group(3), user_manager);
            if (permissions == null) {
                if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendWarning(context, "Invalid user, permissions invalid"); }
                name = null;
            } else {
                encrypted_password      = m1.group(1);
                need_to_change_password = m1.group(2).equals("INITIAL");

                if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "User data settings valid"); }
            }
        }

        return new UserImpl(context, name, permissions, encrypted_password, need_to_change_password, user_manager);
    }

    protected String              name;
    protected String              encrypted_password;
    protected boolean             need_to_change_password;
    protected Permissions         permissions;
    protected UserManager         user_manager;

    protected UserImpl (CallContext context, String name, Permissions permissions, String encrypted_password, boolean need_to_change_password, UserManagerImpl user_manager) {
        super(context);

        this.name                     = name;
        this.encrypted_password       = encrypted_password;
        this.need_to_change_password  = need_to_change_password;
        this.permissions              = permissions;
        this.user_manager             = user_manager;

        check(context);
    }

    public String getName(CallContext context) {
        return this.name;
    }

    public String getEncryptedPassword (CallContext context) {
        return this.encrypted_password;
    }

    public boolean needToChangePassword (CallContext context) {
        return this.need_to_change_password;
    }

    public Permissions getPermissions (CallContext context) {
        return this.permissions;
    }

    protected void updatePassword(CallContext context, String new_digest) throws InvalidNewPassword {
        ((UserManagerImpl) user_manager).updateUserPassword(context, this.name, new_digest);
        check(context);
    }
}
