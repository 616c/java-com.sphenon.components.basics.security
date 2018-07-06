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

public class RoleBaseImpl implements Role {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.RoleBaseImpl"); };

    protected String              name;
    protected String              encrypted_password;
    protected boolean             need_to_change_password;
    protected boolean             is_valid;
    protected Permissions         permissions;
    protected UserManager         user_manager;

    /**
     * Tries to create a role instance. If parameters are invalid, the role instance
     * will be invalid, too. This condition should be checked before the role instance
     * is used.
     * @param name                role name
     * @param user_manager        is used to delegate password changes to, and to inform
     *                            about modification of the security database
     */
    public RoleBaseImpl (CallContext context, String name, Permissions permissions, UserManager user_manager) {
        if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Creating role data object..."); }

        this.user_manager = user_manager;
        this.name         = name;

        if (this.name == null) {
            if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendWarning(context, "Invalid role, name is null"); }
            this.permissions             = null;
            this.is_valid                = false;
        } else {
            this.permissions = permissions;
            if (this.permissions == null) {
                if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendWarning(context, "Invalid role, permissions invalid"); }
                this.is_valid = false;
            } else {
                this.is_valid = true;
                if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Role data object created."); }
            }
        }
    }

    public String getName(CallContext context) {
        return this.name;
    }

    public Permissions getPermissions (CallContext context) {
        return this.permissions;
    }

    public boolean isValid (CallContext context) {
        return this.is_valid;
    }
}
