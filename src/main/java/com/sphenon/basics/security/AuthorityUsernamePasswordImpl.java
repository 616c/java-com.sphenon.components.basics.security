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
import com.sphenon.basics.event.*;
import com.sphenon.basics.event.classes.*;

import com.sphenon.basics.security.returncodes.*;
import com.sphenon.basics.actor.*;
import com.sphenon.basics.actor.classes.*;
import com.sphenon.basics.session.*;

import java.util.Vector;

abstract public class AuthorityUsernamePasswordImpl extends Class_Changing implements Authority {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.AuthorityUsernamePasswordImpl"); };

    static protected Configuration config;
    static { config = Configuration.create(RootContext.getInitialisationContext(), "com.sphenon.basics.security.AuthorityUsernamePasswordImpl"); };

    protected boolean     logged_in;
    protected User        user = null;
    protected long        last_modification;
    protected UserManager user_manager;

    public AuthorityUsernamePasswordImpl (CallContext context, UserManager user_manager) {
        this.last_modification = -1;
        this.user_manager = user_manager;
    }

    public String getUsername(CallContext context) {
        return (this.user == null ? null : this.user.getName(context));
    }

    // note: this method is intentionally protected - the user
    // MUST only be changed by means of the login-method - this
    // method here is used internally to ensure notification
    // of the SessionContext

    protected void setUser(CallContext context, User new_user) {
        this.user = new_user;
        Actor new_actor = createActor(context);
        if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create(Context.create(context)).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Changing actor to '%(newactor)'", "newactor", new_actor); }
        Session.get((Context) context).setActor(context, new_actor);
    }

    protected Actor createActor(CallContext context) {
        return new Class_Actor(context, this.getUsername(context));
    }

    public String getUnambiguousSecurityIdentifier(CallContext context) {
        return (this.user == null ? "-" : ("U" + this.user.getName(context)));
    }

    public LoginPanel getLoginPanel (CallContext context) {
        return new Simple_LoginPanel (context, this);
    }

    public boolean isLoggedIn (CallContext call_context) {
        return this.logged_in;
    }

    public boolean mayChangePassword (CallContext context) {
        return this.user != null && this.user.getPermissions(context) != null && this.user.getPermissions(context).isAccessGranted(context, "Password", null, AccessType.MODIFY);
    }

    public void changePassword (CallContext context, String username, String password, String new_password) throws PasswordChangeRequired, AccessDenied, InvalidNewPassword {
        this.login(context, username, password, new_password);
    }

    public long getLastModificationOfAuthorisation(CallContext context) {
        long perm_mod = this.getPermissions(context).getLastModification(context);
        return perm_mod > this.last_modification ? perm_mod : this.last_modification;
    }

    public long getLastModification(CallContext context) {
        return this.getLastModificationOfAuthorisation(context);
    }

    public long getLastModificationOfUserPermissions(CallContext context) {
        return this.getPermissions(context).getLastModification(context);
    }

    public void login(CallContext context, String try_username, String try_password) throws PasswordChangeRequired, AccessDenied, InvalidNewPassword {
        login(context, try_username, try_password, null);
    }

    protected void login(CallContext context, String try_username, String try_password, String new_password) throws PasswordChangeRequired, AccessDenied, InvalidNewPassword {
        try {
            if (try_username == null || try_password == null) {
                AccessDenied.createAndThrow(context, "");
            }
            User try_user = this.user_manager.getUser(context, try_username);

            if (try_user == null) {
                AccessDenied.createAndThrow(context, "");
            }

            try_user.confirmPassword(context, try_password, new_password);

            this.logged_in = true;
            if ((this.notification_level & Notifier.OBSERVATION) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.OBSERVATION, "User '%(user)' logged in (%(authority))", "user", try_username, "authority", this); }
            this.setUser(context, try_user);
            this.getChangeEventDispatcher(context).notify(context, new SecurityEvent(context, this, true));
        } catch (AccessDenied ad) {
            this.logged_in = false;
            if ((this.notification_level & Notifier.OBSERVATION) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.OBSERVATION, "User '%(user)' login failed", "user", try_username); }
            this.setUser(context, null);
            this.getChangeEventDispatcher(context).notify(context, new ChangeEvent(context, this));
            throw ad;
        } catch (PasswordChangeRequired pcd) {
            this.logged_in = false;
            if ((this.notification_level & Notifier.OBSERVATION) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.OBSERVATION, "User '%(user)' login deferred", "user", try_username); }
            this.setUser(context, null);
            this.getChangeEventDispatcher(context).notify(context, new ChangeEvent(context, this));
            throw pcd;
        } catch (InvalidNewPassword inp) {
            this.logged_in = false;
            if ((this.notification_level & Notifier.OBSERVATION) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.OBSERVATION, "User '%(user)' login deferred", "user", try_username); }
            this.setUser(context, null);
            this.getChangeEventDispatcher(context).notify(context, new ChangeEvent(context, this));
            throw inp;
        } finally {
            this.last_modification = new java.util.Date().getTime();
        }
    }

    public void logout(CallContext context) {
        if ((this.notification_level & Notifier.OBSERVATION) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.OBSERVATION, "User '%(user)' logged out (%(authority))", "user", this.getUsername(context), "authority", this); }
        this.logged_in = false;
        this.last_modification = new java.util.Date().getTime();
        this.setUser(context, null);
        this.getChangeEventDispatcher(context).notify(context, new SecurityEvent(context, this, false));
    }

    public void reloadUser(CallContext context) {
        String user_name = this.user == null ? "" : this.user.getName(context);
        User fresh_user = this.user_manager.getUser(context, user_name, false);
        if (fresh_user != this.user) {
            // fresh_user.confirmPassword(context, confirmed_password_TO_BE_STORED, null);
            this.setUser(context, fresh_user);
            this.getChangeEventDispatcher(context).notify(context, new SecurityEvent(context, this, true));
        }
    }

    protected Permissions getPermissions(CallContext context) {
        return (this.user == null ? this.user_manager.getAnonymousUser(context) : this.user).getPermissions(context);
    }

    public void grantAccess (CallContext context, Lock lock, int access_type) throws AccessDenied {
        this.getPermissions(context).grantAccess(context, lock, access_type);
    }

    public void grantAccess (CallContext context, String resource_id, String security_class, int access_type) throws AccessDenied {
        this.getPermissions(context).grantAccess(context, resource_id, security_class, access_type);
    }

    public boolean isAccessGranted (CallContext context, String resource_id, String security_class, int access_type) {
        return this.getPermissions(context).isAccessGranted(context, resource_id, security_class, access_type);
    }

    public Vector<Permission> getPermissionDefinitions(CallContext context) {
        return this.getPermissions(context).getPermissionDefinitions(context);
    }
}
