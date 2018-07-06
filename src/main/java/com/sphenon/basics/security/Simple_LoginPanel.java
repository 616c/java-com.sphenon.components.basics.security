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

import com.sphenon.basics.context.CallContext;
import com.sphenon.basics.context.Context;
import com.sphenon.basics.context.classes.RootContext;
import com.sphenon.basics.customary.CustomaryContext;
import com.sphenon.basics.event.ChangeEvent;
import com.sphenon.basics.event.classes.Class_Changing;
import com.sphenon.basics.notification.NotificationLocationContext;
import com.sphenon.basics.notification.Notifier;
import com.sphenon.basics.security.returncodes.AccessDenied;
import com.sphenon.basics.security.returncodes.InvalidNewPassword;
import com.sphenon.basics.security.returncodes.PasswordChangeRequired;
import com.sphenon.basics.validation.returncodes.ValidationFailure;

public class Simple_LoginPanel extends Class_Changing implements LoginPanelUsernamePassword {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.Simple_LoginPanel"); };

    protected AuthorityUsernamePasswordImpl authority;
    protected String username;
    protected String password;
    protected String new_password;

    protected boolean login_failed;
    protected boolean need_new_password;
    protected boolean invalid_new_password;

    public Simple_LoginPanel (CallContext context, AuthorityUsernamePasswordImpl authority) {
        if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create(Context.create(context)).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "LoginPanel: created ('%(this)')", "this", this); }
        this.authority = authority;
        this.username = authority.getUsername(context);
        this.password = "";
        this.new_password = "";
        if (this.authority != null) {
            this.authority.getChangeEventDispatcher(context).addListener(context, this.getChangeEventDispatcher(context));
        }
    }

    public String getUsername (CallContext context) {
        return this.username;
    }

    public String getPassword (CallContext context) {
        return "";
    }

    public String getNewPassword (CallContext context) {
        return "";
    }

    public void setUsername (CallContext context, String username) {
        if (this.username != null && ! this.username.equals(username)) {
            this.need_new_password = false;
        }
        this.username = username;
        this.login_failed         = false;
        this.invalid_new_password = false;
    }

    public void setPassword (CallContext context, String password) {
        this.password = password;
        this.login_failed      = false;
    }

    public void setNewPassword (CallContext context, String new_password) {
        this.new_password = new_password;
    }

    public void validatePassword (CallContext context) throws ValidationFailure {
        if (this.login_failed) {
            String message = SecurityStringPoolRetriever.retrieve(context).getString(context, "0.0.0");
            ValidationFailure failure = ValidationFailure.createValidationFailure(context, message);    
            throw failure;
        }
    }

    public void validateUsername (CallContext context) throws ValidationFailure {
        if (false) {
            throw (ValidationFailure) null;
        }
    }

    public void validateNewPassword (CallContext context) throws ValidationFailure {
        if (this.invalid_new_password) {
            String message = SecurityStringPoolRetriever.retrieve(context).getString(context, "0.0.1");
            ValidationFailure failure = ValidationFailure.createValidationFailure(context, message);    
            throw failure;
        }
    }

    public boolean isLoggedIn (CallContext call_context) {
        return this.authority.isLoggedIn(call_context);
    }

    public boolean mayChangePassword (CallContext call_context) {
        return this.authority.mayChangePassword(call_context);
    }

    public boolean mustChangePassword (CallContext call_context) {
        return this.need_new_password;
    }

    public void login (CallContext context) {
        if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create(Context.create(context)).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "LoginPanel: login, user '%(user)', panel ('%(this)')", "user", this.username, "this", this); }
        try {
            this.authority.login(context, this.username, this.password);
            this.login_failed         = false;
            this.need_new_password    = false;
            this.invalid_new_password = false;
        } catch (AccessDenied ad) {
            this.login_failed         = true;
            this.need_new_password    = false;
            this.invalid_new_password = false;
        } catch (PasswordChangeRequired pcr) {
            this.login_failed         = false;
            this.need_new_password    = true;
            if (pcr.getCause() != null && pcr.getCause() instanceof InvalidNewPassword) {
                this.invalid_new_password = true;
            } else {
                this.invalid_new_password = false;
            }
        } catch (InvalidNewPassword inp) {
            this.login_failed         = false;
            this.need_new_password    = false;
            this.invalid_new_password = true;
        }
        this.password = "";
        this.new_password = "";
    }

    public void logout (CallContext context) {
        this.authority.logout(context);
        this.password = "";
        this.new_password = "";
    }

    public void changePassword (CallContext context) {
        if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create(Context.create(context)).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "LoginPanel: change password, user '%(user)', panel ('%(this)')", "user", this.username, "this", this); }
        try {
            this.authority.changePassword(context, this.username, this.password, this.new_password);
            this.login_failed      = false;
            this.need_new_password = false;
            this.invalid_new_password = false;
        } catch (AccessDenied ad) {
            this.login_failed      = true;
            this.need_new_password = false;
            this.invalid_new_password = false;
        } catch (PasswordChangeRequired pcr) {
            this.login_failed      = false;
            this.need_new_password = true;
            if (pcr.getCause() != null && pcr.getCause() instanceof InvalidNewPassword) {
                this.invalid_new_password = true;
            } else {
                this.invalid_new_password = false;
            }
        } catch (InvalidNewPassword inp) {
            this.login_failed         = false;
            this.need_new_password    = false;
            this.invalid_new_password = true;
        }
        this.password = "";
        this.new_password = "";
    }

    public void validate(CallContext context) throws ValidationFailure{ 
    }
}
