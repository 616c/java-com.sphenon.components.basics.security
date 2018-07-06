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
import com.sphenon.basics.metadata.*;
import com.sphenon.basics.exception.*;
import com.sphenon.basics.notification.*;
import com.sphenon.basics.customary.*;
import com.sphenon.basics.session.*;

public class SecuritySessionData implements SessionData {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.SecuritySessionData"); };

    public SecuritySessionData(CallContext call_context) {
    }

    public static SecuritySessionData get(CallContext context) {
        CustomaryContext cc = (((notification_level & Notifier.DIAGNOSTICS) != 0) ? CustomaryContext.create((Context) context) : null);
        Session s = Session.get((Context) context);
        synchronized (s) {
            SecuritySessionData ssd = (SecuritySessionData) s.getSessionData(context, TypeManager.get(context, SecuritySessionData.class));
    
            if (ssd == null) {
                ssd = new SecuritySessionData(context);
                s.setSessionData(context, ssd);
                if ((notification_level & Notifier.DIAGNOSTICS) != 0) { cc.sendTrace(context, Notifier.DIAGNOSTICS, "Created SecuritySessionData '%(securitysessiondata)' for session '%(session)'", "securitysessiondata", ssd, "session", s); }
            }

            return ssd;
        }
    }

    public void notifyClientSessionBegin (CallContext context, int client_sessions) {
    }

    public void notifyClientSessionEnd (CallContext context, int client_sessions) {
    }

    // Session Attributes

    protected Authority authority = null;

    public synchronized Authority getAuthority (CallContext context) {
        if (this.authority == null) {
            this.authority = new Simple_Authority(context);
        }
        return this.authority;
    }

    public void setAuthority (CallContext context, Authority authority) {
        this.authority = authority;
    }

    public void setAuthorityCheckFirstTime (CallContext context, Authority authority) {
        if (this.authority != null) {
            this.authority = null;
            CustomaryContext.create((Context)context).throwPreConditionViolation(context, "Could not assign new authority - one is already registered");
            throw (ExceptionPreConditionViolation) null; // compiler insists
        }
        this.authority = authority;
    }
}


