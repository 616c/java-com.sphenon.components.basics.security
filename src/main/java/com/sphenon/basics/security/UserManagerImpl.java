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

abstract public class UserManagerImpl extends UserManagerBaseImpl {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.UserManagerImpl"); };
    
    static protected Configuration config;
    static { config = Configuration.create(RootContext.getInitialisationContext(), "com.sphenon.basics.security.UserManagerImpl"); };

    /**
     * Default constructor
     */
    public UserManagerImpl (CallContext context) {
        super(context);
    }

    protected enum EntryType { USER, ROLE };

    protected User retrieveUser(CallContext context, String name) {
        if (name == null) {
            return null;
        }
        String permission_string = this.getPermissionString(context, name, EntryType.USER);
        if (permission_string == null) {
            return null;
        }
        return UserImpl.create(context, name, permission_string, this);
    }

    protected Role retrieveRole(CallContext context, String name) {
        if (name == null) {
            return null;
        }
        String permission_string = this.getPermissionString(context, name, EntryType.ROLE);
        if (permission_string == null) {
            return null;
        }
        return new RoleImpl(context, name, permission_string, this);
    }

    abstract protected String getPermissionString(CallContext context, String user_or_role_name, EntryType entry_type);
}
