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

abstract public class UserManagerBaseImpl implements UserManager {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.UserManagerBaseImpl"); };
    
    /**
     * Default constructor
     */
    public UserManagerBaseImpl (CallContext context) {
    }

    /**
     * Retrieve a user by name from the security database. If no user
     * is found, or the found user entry is invalid, no user is returned.
     * @param   name  specifies user entry to retrieve
     * @returns       a user instance, if found and valid, or null otherwise
     */
    public User getUser(CallContext context, String name, boolean use_cache) {
        User try_user = use_cache ? this.getCachedUser(context, name) : null;
        if (try_user == null) {
            try_user = this.retrieveUser(context, name);            
            if (try_user == null || try_user.isValid(context) == false) {
                return null;
            }
            this.putCachedUser(context, name, try_user);
        }
        return try_user;
    }

    public User getUser(CallContext context, String name) {
        return getUser(context, name, true);
    }

    abstract protected User retrieveUser(CallContext context, String name);

    /**
     * Retrieve a role by name from the security database. If no role
     * is found, or the found role entry is invalid, no role is returned.
     * @param   name  specifies role entry to retrieve
     * @returns       a role instance, if found and valid, or null otherwise
     */
    public Role getRole(CallContext context, String name) {
        Role try_role = this.getCachedRole(context, name);
        if (try_role == null) {
            try_role = this.retrieveRole(context, name);
            if (try_role == null || try_role.isValid(context) == false) {
                return null;
            }
            this.putCachedRole(context, name, try_role);
        }
        return try_role;
    }

    abstract protected Role retrieveRole(CallContext context, String name);

    /**
     * Retrieve the anonymous user which holds the default permissions
     * if no real user is logged in
     * @returns a user instance, if found and valid, or null otherwise
     */
    public User getAnonymousUser(CallContext context) {
        return this.getUser(context, "");
    }

    /**
     * The last modification of the security database is a simple approach
     * to inform the application whether the current permissions may have
     * changed.
     */
    abstract public long getLastModificationOfSecurityDatabase(CallContext context);

    /**
     * Modifies the password in the security database
     * @param   username                specifies user entry to modify
     * @param   encrypted_new_password  stored in user entry as such
     */
    abstract public void updateUserPassword(CallContext context, String username, String encrypted_new_password) throws InvalidNewPassword;

    // ------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------
    // cache implementation

    protected long cache_reference_time = -1;
    protected java.util.Hashtable<String,User> user_cache;
    protected java.util.Hashtable<String,Role> role_cache;
    protected void checkCache(CallContext context) {
        long last = this.getLastModificationOfSecurityDatabase(context); 
        if (last > this.cache_reference_time) {
            this.user_cache = null;
            this.role_cache = null;
            this.cache_reference_time = last;
        }
    }
    protected User getCachedUser(CallContext context, String name) {
        checkCache(context);
        return this.user_cache == null ? null : this.user_cache.get(name);
    }
    protected void putCachedUser(CallContext context, String name, User user) {
        checkCache(context);
        if (this.user_cache == null) { this.user_cache = new java.util.Hashtable<String,User>(); }
        this.user_cache.put(name, user);
    }
    protected Role getCachedRole(CallContext context, String name) {
        checkCache(context);
        return this.role_cache == null ? null : this.role_cache.get(name);
    }
    protected void putCachedRole(CallContext context, String name, Role role) {
        checkCache(context);
        if (this.role_cache == null) { this.role_cache = new java.util.Hashtable<String,Role>(); }
        this.role_cache.put(name, role);
    }
}
