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

import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Vector;
import java.util.StringTokenizer;
import java.util.NoSuchElementException;
import java.util.regex.*;

abstract public class PermissionsBaseImpl implements Permissions {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.PermissionsBaseImpl"); };

    protected Set<String>               permission_set;
    protected Vector<Pattern>           permission_patterns;
    protected Vector<Permissions>       base_permissions;
    protected Vector<Permission>        permission_definitions;
    protected UserManager               user_manager;

    protected PermissionsBaseImpl (CallContext call_context, Set<String> permission_set, Vector<Pattern> permission_patterns, Vector<Permissions> base_permissions, Vector<Permission> permission_definitions, UserManager user_manager) {
        this.permission_set         = permission_set;
        this.permission_patterns    = permission_patterns;
        this.base_permissions       = base_permissions;
        this.permission_definitions = permission_definitions;
        this.user_manager           = user_manager;
    }

    abstract protected SecurityClass getSecurityClassById(CallContext context, String id);

    public boolean isAccessGranted (CallContext context, String resource_id, String security_class, int access_type) {
        String atn = AccessType.names[access_type];
        SecurityClass sc = getSecurityClassById(context, security_class);
        String rid = (resource_id == null || resource_id.length() == 0 ? null : ("#" + resource_id));
        if (this.isPermitted(context, sc, atn)) {
            if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create(Context.create(context)).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Permission '%(class)'/'%(accesstype)' granted (%(authority))", "class", security_class, "accesstype", atn, "authority", this); }
            return true;
        } else if (this.isPermitted(context, rid, atn)) {
            if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create(Context.create(context)).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Permission '%(id)'/'%(accesstype)' granted (%(authority))", "id", rid, "accesstype", atn, "authority", this); }
            return true;
        } else {
            for (Permissions permissions : this.base_permissions) {
                if (permissions.isAccessGranted (context, resource_id, security_class, access_type)) { return true; }
            }
            if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create(Context.create(context)).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Permission '%(class)'/'%(id)'/'%(accesstype)' denied (%(authority))", "class", security_class, "id", resource_id, "accesstype", atn, "authority", this); }
            return false;
        }
    }

    public void grantAccess (CallContext context, String resource_id, String security_class, int access_type) throws AccessDenied {
        if (! isAccessGranted(context, resource_id, security_class, access_type)) {
            AccessDenied.createAndThrow(context);
            throw (AccessDenied) null; // compiler insists
        }
    }

    public void grantAccess (CallContext context, Lock lock, int access_type) throws AccessDenied {
        grantAccess(context, null, lock.getSecurityClass(context), access_type);

        String password = "xyz"; // somehow retrieve pwd from user data by means of lock.getId(context);
                                 // z.B.: (digest(cleartext_pwd XOR digest(special_admin_pwd)) XOR permission_entry_by_lock_id) --> pwd
        Key_Password kp = new Key_Password(context, password);
        lock.unlock(context, kp);
    }

    protected boolean isPermitted(CallContext context, SecurityClass security_class, String access_type_name) {
        if (security_class == null) {
            return false;
        }
        if (isPermitted(context, security_class.getId(context), access_type_name)) {
            return true;
        }
        SecurityClass base = security_class.getBase(context);
        if (base != null) {
            return isPermitted(context, base, access_type_name);
        }
        return false;
    }

    protected boolean isPermitted(CallContext context, String class_or_id, String access_type_name) {
        if (class_or_id == null) {
            return false;
        }

        String permission = (class_or_id + "|" + access_type_name);

        if (this.getPermissionSet(context).contains(permission)) { return true; }

        if (this.getPermissionPatterns(context) != null) {
            for (Pattern p : this.getPermissionPatterns(context)) {
                Matcher m = p.matcher(permission);
                if (m.matches()) { return true; }
            }
        }

        return false;
    }

    protected Set<String> getPermissionSet(CallContext context) {
        return this.permission_set;
    }

    protected Vector<Pattern> getPermissionPatterns(CallContext context) {
        return this.permission_patterns;
    }

    public Vector<Permission> getPermissionDefinitions(CallContext context) {
        return this.permission_definitions;
    }

    public long getLastModification(CallContext context) {
        return this.user_manager.getLastModificationOfSecurityDatabase(context);
    }
}

