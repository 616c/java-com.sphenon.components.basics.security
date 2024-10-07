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
import com.sphenon.basics.encryption.*;

import com.sphenon.basics.security.returncodes.*;

import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Vector;
import java.util.StringTokenizer;
import java.util.NoSuchElementException;
import java.util.regex.*;

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

// syntax: see .security.properties

abstract public class PermissionsBaseImpl implements Permissions {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.PermissionsBaseImpl"); };

    protected Set<String>                    permission_set;
    protected Vector<Pattern>                permission_patterns;
    protected Map<String,Map<String,String>> vault;
    protected Map<String,Map<String,String>> security_properties;
    protected Vector<Permissions>            base_permissions;
    protected Vector<Permission>             permission_definitions;
    protected UserManager                    user_manager;

    protected PermissionsBaseImpl (CallContext call_context, Set<String> permission_set, Vector<Pattern> permission_patterns, Map<String,Map<String,String>> vault, Map<String,Map<String,String>> security_properties, Vector<Permissions> base_permissions, Vector<Permission> permission_definitions, UserManager user_manager) {
        this.permission_set         = permission_set;
        this.permission_patterns    = permission_patterns;
        this.vault                  = vault;
        this.security_properties    = security_properties;
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
        grantAccess(context, lock.getResourceId(context), lock.getSecurityClass(context), access_type);
        if (getVault(context) == null) {
            AccessDenied.createAndThrow(context);
            throw (AccessDenied) null; // compiler insists
        }
        String encrypted_password = getVaultEntry(context, lock.getResourceId(context), lock.getSecurityClass(context), lock.getLockId(context), true);
        if (encrypted_password == null) {
            AccessDenied.createAndThrow(context);
            throw (AccessDenied) null; // compiler insists
        }
        int pos = encrypted_password.indexOf('|');
        String sc = "ServerRuntime";
        if (pos != -1) {
            sc = encrypted_password.substring(pos + 1);
            encrypted_password = encrypted_password.substring(0, pos);
            if (sc.isEmpty()) { sc = null; }
        }
        
        String dp = (sc == null ? null : this.getDecryptionPassword(context, sc));
        String pw = null;
        try {
            pw = (  sc == null ?
                    (   this.decryption_key != null ?
                          EncryptionUtilities.get(context).decrypt(context, encrypted_password, this.decryption_key)
                        : null
                    )
                  : (   dp != null ?
                          EncryptionUtilities.get(context).decrypt(context, encrypted_password, dp)
                        : EncryptionUtilities.get(context).decryptForSecurityClass(context, encrypted_password, sc)
                    )
                );
        } catch (Throwable t) {
            // might happen in decryptForSecurityClass if runtime password not found
            AccessDenied.createAndThrow(context);
            throw (AccessDenied) null; // compiler insists
        }
        lock.unlock(context, new Key_Password(context, pw));
    }

    public String getVaultEntry (CallContext context, String resource_id, String entry_id) {
        return getVaultEntry(context, resource_id, null, entry_id, false);
    }

    public String getVaultEntry (CallContext context, String resource_id, String security_class, String entry_id) {
        return getVaultEntry(context, resource_id, security_class, entry_id, false);
    }

    protected String getVaultEntry (CallContext context, String resource_id, String entry_id, boolean also_protected_entries) {
        return getVaultEntry(context, resource_id, null, entry_id, also_protected_entries);
    }

    protected String getVaultEntry (CallContext context, String resource_id, String security_class, String entry_id, boolean also_protected_entries) {
        if ((resource_id == null && security_class == null) || entry_id == null) {
            return null;
        }

        Map<String,Map<String,String>> vault = null;
        Map<String,String> vault_entries = null;
        String entry_data = null;
        if (    (vault = this.getVault(context)) != null
             && (    also_protected_entries == true
                  || entry_id.matches("^!.*!$")
                     // only entry ids of the form '!...!' are accepted,
                     // to explicitly mark them as 'directly retrievable'
                )
             && (    (resource_id != null && (vault_entries = vault.get("#" + resource_id)) != null)
                  || (security_class != null && (vault_entries = vault.get(security_class)) != null)
                )
             && (entry_data = vault_entries.get(entry_id)) != null
           ) {
            return entry_data;
        }

        for (Permissions permissions : this.base_permissions) {
            if ((entry_data = ((PermissionsBaseImpl) permissions).getVaultEntry(context, resource_id, entry_id, also_protected_entries)) != null) {
                return entry_data;
            }
        }

        return null;
    }

    public String getSecurityProperty(CallContext context, String security_class, String property_name, String default_value) {
        if (security_class == null || property_name == null) {
            return null;
        }

        Map<String,Map<String,String>> security_properties = null;
        Map<String,String> security_class_properties = null;
        String property_value = null;
        if (    (security_properties = this.getSecurityProperties(context)) != null
             && (security_class_properties = security_properties.get(security_class)) != null
             && (property_value = security_class_properties.get(property_name)) != null
           ) {
            return property_value;
        }

        for (Permissions permissions : this.base_permissions) {
            if ((property_value = permissions.getSecurityProperty(context, security_class, property_name, (String) null)) != null) {
                return property_value;
            }
        }

        return default_value;
    }

    // ---------------------------------------------------------------------------------------------
    // allow per user storage of (EncryptionUtilities) security class specific decryption passwords
    protected String decryption_key;

    public void setDecryptionKey(CallContext context, String decryption_key) {
        this.decryption_key = decryption_key;
    }

    protected String getDecryptionPassword(CallContext context, String security_class) {
        if (    security_class == null
             || this.decryption_key == null
             || this.getVault(context) == null) {
            return null;
        }
        Map<String,String> vault_entries = getVault(context).get("#User");
        if (vault_entries == null) {
            return null;
        }
        String entry_data = vault_entries.get("Password-" + security_class);
        if (entry_data == null) {
            return null;
        }
        String password = EncryptionUtilities.decrypt(context, entry_data, this.decryption_key);
        return password;
    }

    // ---------------------------------------------------------------------------------------------

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

        // [ToDo:OwnedObjects - UserOwned.model,Unit_Owner.model,PermissionsBaseImpl.java]
        for (String coi : class_or_id.split(",",-1)) {
            if (coi.isEmpty() == false) {
                String permission = (coi + "|" + access_type_name);

                if (this.getPermissionSet(context).contains(permission)) { return true; }

                if (this.getPermissionPatterns(context) != null) {
                    for (Pattern p : this.getPermissionPatterns(context)) {
                        Matcher m = p.matcher(permission);
                        if (m.matches()) { return true; }
                    }
                }
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

    public Vector<Permissions> getBasePermissions(CallContext context) {
        return this.base_permissions;
    }

    public Vector<Permission> getPermissionDefinitions(CallContext context) {
        return getPermissionDefinitions(context, false);
    }

    public Vector<Permission> getPermissionDefinitions(CallContext context, boolean deep) {
        if (deep == false) {
            return this.permission_definitions;
        } else {
            Vector all_definitions = new Vector();
            appendDefinitions(context, this, all_definitions);
            return all_definitions;
        }
    }

    protected void appendDefinitions(CallContext context, Permissions ps, Vector<Permission> all_permissions) {
        all_permissions.addAll(ps.getPermissionDefinitions(context));
        if (ps.getBasePermissions(context) != null) {
            for (Permissions bps : ps.getBasePermissions(context)) {
                this.appendDefinitions(context, bps, all_permissions);
            }
        }
    }

    protected Map<String,Map<String,String>> getVault(CallContext context) {
        return this.vault;
    }

    protected Map<String,Map<String,String>> getSecurityProperties(CallContext context) {
        return this.security_properties;
    }

    public long getLastModification(CallContext context) {
        return this.user_manager.getLastModificationOfSecurityDatabase(context);
    }
}

