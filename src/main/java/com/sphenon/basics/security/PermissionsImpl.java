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
import com.sphenon.basics.encoding.*;

import com.sphenon.basics.security.returncodes.*;

import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Vector;
import java.util.StringTokenizer;
import java.util.NoSuchElementException;
import java.util.regex.*;

public class PermissionsImpl extends PermissionsBaseImpl {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.PermissionsImpl"); };

    protected String                         permission_string;

    static protected RegularExpression splitre  = new RegularExpression("([^:]*)(:|$)");
    static protected RegularExpression keyvalre = new RegularExpression("^[ \t]*(#?[^ \t:=]+)[ \t]*=[ \t]*([A-Za-z0-9_,]+)[ \t]*$");
    static protected RegularExpression plainkey = new RegularExpression("^[A-Za-z0-9_]+$");
    static protected RegularExpression rolere   = new RegularExpression("^([A-Za-z0-9_]+)$");

    static public PermissionsImpl create (CallContext context, String permission_string, UserManager user_manager) {
        Set<String>               try_permissions        = new HashSet<String>();
        Vector<Pattern>           try_permission_patterns= null;
        Vector<Permissions>       try_base_permissions   = new Vector<Permissions>();
        Vector<Permission>        permission_definitions = new Vector<Permission>();
        Map<String,SecurityClass> security_classes_by_id = new HashMap<String,SecurityClass>();

        Matcher m2 = splitre.getMatcher(context, permission_string);

        while (m2.find()) {
            String token = m2.group(1);
            if (token != null && token.length() > 0) {
                Matcher m3 = keyvalre.getMatcher(context, token);
                if (! m3.find()) {
                    Matcher m4 = rolere.getMatcher(context, token);
                    if (! m4.find()) {
                        if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendCaution(context, "Rejecting user object - invalid security property '%(entry)', part '%(part)' - expected 'Password:[INITIAL]:[SecurityClass=[AccessType,...]:...][Role:...]'", "entry", permission_string, "part", token); }
                        return null;
                    } else {
                        String role_name = m4.group(1).trim();
                        Role role = user_manager.getRole(context, role_name);
                        if (role == null) {
                            if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendCaution(context, "Rejecting user object - invalid security property '%(entry)', part '%(part)' - role does not exist or is not valid", "entry", permission_string, "part", token); }
                            return null;
                        }
                        try_base_permissions.add(role.getPermissions(context));
                    }
                } else {
                    String security_class = Encoding.recode(context, m3.group(1).trim(), Encoding.URI, Encoding.UTF8);
                    SecurityClass sc = security_classes_by_id.get(security_class);
                    if (sc == null) {
                        security_classes_by_id.put(security_class, sc = new SecurityClassImpl(context, security_class));
                    }
                    Vector<String> access_types = new Vector<String>();
                    StringTokenizer t3 = new StringTokenizer(m3.group(2), ",");
                    while (t3.hasMoreTokens()) {
                        String access_type = t3.nextToken().trim();
                        if (plainkey.matches(context, security_class)) {
                            String perm = security_class + "|" + access_type;
                            try_permissions.add(perm);
                            access_types.add(access_type);
                            if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Added permission '%(permission)'", "permission", perm); }
                        } else {
                            if (try_permission_patterns == null) {
                                try_permission_patterns = new Vector<Pattern>();
                            }
                            String perm = security_class + "\\|" + access_type;
                            try {
                                try_permission_patterns.add(Pattern.compile(perm));
                                if ((notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Added permission pattern '%(permission)'", "permission", perm); }
                                access_types.add(access_type);
                            } catch(PatternSyntaxException pse) {
                                if ((notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create((Context)context).sendCaution(context, "Rejecting user object - invalid security property '%(entry)', part '%(part)' - pattern does not compile properly: '%(reason)'", "entry", permission_string, "part", token, "reason", pse); }
                                return null;
                            }
                        }
                    }
                    permission_definitions.add(new PermissionImpl(context, sc, access_types));
                }
            }
            String g2 = m2.group(2);
            if (g2 == null || ! g2.equals(":")) {
                break;
            }
        }
        return new PermissionsImpl (context, try_permissions, try_permission_patterns, try_base_permissions, permission_definitions, permission_string, security_classes_by_id, user_manager);
    }

    protected Map<String,SecurityClass> security_classes_by_id;

    protected SecurityClass getSecurityClassById(CallContext context, String id) {
        if (id == null) { return null; }
        return this.security_classes_by_id.get(id);
    }

    protected PermissionsImpl (CallContext context, Set<String> permission_set, Vector<Pattern> permission_patterns, Vector<Permissions> base_permissions, Vector<Permission> permission_definitions, String permission_string, Map<String,SecurityClass> security_classes_by_id, UserManager user_manager) {
        super(context, permission_set, permission_patterns, base_permissions, permission_definitions, user_manager);
        this.permission_string = permission_string;
        this.security_classes_by_id = security_classes_by_id;
    }

    protected String getPermissionString(CallContext context) {
        return this.permission_string;
    }
}

