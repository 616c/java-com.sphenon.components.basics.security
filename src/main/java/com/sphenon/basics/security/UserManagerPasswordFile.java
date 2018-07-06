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

import java.io.File;

public class UserManagerPasswordFile extends UserManagerImpl {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.UserManagerPasswordFile"); };
    
    static protected Configuration config;
    static { config = Configuration.create(RootContext.getInitialisationContext(), "com.sphenon.basics.security.UserManagerPasswordFile"); };

    /**
     * Default constructor
     */
    public UserManagerPasswordFile (CallContext context) {
        super(context);
    }

    /**
     * Erstellung mit einer Kennwortdatei
     * @param context
     * @param password_file
     */
    public UserManagerPasswordFile (CallContext context, File password_file) {
      super(context);
      this.setPasswordFile(context, password_file);
    }

    protected void setPasswordFile(CallContext context, File password_file)
    {
      this.password_file_initialised              = false;
      this.password_file                          = password_file;
      this.password_file_name                     = password_file.getAbsolutePath();       
      this.last_modification_of_security_database = -1;
      this.entries                                = null;
    }

    protected long last_modification_of_security_database;

    public long getLastModificationOfSecurityDatabase(CallContext context) {
        this.checkPasswordFile(context);
    	return this.last_modification_of_security_database;
    }

    protected java.io.File        password_file=null;
    protected String              password_file_name;
    protected long                last_check = 0;
    protected java.util.Hashtable<String, String> entries;

    protected String getPermissionString(CallContext context, String user_or_role_name, EntryType entry_type) {
        this.checkPasswordFile(context);
        String permissions = null;
        String key = (user_or_role_name == null || user_or_role_name.length() == 0 ? "Default" : ((entry_type == EntryType.USER ? "User" : "Role") + "." + user_or_role_name));
        if (this.entries != null) {
            permissions = (String) entries.get(key);
        } else {
            String prop_id = "Permissions." + key;
            permissions = config.get(context, prop_id, (String) null);
        }
        if (permissions == null) {
            if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create(Context.create(context)).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "No security properties for '%(id)'", "id", key); }
        }
        return permissions;
    }

    protected boolean password_file_initialised = false;
    protected void initialisePasswordFile(CallContext context) {
        if (this.password_file_initialised == false) {
            this.password_file_initialised = true;
          
            File pf =null;
            if (this.password_file != null) {
                pf = this.password_file;
            } else {
                String pfn = config.get(context, "PasswordFile", (String) null);
                if (pfn != null) {
                    pf = new File(pfn);
                }
            }
            if (pf != null && !pf.exists() ) {
                if ((notification_level & Notifier.MONITORING) != 0) { NotificationContext.sendCaution(context, "Password file '%(file)' does not exist", "file", pf.getPath()); }
            }
            if (pf != null && pf.exists()) {
                this.password_file_name = pf.getAbsolutePath();
                this.password_file      = pf;
            } else {
                this.password_file_name                     = null;
                this.password_file                          = null;
                this.last_modification_of_security_database = -1;
                this.entries                                = null;
            }
        }
    }
    
    protected synchronized void checkPasswordFile (CallContext context) {
        initialisePasswordFile(context);

        if (    this.password_file != null
             && (    this.entries == null
                  || this.password_file.lastModified() > this.last_modification_of_security_database
                )
           ) {
           
            if ((this.notification_level & Notifier.DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.DIAGNOSTICS, "Reading password file '%(file)' ...", "file", this.password_file_name); }
            try {
                java.io.BufferedReader pwbr =  new java.io.BufferedReader(new java.io.InputStreamReader(new java.io.FileInputStream(this.password_file), "UTF-8"));
                String line;

                this.entries = new java.util.Hashtable();

                while ((line = pwbr.readLine()) != null) {
                    int sep = line.indexOf('=');
                    if (line.length() > 0 && line.charAt(0) != '#' && sep != -1) {
                        String pwname = line.substring(0, sep);
                        String pwvalue = line.substring(sep+1, line.length());
                        if ((this.notification_level & Notifier.DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.DIAGNOSTICS, "Entry: '%(name)' = '%(value)'", "name", pwname, "value", pwvalue); }
                        this.entries.put(pwname, pwvalue);
                    }
                }

                pwbr.close();

                this.last_modification_of_security_database = this.password_file.lastModified();
            } catch (java.io.FileNotFoundException fnfe) {
                this.password_file_name                     = null;
                this.password_file                          = null;
                this.last_modification_of_security_database = -1;
                this.entries                                = null;
                CustomaryContext.create((Context)context).throwImpossibleState(context, fnfe, "File exists, but does not exist - hm...");
                throw (ExceptionImpossibleState) null; // compiler insists
            } catch (java.io.UnsupportedEncodingException uee) {
                this.password_file_name                     = null;
                this.password_file                          = null;
                this.last_modification_of_security_database = -1;
                this.entries                                = null;
                CustomaryContext.create((Context)context).throwLimitation(context, uee, "Unexpected limitation: UTF-8 not supported?");
                throw (ExceptionLimitation) null; // compiler insists
            } catch (java.io.IOException ioe) {
                this.password_file_name                     = null;
                this.password_file                          = null;
                this.last_modification_of_security_database = -1;
                this.entries                                = null;
                CustomaryContext.create((Context)context).throwEnvironmentFailure(context, ioe, "Could not read password file");
                throw (ExceptionEnvironmentFailure) null; // compiler insists
            }
        }
    }

    public synchronized void updateUserPassword(CallContext context, String username, String encrypted_new_password) throws InvalidNewPassword {
        this.checkPasswordFile(context);
        String user_key = "User." + username;
        if (this.password_file_name == null || this.password_file == null || this.entries == null) {
            CustomaryContext.create((Context)context).throwConfigurationError(context, "Cannot change password, password database is not modifyable");
            throw (ExceptionConfigurationError) null; // compiler insists
        }
       
        if ((this.notification_level & Notifier.DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.DIAGNOSTICS, "Writing password file '%(file)', modifying password for user '%(user)' ...", "file", this.password_file_name, "user", username); }
        try {
            java.io.PrintWriter    pwpw      =  new java.io.PrintWriter(new java.io.OutputStreamWriter(new java.io.FileOutputStream(password_file), "UTF-8"));
            for (java.util.Map.Entry<String, String> me : entries.entrySet()) {
                String temp_username    = (String) me.getKey();
                String temp_permissions = (String) me.getValue();
                if (temp_username.equals(user_key)) {
                    String new_user_data = user_key + "=" + encrypted_new_password + "::" + temp_permissions.replaceFirst("^[^:]*:[^:]*:","");
                    if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Modifying entry: from '%(old)' to '%(new)'...", "old", temp_username + "=" + temp_permissions, "new", new_user_data); }
                    pwpw.println(new_user_data);
                } else {
                    if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Entry '%(user)' kept...", "user", temp_username); }
                    pwpw.println(temp_username + "=" + temp_permissions);
                }
            }
            pwpw.close();

        } catch (java.io.FileNotFoundException fnfe) {
            CustomaryContext.create((Context)context).throwImpossibleState(context, fnfe, "File exists, but does not exist - hm...");
            throw (ExceptionImpossibleState) null; // compiler insists
        } catch (java.io.UnsupportedEncodingException uee) {
            CustomaryContext.create((Context)context).throwLimitation(context, uee, "Unexpected limitation: UTF-8 not supported?");
            throw (ExceptionLimitation) null; // compiler insists
        } catch (java.io.IOException ioe) {
                CustomaryContext.create((Context)context).throwEnvironmentFailure(context, ioe, "Could not write to password file");
                throw (ExceptionEnvironmentFailure) null; // compiler insists
        }
    }
}
