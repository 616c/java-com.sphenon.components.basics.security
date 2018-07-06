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

import com.sphenon.basics.security.returncodes.*;

import java.io.*;

public class UserManagerPasswordShadowFile extends UserManagerPasswordFile {
    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.UserManagerPasswordFile"); };
    static protected Configuration config;
    static { config = Configuration.create(RootContext.getInitialisationContext(), "com.sphenon.basics.security.UserManagerPasswordFile"); };

    protected File shadow_file = null;
    protected long last_modification_of_security_database;
    protected long last_modification_of_shadow_database;

    public UserManagerPasswordShadowFile (CallContext context) {
        super(context);
    }

    public UserManagerPasswordShadowFile (CallContext context, File password_file) {
        super(context, password_file);
    }

    public UserManagerPasswordShadowFile (CallContext context, File password_file, File shadow_file) {
        super(context);
        this.setPasswordFile(context, password_file,shadow_file);
    }


    protected void setPasswordFile(CallContext context, File password_file, File shadow_file) {
        super.setPasswordFile(context, password_file);
        this.shadow_file = shadow_file;
        this.last_modification_of_shadow_database   = -1;
    }
    
    protected void setPasswordFile(CallContext context, File password_file) {
        super.setPasswordFile(context, password_file);
        this.shadow_file = new File(password_file_name + ".shadow");
        this.last_modification_of_shadow_database   = -1;
    }


    public long getLastModificationOfSecurityDatabase(CallContext context) {
        this.checkPasswordFile(context);
        return this.last_modification_of_security_database > this.last_modification_of_shadow_database ? last_modification_of_security_database : this.last_modification_of_shadow_database;
    }

    protected void initialisePasswordFile(CallContext context) {
        super.initialisePasswordFile(context);
        if (this.password_file != null && this.password_file.exists()) {
            this.shadow_file = new File(password_file_name + ".shadow");
        } else {
            this.shadow_file                            = null;
            this.last_modification_of_shadow_database   = -1;
        }
    }
    
    protected synchronized void checkPasswordFile(CallContext context) {
        super.checkPasswordFile(context);
        try {
            if (this.shadow_file.exists() && this.shadow_file.lastModified() > this.last_modification_of_shadow_database) {
                if ((this.notification_level & Notifier.DIAGNOSTICS) != 0) {
                    CustomaryContext.create((Context) context).sendTrace(context, Notifier.DIAGNOSTICS, "Reading shadow file '%(file)' ...", "file",
                                                                         this.shadow_file.getAbsoluteFile());
                }
                BufferedReader pwbr = new BufferedReader(new InputStreamReader(new FileInputStream(this.shadow_file), "UTF-8"));
                String line;
                while ((line = pwbr.readLine()) != null) {
                    int sep = line.indexOf('=');
                    if (line.length() > 0 && line.charAt(0) != '#' && sep != -1) {
                        String pwname = line.substring(0, sep);
                        String pwvalue = line.substring(sep + 1, line.length());
                        if ((this.notification_level & Notifier.DIAGNOSTICS) != 0) {
                            CustomaryContext.create((Context) context).sendTrace(context, Notifier.DIAGNOSTICS, "Entry: '%(name)' = '%(value)'", "name", pwname, "value", pwvalue);
                        }
                        String user_key = "User." + pwname;
                        String current_value = entries.get(user_key);
                        if (current_value != null) {
                            int pos = current_value.indexOf(':');
                            current_value = current_value.substring(pos+1);
                            pos = current_value.indexOf(':');
                            current_value = current_value.substring(pos);
                            current_value = pwvalue + ":" + current_value;
                            entries.put(user_key, current_value);
                        }
                    }
                }
            }
            this.last_modification_of_shadow_database = this.password_file.lastModified();
        } catch (FileNotFoundException fnfe) {
            this.password_file_name = null;
            this.password_file = null;
            this.last_modification_of_security_database = -1;
            this.entries = null;
            CustomaryContext.create((Context) context).throwImpossibleState(context, fnfe, "File not found");
            throw (ExceptionImpossibleState) null;
        } catch (UnsupportedEncodingException uee) {
            this.password_file_name = null;
            this.password_file = null;
            this.last_modification_of_security_database = -1;
            this.entries = null;
            CustomaryContext.create((Context) context).throwLimitation(context, uee, "Unexpected limitation: UTF-8 not supported?");
            throw (ExceptionLimitation) null;
        } catch (IOException ioe) {
            this.password_file_name = null;
            this.password_file = null;
            this.last_modification_of_security_database = -1;
            this.entries = null;
            CustomaryContext.create((Context) context).throwEnvironmentFailure(context, ioe, "Could not read shadow file");
            throw (ExceptionEnvironmentFailure) null;
        }
    }
    
    public synchronized void updateUserPassword(CallContext context, String username, String encrypted_new_password) throws InvalidNewPassword {
        super.updateUserPassword(context, username, encrypted_new_password);

        this.checkPasswordFile(context);
        String user_key = "User." + username;
        if ((this.notification_level & Notifier.DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.DIAGNOSTICS, "Writing password file '%(file)', modifying password for user '%(user)' ...", "file", this.password_file_name, "user", username); }
        try {
            PrintWriter    pwshadow  =  new PrintWriter(new OutputStreamWriter(new FileOutputStream(shadow_file), "UTF-8"));
            for (java.util.Map.Entry<String, String> me : entries.entrySet()) {
                String temp_username    = me.getKey();
                String temp_permissions = me.getValue();
                if (temp_username.startsWith("User.")) {
                    String shadow_user = temp_username.substring(5);
                    if (temp_username.equals(user_key)) {
                        if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Shadow entry '%(user)' modified...", "user", temp_username); }
                        pwshadow.println(shadow_user + "=" + encrypted_new_password);
                    } else {
                        if ((this.notification_level & Notifier.SELF_DIAGNOSTICS) != 0) { CustomaryContext.create((Context)context).sendTrace(context, Notifier.SELF_DIAGNOSTICS, "Shadow entry '%(user)' kept...", "user", temp_username); }
                        int pos = temp_permissions.indexOf(':');
                        if (pos > 0) {
                            String password = temp_permissions.substring(0,pos);
                            pwshadow.println(shadow_user + "=" + password);
                        }
                    }
                }
            }
            pwshadow.close();
        } catch (FileNotFoundException fnfe) {
            CustomaryContext.create((Context)context).throwImpossibleState(context, fnfe, "File exists, but does not exist - hm...");
            throw (ExceptionImpossibleState) null; // inane, but compiler insists
        } catch (UnsupportedEncodingException uee) {
            CustomaryContext.create((Context)context).throwLimitation(context, uee, "Unexpected limitation: UTF-8 not supported?");
            throw (ExceptionLimitation) null; // inane, but compiler insists
        } catch (IOException ioe) {
                CustomaryContext.create((Context)context).throwEnvironmentFailure(context, ioe, "Could not write to shadow password file");
                throw (ExceptionEnvironmentFailure) null; // inane, but compiler insists
        }
    }
}
