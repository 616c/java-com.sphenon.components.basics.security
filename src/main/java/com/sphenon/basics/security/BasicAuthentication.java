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
import com.sphenon.basics.message.*;
import com.sphenon.basics.notification.*;
import com.sphenon.basics.exception.*;
import com.sphenon.basics.customary.*;
import com.sphenon.basics.encoding.*;
import com.sphenon.basics.expression.*;

import static com.sphenon.basics.system.StringUtilities.nonNull;

import com.sphenon.basics.security.returncodes.*;

// [Issue: replace direct access in Mailer.java with Authority based access - Mailer.java,BasicAuthentication.java]

public class BasicAuthentication {

    static protected RegularExpression password_lock_re = new RegularExpression("password-lock:([^:]+):(?:(?:([^#].*))|(?:(?:#(.+))))");

    static protected class Base64Credentials extends LockBase {
        protected String username;
        protected String credentials;

        public Base64Credentials (CallContext context, String security_class, String resource_id, String lock_id, String username, String password) {
            super(context, security_class, resource_id, lock_id);
            this.username       = username;
            if (password != null) {
                this.unlock(context, new Key_Password(context, password));
            }
        }
        public void unlock (CallContext context, Key key) {
            this.credentials = Encoding.recode(context, nonNull(this.username) + ":" + nonNull(((Key_Password) key).getPassword(context)), Encoding.UTF8, Encoding.BASE64);
        }
        public String getEncodedCredentials(CallContext context) { return this.credentials; }
    }

    static public String getBase64Credentials(CallContext context, String username, String password) {
        String[] plm = password_lock_re.tryGetMatches(context, password);
        Base64Credentials b64c = null;
        if (plm == null) {
            b64c = new Base64Credentials(context, null, null, null, username, password);
        } else {
            b64c = new Base64Credentials(context, plm[1], plm[2], plm[0], username, null);
            SecurityContext sc = SecurityContext.get((Context) context);
            if (sc == null) {
                CustomaryContext.create((Context)context).throwSecurityViolation(context, "No security context provided for basic authentication");
                throw (ExceptionSecurityViolation) null; // compiler insists
            }
            Authority a = sc.getAuthority(context);
            if (a == null) {
                CustomaryContext.create((Context)context).throwSecurityViolation(context, "No authority found  in security context for basic authentication");
                throw (ExceptionSecurityViolation) null; // compiler insists
            }
            try {
                a.grantAccess(context, b64c, AccessType.UNLOCK);
            } catch (AccessDenied ad) {
                CustomaryContext.create((Context)context).throwSecurityViolation(context, ad, "Could not get credentials for basic authentication (vault might be locked) ");
                throw (ExceptionSecurityViolation) null; // compiler insists
            }
        }
        return b64c.getEncodedCredentials(context);
    }
}
