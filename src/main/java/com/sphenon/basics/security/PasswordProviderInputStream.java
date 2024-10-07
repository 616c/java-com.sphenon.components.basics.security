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
import com.sphenon.basics.system.*;

import static com.sphenon.basics.system.StringUtilities.nonNull;

import com.sphenon.basics.security.returncodes.*;

import java.io.OutputStream;
import java.io.PrintWriter;

public class PasswordProviderInputStream extends OnDemandByteArrayInputStream {

    protected Lock   lock;
    protected Key    key;

    protected OutputStream password_stream;

    public PasswordProviderInputStream (CallContext context, String security_class, String resource_id, String lock_id) {
        super(context);
        this.lock = new LockBase(context, security_class, resource_id, lock_id) {
                            public void unlock (CallContext context, Key key) { PasswordProviderInputStream.this.key = key; }
                        };
    }
     
    protected byte[] getData(CallContext context) {
        SecurityContext sc = SecurityContext.get((Context) context);
        if (sc == null) {
            CustomaryContext.create((Context)context).throwSecurityViolation(context, "No security context provided for password stream provider");
            throw (ExceptionSecurityViolation) null; // compiler insists
        }
        Authority a = sc.getAuthority(context);
        if (a == null) {
            CustomaryContext.create((Context)context).throwSecurityViolation(context, "No authority found  in security context for password stream provider");
            throw (ExceptionSecurityViolation) null; // compiler insists
        }
        try {
            a.grantAccess(context, this.lock, AccessType.UNLOCK);
        } catch (AccessDenied ad) {
            CustomaryContext.create((Context)context).throwSecurityViolation(context, ad, "Could not get credentials for password stream provider (vault might be locked) ");
            throw (ExceptionSecurityViolation) null; // compiler insists
        }
        return ((Key_Password) this.key).getPassword(context).getBytes();
    }
}
