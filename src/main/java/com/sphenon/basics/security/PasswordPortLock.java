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
import com.sphenon.basics.notification.*;
import com.sphenon.basics.configuration.*;
import com.sphenon.basics.customary.*;
import com.sphenon.basics.exception.*;
import com.sphenon.basics.customary.*;

import java.net.*;
import java.io.*;

public class PasswordPortLock implements Lock {

    static protected long notification_level;
    static public    long adjustNotificationLevel(long new_level) { long old_level = notification_level; notification_level = new_level; return old_level; }
    static public    long getNotificationLevel() { return notification_level; }
    static { notification_level = NotificationLocationContext.getLevel(RootContext.getInitialisationContext(), "com.sphenon.basics.security.PasswordPortLock"); };
    static protected Configuration config;
    static { config = Configuration.create(RootContext.getInitialisationContext(), "com.sphenon.basics.security.PasswordPortLock"); };

    protected String id;
    protected String security_class;
    protected ServerSocket password_server = null;

    protected PasswordPortLock (CallContext context, String id, String security_class) {
        this.id = id;
        this.security_class = security_class;
	try {
            this.password_server = new ServerSocket(0);
	} catch (IOException ioe) {
            CustomaryContext.create(Context.create(context)).throwEnvironmentFailure(context, ioe, "Creation of server socket (port zero) for password port lock failed");
            throw (ExceptionEnvironmentFailure) null; // compiler insists
	}
    }
    
    static public PasswordPortLock create (CallContext context, String id, String security_class) {
        return new PasswordPortLock(context, id, security_class);
    }

    public void unlock (CallContext context, Key key) {
        Key_Password kp = (Key_Password) key;
        
	Socket client_socket = null;
        int timeout = config.get(context, "Timeout", 60000);
    	try {
            password_server.setSoTimeout(timeout);
            client_socket = password_server.accept();
        } catch (InterruptedIOException iioe) {
            if ((this.notification_level & Notifier.MONITORING) != 0) { CustomaryContext.create(Context.create(context)).sendCaution(context, "Client process did not ask for password within %(timeout) msec - password port lock timed out - %(reason)", "timeout", t.o(timeout), "reason", iioe); }
	} catch (IOException ioe) {
            CustomaryContext.create(Context.create(context)).throwEnvironmentFailure(context, ioe, "Accept call on server socket for password port lock failed");
            throw (ExceptionEnvironmentFailure) null; // compiler insists
	}

    	try {
            PrintWriter out = new PrintWriter(client_socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(client_socket.getInputStream()));

            String inputLine;
            if ((inputLine = in.readLine()) != null) {	
                out.println(kp.getPassword(context) + "\n");
            }

            out.close();
            in.close();
            client_socket.close();
            password_server.close();
	} catch (IOException ioe) {
            CustomaryContext.create(Context.create(context)).throwEnvironmentFailure(context, ioe, "Accept call on server socket for password port lock failed");
            throw (ExceptionEnvironmentFailure) null; // compiler insists
	}
    }

    public int getPort (CallContext context) {
        return this.password_server.getLocalPort();
    }

     public String getId (CallContext context) {
        return this.id;
    }

    public String getSecurityClass (CallContext context) {
        return this.security_class;
    }

 }
