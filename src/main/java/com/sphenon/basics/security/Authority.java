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
import com.sphenon.basics.message.*;
import com.sphenon.basics.notification.*;
import com.sphenon.basics.customary.*;
import com.sphenon.basics.event.*;

import com.sphenon.basics.security.returncodes.*;

import java.util.Vector;

public interface Authority extends Changing {

    public void grantAccess (CallContext context, Lock lock, int access_type) throws AccessDenied;
    public void grantAccess (CallContext context, String resource_id, String security_class, int access_type) throws AccessDenied;
    public boolean isAccessGranted (CallContext context, String resource_id, String security_class, int access_type);
    public LoginPanel getLoginPanel (CallContext context);
    public void reloadUser(CallContext context);

    /**
       @returns list of current permissions, e.g. to be used in sql queries for filtering
     */
    public Vector<Permission> getPermissionDefinitions(CallContext context);

    /**
       @returns last modification of the authorisation, either by means of changing
                login or due to changes in the security database
     */
    public long getLastModificationOfAuthorisation(CallContext context);

    /**
       @deprecated for clarity, use getLastModificationOfAuthorisation instead
     */
    public long getLastModification(CallContext context);

    /**
       @returns last modification of the permissions of the current user, in particular
                that may be an older point in time than the last modification of the
                authorisation in general, by means of login or logout
     */
    public long getLastModificationOfUserPermissions(CallContext context);

    /**
       Returns an idendifier which unambiguously reflects the current security
       settings. It is intended to be used as a cache key to store content
       filtered according to these security settings.
     
       A feasible way of implementation is to return the current user name,
       or, if users share security data via and only via one group, the
       current group name.
     
       @docl:Caution Aspect="Implementation"
      
       Choose this identifier wisely, in other words, not too coarse and not
       too fine:
       - in case the identifier is not unambiguous it is possible that
          cached content is delivered to an unauthorised audience
       - in case the identifier is too specific, i.e. there is a large amount
         of users sharing the same security settings, there is much waste
         in the cache (which may, for example, comprise the whole content of
         a website)
     */
    public String getUnambiguousSecurityIdentifier(CallContext context);
}
