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
import com.sphenon.basics.exception.*;
import com.sphenon.basics.customary.*;

public class SecurityContext extends SpecificContext {

    static public SecurityContext getOrCreate(Context context) {
        SecurityContext security_context = (SecurityContext) context.getSpecificContext(SecurityContext.class);
        if (security_context == null) {
            security_context = new SecurityContext(context);
            context.setSpecificContext(SecurityContext.class, security_context);
        }
        return security_context;
    }

    static public SecurityContext get(Context context) {
        return (SecurityContext) context.getSpecificContext(SecurityContext.class);
    }

    static public SecurityContext create(Context context) {
        SecurityContext security_context = new SecurityContext(context);
        context.setSpecificContext(SecurityContext.class, security_context);
        return security_context;
    }

    protected SecurityContext (Context context) {
        super(context);
        this.authority = null;
    }

    protected Authority authority;

    public void setAuthority(CallContext context, Authority authority) {
        this.authority = authority;
    }

    public Authority getAuthority(CallContext cc) {
        SecurityContext security_context;
        return (this.authority != null ?
                     this.authority
                  : (security_context = (SecurityContext) this.getCallContext(SecurityContext.class)) != null ?
                       security_context.getAuthority(cc)
                     : getDefaultAuthority(cc)
               );
    }

    protected Authority getDefaultAuthority(CallContext context) {
        /*
          IMPLEMENTATION NOTE:
          
          This is a migration hack!
          
          The mechanism used here to retrieve the authority is from the very early
          days of the Sphenon Components. The authority was bound explicitly to a
          session, and this coupling was not hidden carefully enough.
          
          The correct solution ist: in the ApplicationManager, on session
          creation, the security context is instantiated within the session
          context and a respective authority is registered.
          
          Currently the applications register their authority within the
          sessiondata.
          
          This change will affect all not yet migrated applications.
        */
        return SecuritySessionData.get(context).getAuthority(context);
    }
}
