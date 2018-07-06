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

import java.util.Vector;

public class PermissionImpl implements Permission {

    public PermissionImpl(CallContext context, SecurityClass security_class, Vector<String> access_types) {
        this.security_class = security_class;
        this.access_types = access_types;
    }

    protected SecurityClass security_class;

    public SecurityClass getSecurityClass (CallContext context) {
        return this.security_class;
    }

    public void setSecurityClass (CallContext context, SecurityClass security_class) {
        this.security_class = security_class;
    }

    protected Vector<String> access_types;

    public Vector<String> getAccessTypes (CallContext context) {
        return this.access_types;
    }

    public void setAccessTypes (CallContext context, Vector<String> access_types) {
        this.access_types = access_types;
    }
}
