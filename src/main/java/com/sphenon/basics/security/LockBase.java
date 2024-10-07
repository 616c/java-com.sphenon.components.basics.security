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
import com.sphenon.basics.notification.*;
import com.sphenon.basics.configuration.*;
import com.sphenon.basics.customary.*;
import com.sphenon.basics.exception.*;
import com.sphenon.basics.customary.*;

import java.net.*;
import java.io.*;

abstract public class LockBase implements Lock {
    protected String resource_id;
    protected String lock_id;
    protected String security_class;

    public LockBase (CallContext context, String security_class, String resource_id, String lock_id) {
        this.security_class = security_class;
        this.resource_id    = resource_id;
        this.lock_id        = lock_id;
    }

    public String getSecurityClass (CallContext context) {
        return this.security_class;
    }

    public String getResourceId (CallContext context) {
        return this.resource_id;
    }

    public String getLockId (CallContext context) {
        return this.lock_id;
    }
 }
