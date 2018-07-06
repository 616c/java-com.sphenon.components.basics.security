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

public class SecurityClassImpl implements SecurityClass {

    public SecurityClassImpl(CallContext context, String id) {
        this.id = id;
    }

    protected String id;

    public String getId (CallContext context) {
        return this.id;
    }

    public void setId (CallContext context, String id) {
        this.id = id;
    }

    protected SecurityClass base;

    public SecurityClass getBase (CallContext context) {
        return this.base;
    }

    public void setBase (CallContext context, SecurityClass base) {
        this.base = base;
    }
}
