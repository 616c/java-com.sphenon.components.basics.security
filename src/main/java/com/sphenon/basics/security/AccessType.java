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
import com.sphenon.basics.notification.*;
import com.sphenon.basics.customary.*;

public class AccessType {
    public final static int DISCOVER = 1;
    public final static int READ     = 2;
    public final static int CREATE   = 3;
    public final static int MODIFY   = 4;
    public final static int EXECUTE  = 5;
    public final static int DELETE   = 6;
    public final static int UNLOCK   = 7;

    public final static String [] names = {
        "",
        "DISCOVER",
        "READ",
        "CREATE",
        "MODIFY",
        "EXECUTE",
        "DELETE",
        "UNLOCK"
    };

    static protected java.util.Hashtable name_hash = null;

    static public int getByName(CallContext context, String name) {
        if (name_hash == null) {
            java.util.Hashtable nh = new java.util.Hashtable();
            for (int i=1; i<8; i++) {
                nh.put(names[i], new Integer(i));
            }
            name_hash = nh;
        }
        Object o = name_hash.get(name);
        if (o == null) {
            CustomaryContext.create(Context.create(context)).throwPreConditionViolation(context, "Invalid access type '%(accesstype)', must be one of DISCOVER, READ, CREATE, MODIFY, EXECUTE, DELETE, UNLOCK", "accesstype", name);
            throw (ExceptionPreConditionViolation) null; // compiler insists
        }
        return ((Integer) o).intValue();
    }
}
