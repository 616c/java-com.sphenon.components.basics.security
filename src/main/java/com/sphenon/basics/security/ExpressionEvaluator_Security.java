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
import com.sphenon.basics.exception.*;
import com.sphenon.basics.customary.*;
import com.sphenon.basics.encoding.*;
import com.sphenon.basics.expression.*;
import com.sphenon.basics.expression.classes.*;
import com.sphenon.basics.expression.returncodes.*;
import com.sphenon.basics.operations.*;
import com.sphenon.basics.operations.classes.*;
import com.sphenon.basics.operations.factories.*;
import com.sphenon.basics.data.*;
import com.sphenon.basics.operations.*;
import com.sphenon.basics.encryption.*;

import com.sphenon.basics.security.returncodes.*;

public class ExpressionEvaluator_Security implements ExpressionEvaluator {

    public ExpressionEvaluator_Security (CallContext context) {
        this.result_attribute = new Class_ActivityAttribute(context, "Result", "Object", "-", "*");
        this.activity_interface = new Class_ActivityInterface(context);
        this.activity_interface.addAttribute(context, this.result_attribute);
    }

    protected Class_ActivityInterface activity_interface;
    protected ActivityAttribute result_attribute;

    public String[] getIds(CallContext context) {
        return new String[] { "security" };
    }

    static protected RegularExpression login_command  = new RegularExpression("^ *login +(?:([^ \"'][^ ]*)|(?:\"([^\"]*)\")|(?:'([^']*)')) +(?:([^ \"'][^ ]*)|(?:\"([^\"]*)\")|(?:'([^']*)')) *$");
    static protected RegularExpression logout_command = new RegularExpression("^ *logout *$");
    static protected RegularExpression define_command = new RegularExpression("^ *define +(?:([^ \"'][^ ]*)|(?:\"([^\"]*)\")|(?:'([^']*)')) +(?:([^ \"'][^ ]*)|(?:\"([^\"]*)\")|(?:'([^']*)')) *$");

    public Object evaluate(CallContext context, String instruction, Scope scope, com.sphenon.basics.data.DataSink<Execution> execution_sink) throws EvaluationFailure {
        Execution_Basic e = null;
        if (execution_sink != null) {
            e = (Execution_Basic) Factory_Execution.createExecutionInProgress(context, instruction);
            execution_sink.set(context, e);
        }

        try {
            String result = "";
            String[] matches;
            
            if ((matches = login_command.tryGetMatches(context, instruction)) != null) {
                String username = (   matches[0] != null ? matches[0]
                                    : matches[1] != null ? matches[1]
                                    : matches[2] != null ? matches[2]
                                    : null
                                  );
                String password = (   matches[3] != null ? matches[3]
                                    : matches[4] != null ? matches[4]
                                    : matches[5] != null ? matches[5]
                                    : null
                                  );
                SecurityContext sc = SecurityContext.get((Context) context);
                Authority authority = sc.getAuthority(context);
                if (authority == null) {
                    EvaluationFailure.createAndThrow(context, "No authority available");
                    throw (EvaluationFailure) null;
                }
                if ((authority instanceof AuthorityUsernamePasswordImpl) == false) {
                    EvaluationFailure.createAndThrow(context, "No authority available with login capabilities");
                    throw (EvaluationFailure) null;
                }
                ((AuthorityUsernamePasswordImpl) authority).login(context, username, password);
                result = "logged in";
            } else if ((matches = logout_command.tryGetMatches(context, instruction)) != null) {
                SecurityContext sc = SecurityContext.get((Context) context);
                Authority authority = sc.getAuthority(context);
                if (authority == null) {
                    EvaluationFailure.createAndThrow(context, "No authority available");
                    throw (EvaluationFailure) null;
                }
                if ((authority instanceof AuthorityUsernamePasswordImpl) == false) {
                    EvaluationFailure.createAndThrow(context, "No authority available with login capabilities");
                    throw (EvaluationFailure) null;
                }
                ((AuthorityUsernamePasswordImpl) authority).logout(context);
                result = "logged out";
            } else if ((matches = define_command.tryGetMatches(context, instruction)) != null) {
                String security_class = (   matches[0] != null ? matches[0]
                                          : matches[1] != null ? matches[1]
                                          : matches[2] != null ? matches[2]
                                          : null
                                        );
                String password       = (   matches[3] != null ? matches[3]
                                          : matches[4] != null ? matches[4]
                                          : matches[5] != null ? matches[5]
                                          : null
                                        );
                EncryptionUtilities.get(context).setPassword(context, security_class, password);
                result = "defined";
            } else {
                EvaluationFailure.createAndThrow(context, "No such command: '%(instruction)'", "instruction", instruction);
                throw (EvaluationFailure) null;
            }

            if (e != null) { e.setSuccess(context); }

            return result;
        } catch (Throwable t) {
            if (e != null) { e.setFailure(context, t); }
            EvaluationFailure.createAndThrow(context, t, "Evaluation failure");
            throw (EvaluationFailure) null;
        }
    }

    public ActivityClass parse(CallContext context, ExpressionSource expression_source) throws EvaluationFailure {
        return new ActivityClass_ExpressionEvaluator(context, this, expression_source, this.activity_interface, this.result_attribute);
    }
}
