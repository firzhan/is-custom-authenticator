/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.soasecurity.wso2.custom.authenticator.local.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.soasecurity.wso2.custom.authenticator.local.BasicCustomAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;


/**
 * @scr.component name="soasecurity.wso2.authenticator.local.basic.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class BasicCustomAuthenticatorServiceComponent500 {

    private static Log log = LogFactory.getLog(BasicCustomAuthenticatorServiceComponent500.class);

    private static RealmService realmService;

    public static RealmService getRealmService() {
        return realmService;
    }

    protected void activate(ComponentContext ctxt) {
        try {
            BasicCustomAuthenticator basicCustomAuth = new BasicCustomAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), basicCustomAuth, null);
            if (log.isDebugEnabled()) {
                log.info("BasicCustomAuthenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("BasicCustomAuthenticator bundle activation Failed", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("BasicCustomAuthenticator bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        BasicCustomAuthenticatorServiceComponent500.realmService = null;
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        BasicCustomAuthenticatorServiceComponent500.realmService = realmService;
    }
}
