/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.application.authenticator.qrcode;

import com.google.zxing.WriterException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authenticator.qrcode.util.QRUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.authenticator.qrcode.internal.QRAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * QR code based custom Authenticator
 */
public class QRAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(QRAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return request.getParameter(QRAuthenticatorConstants.PROCEED_AUTH) != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String sessionDataKey = request.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);

        String retryParam = "";

        if (context.isRetrying()) {
            retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
        }

        redirectQRPage(response, sessionDataKey);

    }

    protected void redirectQRPage(HttpServletResponse response, String sessionDataKey)
            throws AuthenticationFailedException {

        try {
            String qrPage = ServiceURLBuilder.create().addPath(QRAuthenticatorConstants.QR_PAGE)
                    .addParameter("sessionDataKey", sessionDataKey).build().getAbsolutePublicURL();
            QRUtil.generateQRCode(sessionDataKey);
            response.sendRedirect(qrPage);
        } catch (IOException e) {
            String errorMessage = String.format("Error occurred when trying to to redirect user to the login page.");
            throw new AuthenticationFailedException(errorMessage, e);
        } catch (URLBuilderException e) {
            String errorMessage = String.format("Error occurred when building the URL for the login page for user.");
            throw new AuthenticationFailedException(errorMessage, e);
        } catch (WriterException e) {
            e.printStackTrace();
        }
    }

    /**
     * This method is used to process the authentication response.
     * Inside here we check if this is a authentication request coming from oidc flow and then check if the user is
     * in the 'photoSharingRole'.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(QRAuthenticatorConstants.USER_NAME);
        boolean isAuthenticated = true;
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
        boolean authorization = false;

        if(isAuthenticated) {
            if ("oidc".equalsIgnoreCase(context.getRequestType())) {
                // authorization only for openid connect requests
                try {
                    int tenantId = QRAuthenticatorServiceComponent.getRealmService().getTenantManager().
                            getTenantId(MultitenantUtils.getTenantDomain(username));
                    UserStoreManager userStoreManager = (UserStoreManager) QRAuthenticatorServiceComponent.getRealmService().
                            getTenantUserRealm(tenantId).getUserStoreManager();

                    // verify user is assigned to role
                    authorization = ((AbstractUserStoreManager) userStoreManager).isUserInRole(username, "roleName");
                } catch (UserStoreException e) {
                    log.error(e);
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    log.error(e);
                }
            } else {
                // others scenarios are not verified.
                authorization = false;
            }

            if (!authorization) {
                log.error("user authorization is failed.");
            }
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    @Override
    public String getFriendlyName() {
        //Set the name to be displayed in local authenticator drop down lsit
        return QRAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {
        return QRAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}
