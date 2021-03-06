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
package org.wso2.carbon.identity.application.authenticator.qrcode;

/**
 * Constants used by the QRAuthenticator
 */
public abstract class QRAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "qrcode";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "QRCodeBased";
    public static final String USER_NAME = "username";
    public static final String QR_PAGE = "/authenticationendpoint/qrpage.jsp";
    public static final String PROCEED_AUTH = "proceedAuthorization";
    public static final String QR_CODE_CLAIM_URL = "http://wso2.org/claims/identity/qrcodeurl";
}
