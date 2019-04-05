/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.shreqb64;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.util.LinkedHashMap;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

public class JSONRequestValidation extends ValidationCore {
    
    JSONObjectReader message;  // "message" in the specification
    
    public JSONRequestValidation(String targetUri,
                                 String targetMethod,
                                 LinkedHashMap<String, String> headerMap,
                                 String jwsString) throws IOException, GeneralSecurityException {
        super(targetUri, targetMethod, headerMap);
        decodeJwsString(jwsString, false);
        this.message = JSONParser.parse(JWS_Payload);
    }

    @Override
    protected void validateImplementation() throws IOException, 
                                                   GeneralSecurityException {
        JSONObjectReader temp = message.getObject(SHREQSupport.SHREQ_SECINF_LABEL);
        secinf = commonDataFilter(temp, false);

        String normalizedURI = secinf.getString(SHREQSupport.SHREQ_TARGET_URI);
        if (!normalizedURI.equals(normalizedTargetUri)) {
            error("Declared URI=" + normalizedURI + " Actual URI=" + normalizedTargetUri);
        }
    }

    @Override
    protected String defaultMethod() {
        return SHREQSupport.SHREQ_DEFAULT_JSON_METHOD;
    }
}
