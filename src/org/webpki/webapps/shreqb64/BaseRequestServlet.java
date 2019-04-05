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
package org.webpki.webapps.shreqb64;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.text.SimpleDateFormat;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.TimeZone;

import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.jose.JOSEAsymSignatureValidator;
import org.webpki.jose.JOSEHmacValidator;
import org.webpki.jose.JOSESupport;

import org.webpki.shreqb64.JSONRequestValidation;
import org.webpki.shreqb64.URIRequestValidation;
import org.webpki.shreqb64.ValidationCore;
import org.webpki.shreqb64.ValidationKeyService;

import org.webpki.util.DebugFormatter;

import org.webpki.webutil.ServletUtil;

public abstract class BaseRequestServlet extends HttpServlet implements ValidationKeyService {

    private static final long serialVersionUID = 1L;
    
    private static final String CONTENT_TYPE   = "Content-Type";
    private static final String CONTENT_LENGTH = "Content-Length";
    
    private static final String JWS_CONTENT    = "application/jws";

    static final String EXTCONFREQ             = "/extconfreq";
    static final String PRECONFREQ             = "/preconfreq";
    static final String EXTCONFREQ2            = "/extconfreq2";
    static final String PRECONFREQ2            = "/preconfreq2";
    
    static final int TIME_STAMP_TOLERANCE      = 300000;  // Milliseconds
  
    static Logger logger = Logger.getLogger(BaseRequestServlet.class.getName());
    
    protected abstract boolean externallyConfigured(); 
    
    static String getFormattedUTCTime(GregorianCalendar dateTime) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd' 'HH:mm:ss 'UTC'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(dateTime.getTime());
    }
    static String getStackTrace(Exception e) {
        StringBuffer error = new StringBuffer("Stack trace:\n")
            .append(e.getClass().getName())
            .append(": ")
            .append(e.getMessage());
        StackTraceElement[] st = e.getStackTrace();
        int length = st.length;
        if (length > 20) {
            length = 20;
        }
        for (int i = 0; i < length; i++) {
            String entry = st[i].toString();
            error.append("\n  at " + entry);
            if (entry.contains("HttpServlet")) {
                break;
            }
        }
        return error.toString();
    }
    
    static String getUrlFromRequest(HttpServletRequest request) {
        return request.getScheme() +
                "://" +
                request.getServerName() +
                ":" +
                request.getServerPort() +
                request.getRequestURI() +
               (request.getQueryString() == null ? 
                                              "" : "?" + request.getQueryString());
    }
    
    protected boolean enforceTimeStamp() {
        return false;
    }
    
    private void returnResponse(HttpServletResponse response, int status, String text) throws IOException {
        response.resetBuffer();
        response.setStatus(status);
        response.getOutputStream().write(text.getBytes("utf-8"));;
        response.setHeader(CONTENT_TYPE, "text/plain;utf-8");       
        response.flushBuffer();
    }
    
    @Override
    public void service(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        ValidationCore validationCore = null;

        // Get the Target Method (4.2:1 , 5.2:1)
        String targetMethod = request.getMethod();
        
        // Recreate the Target URI (4.2:2 , 5.2:2)
        String targetUri = getUrlFromRequest(request);

        // Collect HTTP Headers
        @SuppressWarnings("unchecked")
        Enumeration<String> headerNames = request.getHeaderNames();
        
        try {
            LinkedHashMap<String, String> headerMap = new LinkedHashMap<String, String>();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement().toLowerCase();
                @SuppressWarnings("unchecked")
                Enumeration<String> headerValues = request.getHeaders(headerName);
                boolean next = false;
                do {
                    String headerValue = headerValues.nextElement().trim();
                    if (next) {
                        headerMap.put(headerName, headerMap.get(headerName) + ", " + headerValue);
                    } else {
                        headerMap.put(headerName, headerValue);
                        next = true;
                    }
                } while (headerValues.hasMoreElements());
            }

            // 3. Determining Request Type
            if (request.getHeader(CONTENT_LENGTH) == null) {

                // 5.2 URI Request
                if (request.getHeader(CONTENT_TYPE) != null) {
                    throw new IOException("Unexpected: " + CONTENT_TYPE);
                }
                validationCore = new URIRequestValidation(targetUri,
                                                          targetMethod, 
                                                          headerMap);
            } else {

                // 4.2 JSON Request
                if (!JWS_CONTENT.equals(request.getHeader(CONTENT_TYPE))) {
                    throw new IOException(CONTENT_TYPE +
                                          "=" +
                                          request.getHeader(CONTENT_TYPE) +
                                          " must be=" +
                                          JWS_CONTENT);
                }
                validationCore = new JSONRequestValidation(targetUri,
                                                           targetMethod,
                                                           headerMap,
                                                           new String(ServletUtil.getData(request), "utf-8"));
            }
            
            // Core Request Data Successfully Collected - Validate!
            validationCore.validate(this);

            // In *this* service we don't accept any unread/unused JWS header variables
            validationCore.getJwsProtectedHeader().checkForUnread();
            
            // Optional test
            if (enforceTimeStamp()) {
                validationCore.enforceTimeStamp(TIME_STAMP_TOLERANCE, TIME_STAMP_TOLERANCE);
            }

            // No exceptions => We did it!
            returnResponse(response, HttpServletResponse.SC_OK,
                    "\n" +
                    "       |============================================|\n" +
                    "       | SUCCESSFUL REQUEST " +
                            getFormattedUTCTime(new GregorianCalendar()) + " |\n" +
                    "       |============================================|\n" +
                    validationCore.printCoreData());


        } catch (Exception e) {

            // Houston, we got a problem...
            returnResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "\n" +
                    "                       *************\n" +
                    "                       * E R R O R *\n" +
                    "                       *************\n" +
                    getStackTrace(e) + (validationCore == null ? 
                            "\nValidation context not available\n" : validationCore.printCoreData()));
        }
    }

    void extConfError() throws IOException {
        throw new IOException("'" + 
                              EXTCONFREQ +
                              "' only supports requests with in-lined asymmetric JWKs and X5Cs");
    }

    @Override
    public JOSESupport.CoreSignatureValidator getSignatureValidator(ValidationCore validationCore,
                                                                    SignatureAlgorithms signatureAlgorithm,
                                                                    PublicKey publicKey, 
                                                                    String keyId)
    throws IOException, GeneralSecurityException {
        if (signatureAlgorithm.isSymmetric()) {
            if (externallyConfigured()) {
                extConfError();
            }
            byte[] secretKey = SHREQService.predefinedSecretKeys
                    .get(signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE));
            validationCore.setCookie(DebugFormatter.getHexString(secretKey));
            return new JOSEHmacValidator(secretKey,
                                         (MACAlgorithms) signatureAlgorithm);
        }
        PublicKey validationKey;
        if (externallyConfigured()) {
            if (publicKey == null) {
                extConfError();
            }
            validationKey = publicKey;
        } else {
            // Lookup predefined validation key
            validationKey = SHREQService.predefinedKeyPairs
        .get(signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE)).getPublic();
            if (publicKey != null && !publicKey.equals(validationKey)) {
                throw new GeneralSecurityException("In-lined public key differs from predefined public key");
            }
            if (validationCore.getCertificatePath() != null) {
                SHREQService.certificateVerifier
                    .verifyCertificatePath(validationCore.getCertificatePath());
            }
        }
        validationCore.setCookie(BaseGuiServlet.getPEMFromPublicKey(validationKey));
        return new JOSEAsymSignatureValidator(validationKey, 
                                              (AsymSignatureAlgorithms)signatureAlgorithm);
    }
}
