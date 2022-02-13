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

import java.security.cert.X509Certificate;

import java.util.LinkedHashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.jose.JOSEAsymSignatureValidator;
import org.webpki.jose.JOSEHmacValidator;
import org.webpki.jose.JOSESupport;

import org.webpki.shreqb64.JSONRequestValidation;
import org.webpki.shreqb64.URIRequestValidation;
import org.webpki.shreqb64.ValidationCore;
import org.webpki.shreqb64.ValidationKeyService;

import org.webpki.util.HexaDecimal;
import org.webpki.util.PEMDecoder;

public class ValidateServlet extends BaseGuiServlet implements ValidationKeyService {

    private static final long serialVersionUID = 1L;

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }
            // Get the two input data items
            String targetUri = getParameter(request, TARGET_URI);
            String signedJsonObject = getParameter(request, JSON_PAYLOAD);
            boolean jsonRequest = new Boolean(getParameter(request, REQUEST_TYPE));
            LinkedHashMap<String,String> httpHeaderData = createHeaderData(getParameter(request, TXT_OPT_HEADERS));
            String validationKey = getParameter(request, JWS_VALIDATION_KEY);
            String targetMethod = getParameter(request, PRM_HTTP_METHOD);
            ValidationCore validationCore = null;

            // Determining Request Type
            if (jsonRequest) {
                validationCore = new JSONRequestValidation(targetUri,
                                                           targetMethod,
                                                           httpHeaderData,
                                                           signedJsonObject);
            } else {
                validationCore = new URIRequestValidation(targetUri,
                                                          targetMethod, 
                                                          httpHeaderData);
            }

            // Now assign the key
            boolean jwkValidationKey = validationKey.startsWith("{");
            validationCore.setCookie(jwkValidationKey ?
                    JSONParser.parse(validationKey).getCorePublicKey(AlgorithmPreferences.JOSE)
                                                                :
                    validationKey.contains("-----") ?
                 PEMDecoder.getPublicKey(validationKey.getBytes("utf-8")) :
                 HexaDecimal.decode(validationKey));
            
            
            // Core Request Data Successfully Collected - Validate!
            validationCore.validate(this);

            // Parse the JSON data
            
            StringBuilder html = new StringBuilder(
                    "<div class=\"header\">Request Successfully Validated</div>")
                .append(HTML.fancyBox("targeturi", targetUri, 
                    "Target URI to be accessed by an HTTP " + targetMethod + " request"));  
            if (jsonRequest) {
                html.append(HTML.fancyBox("httpjsonbody", signedJsonObject, 
                                      "HTTP Body - Base64Url encoded JSON object signed by a JWS"));
            }
            html.append(HTML.fancyBox("jwsheader", 
                                      validationCore.getJwsProtectedHeader()
                                          .serializeToString(JSONOutputFormats.PRETTY_HTML),
                                      "Decoded JWS header"))
                .append(HTML.fancyBox("vkey",
                                      jwkValidationKey ? 
                                          JSONParser.parse(validationKey)
                                              .serializeToString(JSONOutputFormats.PRETTY_HTML)
                                                       :
                                      HTML.encode(validationKey).replace("\n", "<br>"),
                                      "Signature validation " +
                                      (validationCore.getSignatureAlgorithm().isSymmetric() ? 
                                             "secret key in hexadecimal" :
                                             "public key in " + 
                                             (jwkValidationKey ? "JWK" : "PEM") +
                                             " format")));
            html.append(HTML.fancyBox(
                        "jwspayload", 
                        JSONParser.parse(validationCore.getJwsPayload()).serializeToString(JSONOutputFormats.PRETTY_HTML),
                        "Decoded JWS Payload"));
            if (validationCore.getCertificatePath() != null) {
                StringBuilder certificateData = null;
                for (X509Certificate certificate : validationCore.getCertificatePath()) {
                    if (certificateData == null) {
                        certificateData = new StringBuilder();
                    } else {
                        certificateData.append("<br>&nbsp;<br>");
                    }
                    certificateData.append(
                        HTML.encode(new CertificateInfo(certificate).toString())
                            .replace("\n", "<br>").replace("  ", ""));
                }
                html.append(HTML.fancyBox("certpath", 
                                          certificateData.toString(),
                                          "Core certificate data"));
            }
            String time;
            if (validationCore.getIssuedAt() == null) {
                time = "Request does not contain a time stamp";
            } else {
                time = BaseRequestServlet.getFormattedUTCTime(validationCore.getIssuedAt());
            }
            html.append(HTML.fancyBox(
                    "timestamp", 
                    time,
                    "Time stamp"));
            HTML.standardPage(response, null, html.append("<div style=\"padding:10pt\"></div>"));
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }

    @Override
    public JOSESupport.CoreSignatureValidator getSignatureValidator(ValidationCore validationCore,
                                                                    SignatureAlgorithms signatureAlgorithm,
                                                                    PublicKey publicKey, 
                                                                    String keyId)
    throws IOException, GeneralSecurityException {
        if (signatureAlgorithm.isSymmetric()) {
            return new JOSEHmacValidator((byte[])validationCore.getCookie(),
                                         (MACAlgorithms) signatureAlgorithm);
        }
        PublicKey validationKey = (PublicKey)validationCore.getCookie();
        if (publicKey != null && !publicKey.equals(validationKey)) {
            throw new GeneralSecurityException("In-lined public key differs from predefined public key");
        }
        return new JOSEAsymSignatureValidator(validationKey, 
                                             (AsymSignatureAlgorithms)signatureAlgorithm);
    }


    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        getSampleData(request);
        StringBuilder html = new StringBuilder(
            "<form name=\"shoot\" method=\"POST\" action=\"validate\">" +
            "<div class=\"header\">SHREQ Message Validation</div>")

        .append(
            HTML.fancyText(
                true,
                TARGET_URI,
                1, 
                HTML.encode(sampleJsonRequestUri),
                "Target URI"))

        .append(
            HTML.fancyText(
                true,
                JSON_PAYLOAD,
                10, 
                "",
                "Paste a signed JSON request in the text box or try with the default"))

        .append(
            HTML.fancyText(
                false,
                TXT_OPT_HEADERS,
                4,
                "",
                "Optional HTTP headers, each on a separate line"))

        .append(getRequestParameters())

        .append(
            HTML.fancyText(
                true,
                JWS_VALIDATION_KEY,
                4, 
                HTML.encode(SHREQService.sampleKey),
"Validation key (secret key in hexadecimal or public key in PEM or &quot;plain&quot; JWK format)"))

        .append(
            "<div style=\"display:flex;justify-content:center\">" +
            "<div class=\"stdbtn\" onclick=\"document.forms.shoot.submit()\">" +
            "Validate Signed Request" +
            "</div>" +
            "</div>" +
            "</form>" +
            "<div>&nbsp;</div>");

        StringBuilder js = new StringBuilder("\"use strict\";\n")
        .append(

            "function setUserData(unconditionally) {\n" +
            "  let element = document.getElementById('" + JSON_PAYLOAD + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '")
        .append(sampleJsonRequest_JS)
        .append("';\n" +
            "  element = document.getElementById('" + TARGET_URI + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '")
        .append(sampleJsonRequestUri)
        .append("';\n" +
            "}\n" +
            "function showJson(show) {\n" +
            "  document.getElementById('" + JSON_PAYLOAD + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function setMethod(method) {\n" +
            "  let s = document.getElementById('" + PRM_HTTP_METHOD + "');\n" +
            "  for (let i = 0; i < s.options.length; i++) {\n" +
            "    if (s.options[i].text == method) {\n" +
            "      s.options[i].selected = true;\n" +
            "      break;\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "function showHeaders(show) {\n" +
            "  document.getElementById('" + TXT_OPT_HEADERS + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function restoreRequestDefaults() {\n" +
            "  let radioButtons = document.getElementsByName('" + REQUEST_TYPE + "');\n" +
            "  radioButtons[0].checked = true;\n" +
            "  requestChange(true);\n" +
            "  document.getElementById('" + FLG_HEADERS + "').checked = false;\n" +
            "  showHeaders(false);\n" +
            "  setUserData(true);\n" +
            "}\n" +
            "function requestChange(jsonRequest) {\n" +
            "  document.getElementById('" + JSON_PAYLOAD + "').style.display= jsonRequest ? 'block' : 'none';\n" +
            "  setMethod(jsonRequest ? '" + DEFAULT_JSON_METHOD + "' : '" + DEFAULT_URI_METHOD + "');\n" +
            "  let element = document.getElementById('" + TARGET_URI + "').children[1];\n" +
            "  if (jsonRequest) {\n" +
            "    if (element.value == '" + sampleUriRequestUri + "') {\n" +
            "      element.value = '" + sampleJsonRequestUri + "';\n" +
            "    }\n" +
            "  } else {\n" +
            "    if (element.value == '" + sampleJsonRequestUri + "') {\n" +
            "      element.value = '" + sampleUriRequestUri + "';\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "function headerFlagChange(flag) {\n" +
            "  showHeaders(flag);\n" +
            "}\n" +
            "window.addEventListener('load', function(event) {\n" +
            "  let radioButtons = document.getElementsByName('" + REQUEST_TYPE + "');\n" +
            "  showJson(radioButtons[0].checked);\n" +
            "  showHeaders(document.getElementById('" + FLG_HEADERS + "').checked);\n" +
            "  setUserData(false);\n" +
            "});\n");
        HTML.standardPage(response, js.toString(), html);
    }
}
