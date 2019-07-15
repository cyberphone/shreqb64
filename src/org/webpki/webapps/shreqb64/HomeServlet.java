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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
            "<div class=\"header\">SHREQ/B64 - Signed HTTP Requests</div>" +
            "<div style=\"padding-top:15pt\">This site permits testing and debugging systems utilizing a " +
            "scheme for signing HTTP requests tentatively targeted for " +
            "IETF standardization (here in a &quot;tweaked&quot; version using JWS+B64).  For detailed technical information and " +
            "open source code, click on the SHREQ logotype.</div>" +
            "<div style=\"display:flex;justify-content:center\"><table>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='create'\" " +
            "title=\"Create Signed Request\">" +
            "Create Signed Request" +
            "</div></td></tr>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='validate'\" " +
            "title=\"Validate Signed Request\">" +
            "Validate Signed Request" +
            "</div></td></tr>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='curl'\" " +
            "title=\"Online Testing with CURL/Browser\">" +
            "Online Testing with CURL/Browser" +
            "</div></td></tr>" +
            "</table></div>" +
            "<div class=\"sitefooter\">Privacy/security notice: No user provided data is " +
            "ever stored or logged on the server; it only processes the data and returns the " +
            "result.</div>"));
    }
}
