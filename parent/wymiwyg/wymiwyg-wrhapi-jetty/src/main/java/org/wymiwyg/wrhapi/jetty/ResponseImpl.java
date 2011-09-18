/*
 * Copyright  2002-2006 WYMIWYG (http://wymiwyg.org)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.wymiwyg.wrhapi.jetty;

import java.util.Iterator;
import java.util.Map;

import java.util.logging.Logger;
import javax.servlet.http.HttpServletResponse;

import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.MessageBody;
import org.wymiwyg.wrhapi.ResponseStatus;
import org.wymiwyg.wrhapi.util.ResponseBase;


/**
 * @author reto
 */
public class ResponseImpl extends ResponseBase {
    private final static Logger log = Logger.getLogger(ResponseImpl.class.getName());

	private ResponseStatus status = null;

	private MessageBody body;

    // private Exception bodyWriteException;



    public void setBody(MessageBody body) throws HandlerException {
        this.body = body;
    }



    public void setResponseStatus(ResponseStatus status) {
        this.status = status;
    }

	MessageBody getBody() {
		return body;
	}

	ResponseStatus getStatus() {
		return status;
	}

    void writeHeaders(HttpServletResponse servletResponse) {
    	Map<HeaderName, String[]> headerMap = getHeaderMap();
        Iterator<HeaderName> keyIter = headerMap.keySet().iterator();

        while (keyIter.hasNext()) {
            HeaderName current =  keyIter.next();
            String[] values = headerMap.get(current);

            if (current.equals(HeaderName.SET_COOKIE)) {
                /*
                 * found on
                 * http://search.cpan.org/~gaas/libwww-perl-5.803/lib/HTTP/Headers.pm
                 * The HTTP spec (RFC 2616) promise that joining multiple values
                 * in this way will not change the semantic of a header field,
                 * but in practice there are cases like old-style Netscape
                 * cookies (see HTTP::Cookies) where "," is used as part of the
                 * syntax of a single field value.
                 *
                 * So the expririenced IE behavious seems to go back to netscape
                 */
                for (int i = 0; i < values.length; i++) {
                    String string = values[i];
                    servletResponse.addHeader(current.toString(), string);
                }
            } else {
                String currentStringValue = getHeaderStringValue(values);
                servletResponse.setHeader(current.toString(), currentStringValue);
            }
        }
    }

    



	/**
     * @param values
     * @return
     */
    private String getHeaderStringValue(String[] values) {
        StringBuffer buffer = new StringBuffer();
        boolean first = true;

        for (int i = 0; i < values.length; i++) {
            if (first) {
                first = false;
            } else {
                buffer.append(", ");
            }

            buffer.append(values[i]);
        }

        return buffer.toString();
    }



    
}
