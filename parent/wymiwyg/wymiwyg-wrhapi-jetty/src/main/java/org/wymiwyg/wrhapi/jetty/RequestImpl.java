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

import java.security.cert.X509Certificate;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.MessageBody;
import org.wymiwyg.wrhapi.Method;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.RequestURI;
import org.wymiwyg.wrhapi.URIScheme;
import org.wymiwyg.wrhapi.util.MessageBody2Read;

import java.io.IOException;
import java.io.InputStream;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;


/**
 * @author reto
 */
public class RequestImpl implements Request {
    InputStream body;
    HttpServletRequest servletRequest;
    private Method method;
    private RequestURI requestURI;
	private int port;

    RequestImpl(HttpServletRequest servletRequest, int port)
        throws IOException {
        body = servletRequest.getInputStream();
        method = Method.get(servletRequest.getMethod());
        this.servletRequest = servletRequest;
        this.requestURI = new RequestURIImp(servletRequest);
        this.port = port;
    }

    /**
     * @see org.wymiwyg.wrhapi.Request#getMethod()
     */
    public Method getMethod() {
        return method;
    }

    /**
     * @see org.wymiwyg.wrhapi.Request#getRequestURI()
     */
    public RequestURI getRequestURI() {
        return requestURI;
    }

    /**
     * @deprecated
     * @see org.wymiwyg.wrhapi.Request#getBody()
     */
    public Object getBody() {
        return body;
    }

    /**
     * @see org.wymiwyg.wrhapi.Request#getHeaderNames()
     */
    public Set<HeaderName> getHeaderNames() {
        Set<HeaderName> headerNames = new HashSet<HeaderName>();
        Enumeration<?> enumeration = servletRequest.getHeaderNames();

        while (enumeration.hasMoreElements()) {
            headerNames.add(HeaderName.get((String) enumeration.nextElement()));
        }

        return headerNames;
    }

    /**
     * @see org.wymiwyg.wrhapi.Request#getHeaderValues(java.lang.String)
     */
    public String[] getHeaderValues(HeaderName headerName) {
        List<String> resultList = new ArrayList<String>();
        Enumeration<?> headerEnun = servletRequest.getHeaders(headerName.toString());

        while (headerEnun.hasMoreElements()) {
            String current = (String) headerEnun.nextElement();
            splitHeaderField(current, resultList);
        }

        return resultList.toArray(new String[resultList.size()]);
    }

    /**
     * @param object
     * @param resultList
     */
    private void splitHeaderField(String headerValue, List<String> resultList) {
        StringTokenizer tokens = new StringTokenizer(headerValue, ",");

        while (tokens.hasMoreTokens()) {
            resultList.add(tokens.nextToken().trim());
        }
    }

    
    public int getPort() {
        return port;
    }

    public URIScheme getScheme() {
		return URIScheme.getURISchemeFromLowercaseString(servletRequest.getScheme());
	}

    /* (non-Javadoc)
     * @see org.wymiwyg.wrhapi.Request#getRemoteHost()
     */
    public InetAddress getRemoteHost() throws HandlerException {
        try {
            return InetAddress.getByName(servletRequest.getRemoteHost());
        } catch (UnknownHostException ex) {
            throw new RuntimeException(
                "HttpServletRequest returned invalid remote-host address");
        }
    }

	/* (non-Javadoc)
	 * @see org.wymiwyg.wrhapi.Request#getMessageBody()
	 */
	public MessageBody getMessageBody() throws HandlerException {
		return new MessageBody2Read() {

			public ReadableByteChannel read() throws IOException {
				return Channels.newChannel(body);
			}
			
		};
	}

	public X509Certificate[] getCertificates() {
		return (X509Certificate[])servletRequest.getAttribute(
				"javax.servlet.request.X509Certificate");
	}

	public Object getAttribute(String id) {
		return servletRequest.getAttribute(id);
	}
}
