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
package org.wymiwyg.wrhapi.util;

import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.MessageBody;
import org.wymiwyg.wrhapi.Method;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.RequestURI;
import org.wymiwyg.wrhapi.URIScheme;


/**
 * @author reto
 */
public class RequestWrapper implements Request {
    private Request wrapped;

    /**
     * @param wrapped
     */
    public RequestWrapper(Request wrapped) {
        this.wrapped = wrapped;
    }

    /**
     * @deprecated
     * @throws HandlerException
     * @see org.wymiwyg.wrhapi.Request#getBody()
     */
    public Object getBody() throws HandlerException {
        return wrapped.getBody();
    }

    /**
     * @throws HandlerException
     * @see org.wymiwyg.wrhapi.Request#getHeaderNames()
     */
    public Set<HeaderName> getHeaderNames() throws HandlerException {
        return wrapped.getHeaderNames();
    }

    /**
     * @throws HandlerException
     * @see org.wymiwyg.wrhapi.Request#getHeaderValues(java.lang.String)
     */
    public String[] getHeaderValues(HeaderName headerName)
        throws HandlerException {
        return wrapped.getHeaderValues(headerName);
    }

    /**
     * @throws HandlerException
     * @see org.wymiwyg.wrhapi.Request#getMethod()
     */
    public Method getMethod() throws HandlerException {
        return wrapped.getMethod();
    }

    /**
     * @throws HandlerException
     * @see org.wymiwyg.wrhapi.Request#getRequestURI()
     */
    public RequestURI getRequestURI() throws HandlerException {
        return wrapped.getRequestURI();
    }

    /**
     * @throws HandlerException
     * @see org.wymiwyg.wrhapi.Request#getPort()
     */
    public int getPort() throws HandlerException {
        return wrapped.getPort();
    }

    /**
     * @throws HandlerException
     * @see org.wymiwyg.wrhapi.Request#getScheme()
     */
    public URIScheme getScheme() throws HandlerException {
        return wrapped.getScheme();
    }

    /* (non-Javadoc)
     * @see org.wymiwyg.rwcf.Request#getRemote()
     */
    public InetAddress getRemoteHost() throws HandlerException {
        return wrapped.getRemoteHost();
    }

	/* (non-Javadoc)
	 * @see org.wymiwyg.wrhapi.Request#getMessageBody()
	 */
	public MessageBody getMessageBody() throws HandlerException {
		return wrapped.getMessageBody();
	}

	public X509Certificate[] getCertificates() {
		return wrapped.getCertificates();
	}

	/**
	 *
	 * @return an attribute of the Request
	 */
	public Object getAttribute(String name) {
		return wrapped.getAttribute(name);
	}

}
