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

import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.MessageBody;
import org.wymiwyg.wrhapi.Response;
import org.wymiwyg.wrhapi.ResponseStatus;

/**
 * @author reto
 *
 */
public class ResponseWrapper implements Response {
	
	private Response wrapped;

	/**
	 * Creates a Response forwarding all method calls to a wrapped Response
	 * 
	 * @param wrapped the wrapped Response object
	 */
	protected ResponseWrapper(Response wrapped) {
		this.wrapped = wrapped;
	}

	/* (non-Javadoc)
	 * @see org.wymiwyg.wrhapi.Response#addHeader(org.wymiwyg.wrhapi.HeaderName, java.lang.Object)
	 */
	public void addHeader(HeaderName headerName, Object value)
			throws HandlerException {
		wrapped.addHeader(headerName, value);

	}

	/* (non-Javadoc)
	 * @see org.wymiwyg.wrhapi.Response#setBody(org.wymiwyg.wrhapi.MessageBody)
	 */
	public void setBody(MessageBody body) throws HandlerException {
		wrapped.setBody(body);

	}

	/* (non-Javadoc)
	 * @see org.wymiwyg.wrhapi.Response#setHeader(org.wymiwyg.wrhapi.HeaderName, java.lang.Object)
	 */
	public void setHeader(HeaderName headerName, Object value)
			throws HandlerException {
		wrapped.setHeader(headerName, value);

	}

	/* (non-Javadoc)
	 * @see org.wymiwyg.wrhapi.Response#setResponseStatus(org.wymiwyg.wrhapi.ResponseStatus)
	 */
	public void setResponseStatus(ResponseStatus status)
			throws HandlerException {
		wrapped.setResponseStatus(status);

	}

}
