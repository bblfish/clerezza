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
package org.wymiwyg.wrhapi;

import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * @author reto
 */
public interface Request {

	/**
	 * @return the method of this request
	 * @throws HandlerException
	 */
	public Method getMethod() throws HandlerException;

	/**
	 * This methods returns the request-uri including the get parameters.
	 * 
	 * @return the request-uri
	 * @throws HandlerException
	 */
	public RequestURI getRequestURI() throws HandlerException;

	/**
	 * @return the message body of this request
	 * @throws HandlerException
	 */
	public MessageBody getMessageBody() throws HandlerException;

	/**
	 * @deprecated use getMessageBody instead
	 * @return
	 * @throws HandlerException
	 */
	public Object getBody() throws HandlerException;

	/**
	 * According to RFC 2616: "The order in which header fields with differing
	 * field names are received is not significant."
	 * 
	 * @return the all <code>HeaderName<code>S in the order in which they appear
	 * @throws HandlerException
	 */
	public Set<HeaderName> getHeaderNames() throws HandlerException;

	/**
	 * Returns the value of a header-field, if the header-field is not present
	 * an array of size 0 is returned
	 * 
	 * @param headerName
	 *            the <code>HeaderName</code> for which the values are to be
	 *            returned
	 * @return the header-values in the order they appear in the request
               current implementation takes each header line and splits each header line 
     *         after a comma (i.e. the  ',' character). [this assumes all headers split on commas]
	 * @throws HandlerException
	 */
	public String[] getHeaderValues(HeaderName headerName)
			throws HandlerException;

	/**
	 * @return the TCP port to which this request was directed
	 * @throws HandlerException
	 */
	public int getPort() throws HandlerException;

	/**
	 * @return a string representing the protocol scheme used (like 'http' or
	 *         'https')
	 * @throws HandlerException
	 */
	public URIScheme getScheme() throws HandlerException;

	/**
	 * @return the host issuing the request
	 * @throws HandlerException
	 */
	public InetAddress getRemoteHost() throws HandlerException;

	/**
	 * 
	 * @return the <code>X509Certificate</code>s sent by the client, or null
	 *   if no client certificate was sent
	 */
	public X509Certificate[] getCertificates();

	/**
	 *
	 * @return an attribute of the Request
	 */
	public Object getAttribute(String name);
}
