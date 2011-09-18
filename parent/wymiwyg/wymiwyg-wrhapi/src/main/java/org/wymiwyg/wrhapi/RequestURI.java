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

/**
 * Represents a request as defined by section 5.1.2 of RFC 2616.
 * 
 * @author reto
 */
public interface RequestURI {

	

	
	/**
	 * Section 5.1.2 of RFC 2616 defines 4 options for Request-URIs
	 * 
	 * @return the type of this Request-URI
	 */
	public Type getType();

	/**
	 * The abs-path of an http URL as defined in section 3.2.2 of RFC 2616, i.e.
	 * the path including the query-part
	 * 
	 * @return the abs-path or null if this request is of type NO_RESOURCE or
	 *         AUTHORITY
	 */
	public String getAbsPath();
	
	/**
	 * @return the query-part, i.e. the section after "?" or null
	 */
	public String getQuery();

	/**
	 * @return the path without query-part, and without "?".
	 */
	public String getPath();

	/**
	 * @deprecated use org.wymiwyg.wrhapi.util.parameterparser.URLEncodedParameterCollection instead
	 * @return the parameter names in the order they first appear in the request
	 */
	@Deprecated
	public String[] getParameterNames();

	/**
	 * @deprecated use org.wymiwyg.wrhapi.util.parameterparser.URLEncodedParameterCollection instead
	 * @param name
	 *            the name of the parameter
	 * @return an array with the values of the ger parameter or null if the
	 *         parameter is not present
	 */
	@Deprecated
	public String[] getParameterValues(String name);
	
	/**
	 * @see org.wymiwyg.wrhapi.RequestURI.getType()
	 */
	public enum Type {
		/**
		 * From RFC 2616 <quote>The asterisk "*" means that the request does not
		 * apply to a particular resource, but to the server itself, and is only
		 * allowed when the method used does not necessarily apply to a
		 * resource.</quote>
		 */
		NO_RESOURCE,
		/**
		 * From RFC 2616 <quote>The absoluteURI form is REQUIRED when the
		 * request is being made to a proxy.</quote> <quote>To allow for
		 * transition to absoluteURIs in all requests in future versions of
		 * HTTP, all HTTP/1.1 servers MUST accept the absoluteURI form in
		 * requests, even though HTTP/1.1 clients will only generate them in
		 * requests to proxies.</quote>
		 */
		ABSOLUTE_URI,
		/**
		 * A type of request-URI containing only the abs-path section of the
		 * http URL
		 */
		ABS_PATH,
		/**
		 * Used by the HTTP CONNECT method
		 */
		AUTHORITY
	}
}
