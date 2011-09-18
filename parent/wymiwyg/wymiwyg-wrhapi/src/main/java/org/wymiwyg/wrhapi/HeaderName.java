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

import java.io.StringWriter;


/**
 * A case-insensitive String representing an HTTP-Header
 *
 * @author reto
 */
public class HeaderName {
	//TODO add comments referencing to the respective RFC section
    /**
     * 
     */
    public static final Object CONTENT_DISPOSITION = new HeaderName(
            "Content-Disposition");
    /**
     * 
     */
    public static final HeaderName TRANSFER_ENCODING = new HeaderName(
            "Transfer-Encoding");
    /**
     * 
     */
    public static HeaderName ACCEPT = new HeaderName("Accept");
    /**
     * 
     */
    public static HeaderName HOST = new HeaderName("Host");
    /**
     * 
     */
    public static HeaderName CONTENT_TYPE = new HeaderName("Content-Type");
    /**
     * 
     */
    public static HeaderName ACCEPT_LANGUAGE = new HeaderName("Accept-Language");
    /**
     * 
     */
    public static HeaderName CONTENT_LENGTH = new HeaderName("Content-Length");
    /**
     * 
     */
    public static HeaderName CONTENT_ENCODING = new HeaderName(
            "Content-Encoding"); //RFC 2616 Section 7.1, like gzip
    /**
     * 
     */
    public static HeaderName CONTENT_LANGUAGE = new HeaderName(
            "Content-Language");
    /**
     * 
     */
    public static HeaderName COOKIE = new HeaderName("Cookie");
    /**
     * 
     */
    public static HeaderName SET_COOKIE = new HeaderName("Set-Cookie");
    /**
     * 
     */
    public static HeaderName LOCATION = new HeaderName("Location");
    /**
     * 
     */
    public static HeaderName REFERER = new HeaderName("Referer");
    /**
     * 
     */
    public static final HeaderName PRAGMA = new HeaderName("Pragma");
    /**
     * 
     */
    public static final HeaderName EXPIRES = new HeaderName("Expires");
    /**
     * 
     */
    public static final HeaderName AUTHORIZATION = new HeaderName(
            "Authorization");
    /**
     * 
     */
    public static final HeaderName CACHE_CONTROL = new HeaderName(
            "Cache-Control");
    /**
     * 
     */
    public static final HeaderName USER_AGENT = new HeaderName("User-Agent");
    /**
     * 
     */
    public static final HeaderName WWW_AUTHENTICATE = new HeaderName(
            "Www-Authenticate");
    /**
     * 
     */
    public static final HeaderName DEPTH = new HeaderName("Depth");
    /**
     * 
     */
    public static final HeaderName DAV = new HeaderName("Dav");
    /**
     * 
     */
    public static final HeaderName ALLOW = new HeaderName("Allow");
    /**
     * 
     */
    public static final HeaderName LAST_MODIFIED = new HeaderName(
            "Last-Modified");
    /**
     * 
     */
    public static final HeaderName SERVER = new HeaderName("Server");
    /**
     * 
     */
    public static final HeaderName IF_MODIFIED_SINCE = new HeaderName(
            "If-Modified-Since");
    /**
     * 
     */
    public static final HeaderName IF_NONE_MATCH = new HeaderName(
            "If-None-Match");
    private String normalizedCaseName;

    private HeaderName(String normalizedCaseName) {
        this.normalizedCaseName = normalizedCaseName;
    }

 
    /**
     * Static method to create new instances
     * 
     * @param name the name of the header for which an instance is to be returned
     * @return an instance of HeaderName for the specified name
     */
    public static HeaderName get(String name) {
        return new HeaderName(normalizeCase(name));
    }
    
    @Override
    public String toString() {
        return normalizedCaseName;
    }

    @Override
    public boolean equals(Object object) {
        if (!object.getClass().equals(HeaderName.class)) {
            return false;
        } else {
            return normalizedCaseName.equals(((HeaderName) object).normalizedCaseName);
        }
    }

    
	/**
     * @return the hashcode of the case normalized string of the header name,
	 *   a string is case normal iff it the characters are lower case except for
	 *   the first and any character following a dash ('-')
     */
	@Override
    public int hashCode() {
        return normalizedCaseName.hashCode();
    }

	private static String normalizeCase(String string) {
		StringWriter resultWriter = new StringWriter(string.length());
		boolean lastCharADash = false;
		for (int i = 0; i < string.length(); i++) {
			final char currentChar = string.charAt(i);
			if ((i  == 0) || lastCharADash) {
				resultWriter.write(Character.toUpperCase(currentChar));
			} else {
				resultWriter.write(Character.toLowerCase(currentChar));
			}
			if (currentChar == '-') {
				lastCharADash = true;
			} else {
				lastCharADash = false;
			}
		}
		return resultWriter.toString();
	}
}
