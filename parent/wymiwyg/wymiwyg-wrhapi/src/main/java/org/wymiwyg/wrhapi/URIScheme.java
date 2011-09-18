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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * represents a uri-scheme like http, ftp etc. There are no two instances for the same scheme.
 * 
 * @author reto
 * 
 */
public class URIScheme {

	//must be before other variable call constructor
	static Map<String, URIScheme> stringInstanceMap = Collections.synchronizedMap(new HashMap<String, URIScheme>());
	
	/**
	 * the HTTP-Uri Scheme
	 */
	public final static URIScheme HTTP = new URIScheme("http");

	/**
	 * the HTTPS-Uri Scheme
	 */
	public final static URIScheme HTTPS = new URIScheme("https");

	/**
	 * the HTTPSY-Yurl Scheme
	 */
	public final static URIScheme HTTPSY = new URIScheme("httpsy");

	private String lowerCaseString;

	

	private URIScheme(String lowerCaseString) {
		stringInstanceMap.put(lowerCaseString, this);
		this.lowerCaseString = lowerCaseString;
	};

	/**
	 * RFC 1738 says: "For resiliency, programs interpreting URLs should treat
	 * upper case letters as equivalent to lower case in scheme names (e.g.,
	 * allow "HTTP" as well as "http")."
	 * 
	 * This method allows upper-case characters.
	 * 
	 * @param schemeString
	 *            a string of which the lower-case version represents the scheme
	 * @return if available an existing instance of URIScheme, otherwise a anew
	 *         one
	 */
	public static URIScheme getURIScheme(String schemeString) {
		return getURISchemeFromLowercaseString(schemeString.toLowerCase());
	}

	/**
	 * according to RFC 1738 only lower-case letters are allowed in the scheme
	 * 
	 * @param lowerCaseString
	 *            the lower-case string representing the scheme
	 * @return if available an existing instance of URIScheme, otherwise a anew
	 *         one
	 */
	public static URIScheme getURISchemeFromLowercaseString(
			String lowerCaseString) {
		URIScheme existing = stringInstanceMap.get(lowerCaseString);
		if (existing == null) {
			return new URIScheme(lowerCaseString);
		} else {
			return existing;
		}
	}
	
	/**
	 * @return the string representation of this scheme
	 */
	public String getStringRepresentation() {
		return lowerCaseString;
	}

}
