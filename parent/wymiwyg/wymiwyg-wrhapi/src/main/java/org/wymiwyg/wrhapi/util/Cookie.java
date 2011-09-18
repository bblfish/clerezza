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

import java.util.Date;

/**
 * @author reto
 * @date Jun 17, 2004
 */
public class Cookie {
	private String name;
	private String value;
	private String path;
	private String maxAge;

	/**
	 * Creates a Cookie from a String as it appears as value of the
	 * cookie-header
	 * 
	 * @param cookie the String representation of the cooke
	 * @throws InvalidCookieException
	 */
	public Cookie(String cookie) throws InvalidCookieException {
		int colonPos = cookie.indexOf(";");

		if (colonPos != -1) {
			cookie = cookie.substring(0, cookie.indexOf(";"));
		}

		int equalPos = cookie.indexOf("=");

		if (equalPos == -1) {
			throw new InvalidCookieException("No = sign found");
		}

		name = cookie.substring(0, equalPos).trim();
		value = cookie.substring(cookie.indexOf("=") + 1, cookie.length());
	}

	/**
	 * @param name
	 * @param value
	 */
	public Cookie(String name, String value) {
		super();
		this.name = name;
		this.value = value;
	}

	/**
	 * @return Returns the name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return Returns the value.
	 */
	public String getValue() {
		return value;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append(name);
		buffer.append('=');
		buffer.append(value);
		buffer.append("; path=");

		if (path == null) {
			buffer.append("/");
		} else {
			buffer.append(path);
		}

		if (maxAge != null) {
			buffer.append("; Max-Age=");
			buffer.append(maxAge);

			if (!maxAge.equals("-1")) {
				buffer.append("; expires=");
				buffer.append(new HTTPDateFormat().format(new Date(System
						.currentTimeMillis()
						+ (((long) Integer.parseInt(maxAge)) * 1000))));
			}
		}

		return buffer.toString();
	}

	/**
	 * @return the path attribute of this cookie
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Set the path-attribute of this cookie
	 * 
	 * @param path the path to be set
	 */
	public void setPath(String path) {
		this.path = path;
	}

	/**
	 * Set the lifetime of the cookie in seconds (by using the Max-Age attribute
	 * in the http-header
	 * 
	 * @param maxAge
	 *            the maximum age in seconds
	 */
	public void setMaxAge(int maxAge) {
		this.maxAge = Integer.toString(maxAge);
	}
}
