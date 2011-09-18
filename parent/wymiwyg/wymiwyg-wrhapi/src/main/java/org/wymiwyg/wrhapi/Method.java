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
 * A request Method (GET, POST, PUT, DELETE, ...).
 * 
 * @author reto
 */
public class Method {
	/**
	 * see rfc 2616 section 9
	 */
	public static final Method POST = new Method("POST");

	/**
	 * see rfc 2616 section 9
	 */
	public static final Method GET = new Method("GET");

	/**
	 * see rfc 2616 section 9
	 */
	public static final Method PUT = new Method("PUT");

	/**
	 * see rfc 2616 section 9
	 */
	public static final Method DELETE = new Method("DELETE");

	/**
	 * see rfc 2616 section 9
	 */
	public static final Method OPTIONS = new Method("OPTIONS");

	/**
	 * see rfc 2616 section 9
	 */
	public static final Method TRACE = new Method("TRACE");

	/**
	 * see rfc 2616 section 9
	 */
	public static final Method CONNECT = new Method("CONNECT");
	
	/**
	 * see rfc 2616 section 9
	 */
	public static final Method HEAD = new Method("HEAD");

	/** URIQUA method, see http://sw.nokia.com/uriqa/URIQA.html
	 */
	public static final Method MGET = new Method("MGET");

	/**
	 * Webdav method, see RFC 2518
	 */
	public static final Method PROPFIND = new Method("PROPFIND");

	/**
	 * Webdav method, see RFC 2518
	 */
	public static final Method PROPPATCH = new Method("PROPPATCH");

	/**
	 * Webdav method, see RFC 2518
	 */
	public static final Method MKCOL = new Method("MKCOL");

	/**
	 * Webdav method, see RFC 2518
	 */
	public static final Method COPY = new Method("COPY");

	/**
	 * Webdav method, see RFC 2518
	 */
	public static final Method MOVE = new Method("MOVE");

	/**
	 * Webdav method, see RFC 2518
	 */
	public static final Method LOCK = new Method("LOCK");

	/**
	 * Webdav method, see RFC 2518
	 */
	public static final Method UNLOCK = new Method("UNLOCK");

	private String name;

	private Method(String name) {
		this.name = name;
	}

	/**
	 * returns a method object for a string representation of a the method
	 * 
	 * @param name
	 *            the verb of the method
	 * @return
	 */
	public static Method get(String name) {
		return new Method(name.toUpperCase());
	}

	@Override
	public String toString() {
		return "Method: " + name;
	}

	@Override
	public boolean equals(Object object) {
		if (!(object instanceof Method)) {
			return false;
		}

		return name.equals(((Method) object).name);
	}

	/**
	 * @return the hashcode of the upper-case string representing the method.
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return name.hashCode();
	}

	/**
	 * @return the upper-case string representing this method.
	 */
	public String getName() {
		return name;
	}
}
