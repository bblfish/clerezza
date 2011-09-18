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

import java.util.HashMap;
import java.util.Map;

/**
 * A response Status as defined by section 6.1.1 of RFC 2616
 * 
 * @author reto
 */
public class ResponseStatus {
	static Map<Integer, ResponseStatus> instanceMap = new HashMap<Integer, ResponseStatus>();
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus SUCCESS = new ResponseStatus(200,
			"Success");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus CREATED = new ResponseStatus(201,
			"Created");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus NO_CONTENT = new ResponseStatus(204,
			"No Content");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus MULTI_STATUS = new ResponseStatus(207,
			"Multi-Status");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus MULTIPLE_CHOICES = new ResponseStatus(
			300, "Multiple Choices");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus MOVED_TEMPORARILY = new ResponseStatus(
			302, "Moved Temporarily");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus BAD_REQUEST = new ResponseStatus(400,
			"Bad Request");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus UNAUTHORIZED = new ResponseStatus(401,
			"Unauthorized");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus FORBIDDEN = new ResponseStatus(403,
			"Forbidden");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus NOT_FOUND = new ResponseStatus(404,
			"Resource not found");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus METHOD_NOT_ALLOWED = new ResponseStatus(
			405, "Method Not Allowed");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus NOT_ACCEPTABLE = new ResponseStatus(406,
			"Not Acceptable");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus PRECONDITION_FAILED = new ResponseStatus(
			412, "Precondition Failed");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus EXPECTATION_FAILED = new ResponseStatus(
			417, "Expectation Failed");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus INTERNAL_SERVER_ERROR = new ResponseStatus(
			500, "Internal Server Error");
	/**
	 * See section 6.1.1 of RFC 2616
	 */
	public static final ResponseStatus NOT_IMPLEMENTED = new ResponseStatus(
			501, "Not Implemented");
	private int code;
	private String reasonPrase;

	private ResponseStatus(int code) {
		this.code = code;
		instanceMap.put(new Integer(code), this);
	}

	private ResponseStatus(int code, String reasonPrase) {
		this.code = code;
		this.reasonPrase = reasonPrase;
		instanceMap.put(new Integer(code), this);
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object object) {
		if (!(object instanceof ResponseStatus)) {
			return false;
		}

		return code == ((ResponseStatus) object).code;
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return code;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		StringBuffer buffer = new StringBuffer("Response-Status code ");
		buffer.append(code);
		buffer.append(", message ");
		buffer.append(reasonPrase);

		return buffer.toString();
	}

	/**
	 * @return Returns the code.
	 */
	public int getCode() {
		return code;
	}

	/**
	 * @return Returns the message.
	 */
	public String getReasonPhrase() {
		return reasonPrase;
	}

	/**
	 * @param code the response code
	 * @return the instance of ResponseStatus for the specifed code
	 */
	public static synchronized ResponseStatus getInstanceByCode(int code) {
		if (instanceMap.containsKey(new Integer(code))) {
			return (ResponseStatus) instanceMap.get(new Integer(code));
		}

		return new ResponseStatus(code);
	}
}
