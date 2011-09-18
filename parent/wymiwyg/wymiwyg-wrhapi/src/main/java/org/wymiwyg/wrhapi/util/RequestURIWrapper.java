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

import org.wymiwyg.wrhapi.RequestURI;

/**
 * @author reto
 */
public class RequestURIWrapper implements RequestURI {
	private RequestURI wrapped;

	/**
	 * creates a wrapper for a RequestURI
	 * 
	 * @param wrapped
	 *            the base RequestURI
	 */
	public RequestURIWrapper(RequestURI wrapped) {
		this.wrapped = wrapped;
	}

	public String getPath() {
		return wrapped.getPath();
	}

	@Deprecated
	public String[] getParameterNames() {
		return wrapped.getParameterNames();
	}

	@Deprecated
	public String[] getParameterValues(String name) {
		return wrapped.getParameterValues(name);
	}

	@Override
	public String toString() {
		return getAbsPath();
	}

	public String getAbsPath() {
		return wrapped.getAbsPath();
	}

	public Type getType() {
		return wrapped.getType();
	}

	public String getQuery() {
		return wrapped.getQuery();
	}
}
