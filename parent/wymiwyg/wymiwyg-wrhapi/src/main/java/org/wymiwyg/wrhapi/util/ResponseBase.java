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
import org.wymiwyg.wrhapi.Response;

import java.util.HashMap;
import java.util.Map;

/**
 * provides methods for setting and adding headers, the resulting headers are
 * avaliable as a Map to the subclass;
 * 
 * @author reto
 * 
 */
public abstract class ResponseBase implements Response {
	private Map<HeaderName, String[]> headerMap = new HashMap<HeaderName, String[]>();

	public void addHeader(HeaderName headerName, Object value)
			throws HandlerException {
		if (headerMap.containsKey(headerName)) {
			String[] existingValues = (String[]) headerMap.get(headerName);
			String[] newValues;

			if (value instanceof Object[]) {
				Object[] array = (Object[]) value;
				newValues = new String[existingValues.length + array.length];
				System.arraycopy(existingValues, 0, newValues, 0,
						existingValues.length);

				for (int i = 0; i < array.length; i++) {
					newValues[existingValues.length + i] = array[i].toString();
				}
			} else {
				newValues = new String[existingValues.length + 1];
				System.arraycopy(existingValues, 0, newValues, 0,
						existingValues.length);
				newValues[existingValues.length] = value.toString();
			}

			setHeader(headerName, newValues);
		} else {
			setHeader(headerName, value);
		}
	}

	public void setHeader(HeaderName headerName, Object value) {
		if (value instanceof String[]) {
			headerMap.put(headerName, (String[]) value);
		} else {
			if (!(value instanceof Object[])) {
				String[] values = new String[1];
				values[0] = value.toString();
				headerMap.put(headerName, values);
			} else {
				Object[] array = (Object[]) value;
				String[] values = new String[array.length];

				for (int i = 0; i < array.length; i++) {
					values[i] = array[i].toString();
				}
				headerMap.put(headerName, values);
			}
		}
	}

	/**
	 * @return the header-map resulting from previous calls to the set- and
	 *         addHeader-methods.
	 */
	protected Map<HeaderName, String[]> getHeaderMap() {
		return headerMap;
	}
}
