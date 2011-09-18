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
package org.wymiwyg.wrhapi.osgi;

import org.wymiwyg.wrhapi.RequestURI;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.net.URLDecoder;
import java.net.URLEncoder;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.StringTokenizer;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;


/**
 * @author reto
 */
public class RequestURIImp implements RequestURI {
    private HttpServletRequest servletRequest;
    private Map<String, String[]> parameterMap;
	private String queryString;

    /**
     * @param servletRequest
     */
    public RequestURIImp(HttpServletRequest servletRequest) {
        this.servletRequest = servletRequest;

        queryString = servletRequest.getQueryString();

        if (queryString != null) {
            try {
                parameterMap = parseParams(queryString);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            parameterMap = new HashMap<String, String[]>();
        }

        //parameterMap = servletRequest.getParameterMap();
    }

    private Map<String, String[]> parseParams(String queryString)
        throws IOException {
        Map<String, String[]> result = new HashMap<String, String[]>();
        StringTokenizer tokens = new StringTokenizer(queryString, "&");

        while (tokens.hasMoreTokens()) {
            String keyValue = tokens.nextToken();
            int equalsPos = keyValue.indexOf('=');
            if (equalsPos == -1) {
            	continue;
            }
            String key = keyValue.substring(0, equalsPos);
            String[] values = (String[]) result.get(key);

            if (values == null) {
                values = new String[1];
            } else {
                String[] oldValues = values;
                values = new String[oldValues.length + 1];
                System.arraycopy(oldValues, 0, values, 0, oldValues.length);
            }

            values[values.length - 1] = URLDecoder.decode(keyValue.substring(equalsPos +
                        1), "utf-8");
            result.put(key, values);
        }

        return result;
    }

    public String getPath() {
        return servletRequest.getRequestURI();
    }


    public String[] getParameterNames() {
        Set<String> keySet = parameterMap.keySet();
        SortedSet<String> sortedKeys = new TreeSet<String>(keySet);

        return (String[]) sortedKeys.toArray(new String[keySet.size()]);
    }


    public String[] getParameterValues(String name) {
        return (String[]) parameterMap.get(name);
    }

    @Override
    public String toString() {
        StringBuffer buffer = new StringBuffer(getPath());
        boolean first = true;
        String[] parameterNames = getParameterNames();

        for (int i = 0; i < parameterNames.length; i++) {
            String[] values = getParameterValues(parameterNames[i]);

            for (int j = 0; j < values.length; j++) {
                if (first) {
                    buffer.append('?');
                    first = false;
                } else {
                    buffer.append('&');
                }

                buffer.append(parameterNames[i]);
                buffer.append('=');

                try {
                    buffer.append(URLEncoder.encode(values[j], "utf-8"));
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        return buffer.toString();
    }

	public String getAbsPath() {
		return getPath()+(queryString == null? "":"?"+queryString);
	}

	public Type getType() {
		// TODO implement
		return Type.ABS_PATH;
	}

	public String getQuery() {
		return queryString;
	}
}
