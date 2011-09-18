/*
 * Copyright 2008 WYMIWYG (http://wymiwyg.org)
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
package org.wymiwyg.wrhapi.util.pathmappings;

import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.util.Set;
import org.junit.Test;
import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.MessageBody;
import org.wymiwyg.wrhapi.Method;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.RequestURI;
import org.wymiwyg.wrhapi.Response;
import org.wymiwyg.wrhapi.URIScheme;
import org.wymiwyg.wrhapi.util.pathmappings.PathMappingHandler;
import static org.junit.Assert.*;

/**
 *
 * @author reto
 */
public class HandlerTest {

	public HandlerTest() {
	}

	@Test
	public void testSimple() throws HandlerException {
		final int[] calls = new int[1];
		PathMappingHandler handler = new PathMappingHandler();
		handler.addHandler(new Handler() {

			public void handle(Request request, Response response)
					throws HandlerException {
				calls[0]++;
			}
		}, "/", "handler1", false, false);
		assertEquals(0, calls[0]);
		handler.handle(getRequestForPath("/"), null);
		assertEquals(1, calls[0]);
		handler.handle(getRequestForPath("/foo"), null);
		assertEquals(2, calls[0]);
	}

	private Request getRequestForPath(final String path) {
		return new Request() {

			public Method getMethod() throws HandlerException {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public RequestURI getRequestURI() throws HandlerException {
				return new RequestURI() {

					public Type getType() {
						throw new UnsupportedOperationException(
								"Not supported yet.");
					}

					public String getAbsPath() {
						throw new UnsupportedOperationException(
								"Not supported yet.");
					}

					public String getQuery() {
						throw new UnsupportedOperationException(
								"Not supported yet.");
					}

					public String getPath() {
						return path;
					}

					public String[] getParameterNames() {
						throw new UnsupportedOperationException(
								"Not supported yet.");
					}

					public String[] getParameterValues(String name) {
						throw new UnsupportedOperationException(
								"Not supported yet.");
					}
				};
			}

			public MessageBody getMessageBody() throws HandlerException {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public Object getBody() throws HandlerException {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public Set<HeaderName> getHeaderNames() throws HandlerException {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public String[] getHeaderValues(HeaderName headerName) throws HandlerException {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public int getPort() throws HandlerException {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public URIScheme getScheme() throws HandlerException {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public InetAddress getRemoteHost() throws HandlerException {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public X509Certificate[] getCertificates() {
				throw new UnsupportedOperationException("Not supported yet.");
			}

			public Object getAttribute(String name) {
				throw new UnsupportedOperationException("Not supported yet.");
			}
		};
	}
}