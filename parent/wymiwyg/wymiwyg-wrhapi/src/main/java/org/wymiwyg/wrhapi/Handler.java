/*
 * Copyright  2002-2005 WYMIWYG (http://wymiwyg.org)
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
 * A handler processes a web-requests. The handler passed to
 * <code>org.wymiwyg.wrhapi.WebServerFactory.startNewWebServer(Handler, ServerBinding)</code>
 * is invoked on every request the server gets, in other context invocation may
 * be condition, for example the Handler passed to the constructor
 * <code>org.wymiwyg.wrhapi.filter.impl.FilterRunner.FilterRunner(Filter[], Handler)</code>
 * is invoked only if all filters forwards the request.
 * 
 * @author reto
 * 
 */
public interface Handler {

	/**
	 * When a request is to be handled by this Handler this method is invoked .
	 * 
	 * @param request
	 *            the request to be processed
	 * @param response
	 *            a response object for adding response-headers and body
	 * @throws HandlerException
	 * 
	 */
	public void handle(Request request, Response response)
			throws HandlerException;
}
