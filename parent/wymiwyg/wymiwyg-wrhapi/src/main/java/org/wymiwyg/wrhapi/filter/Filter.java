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
package org.wymiwyg.wrhapi.filter;

import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.Response;

/**
 * @author reto
 * 
 */
public interface Filter {

	/**
	 * Handles a request optionally forwarding it to the rest of the
	 * filter-chain by calling the handle-method of rest, this method may be
	 * invoked with the original or with new request and response objects as
	 * parameters.
	 * 
	 * @param request the wrhapi request
	 * @param response the response
	 * @param rest the rest of the filter chain
	 * @throws HandlerException
	 */
	public void handle(Request request, Response response, Handler rest)
			throws HandlerException;
}
