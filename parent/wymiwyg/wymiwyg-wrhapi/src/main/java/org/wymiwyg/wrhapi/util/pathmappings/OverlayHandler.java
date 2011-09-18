/*
 * Copyright (c) 2009 trialox.org (trialox AG, Switzerland).
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wymiwyg.wrhapi.util.pathmappings;

import java.nio.ByteBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.MessageBody;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.Response;
import org.wymiwyg.wrhapi.ResponseStatus;

/**
 * Request are first handled by the overly and passed to the base hanlder only 
 * if the overlay sets the response status to a 404 (Not Found) response code.
 *
 * @author reto
 */
class OverlayHandler implements Handler {

	private static final Logger logger = LoggerFactory.getLogger(OverlayHandler.class);

	private Handler overlay;
	private Handler base;

	public OverlayHandler(Handler overlay, Handler base) {
		this.overlay = overlay;
		this.base = base;
	}

	public void handle(Request request, final Response response) throws HandlerException {
		//final MessageBody[] messageBodyArray = new MessageBody[1];
		final ResponseStatus[] responseStatusArray = new ResponseStatus[1];
		logger.info("Attempt to handle with overlay "+overlay.getClass());
		overlay.handle(request, new Response() {

			public void setBody(MessageBody body) throws HandlerException {
				if (!ResponseStatus.NOT_FOUND.equals(responseStatusArray[0])) {
					response.setBody(body);
				} else {
					//TODO consume message body to null
				}
			}

			public void setHeader(HeaderName headerName, Object value) throws HandlerException {
				if (!ResponseStatus.NOT_FOUND.equals(responseStatusArray[0])) {
					response.setHeader(headerName, value);
				}
			}

			public void addHeader(HeaderName headerName, Object value) throws HandlerException {
				if (!ResponseStatus.NOT_FOUND.equals(responseStatusArray[0])) {
					response.addHeader(headerName, value);
				}
			}

			public void setResponseStatus(ResponseStatus status) throws HandlerException {
				if (ResponseStatus.NOT_FOUND.equals(responseStatusArray[0])) {
					response.setResponseStatus(status);
				} else {
					responseStatusArray[0] = status;
				}
			}
		});
		if (responseStatusArray[0].equals(ResponseStatus.NOT_FOUND)) {
			logger.info("overlay returned 404, handling with "+base.getClass());
			base.handle(request, response);
		} else {
			logger.info("overlay returned "+responseStatusArray[0]);

		}
	}

}
