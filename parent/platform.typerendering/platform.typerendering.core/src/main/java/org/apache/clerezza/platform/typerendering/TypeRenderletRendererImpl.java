/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.clerezza.platform.typerendering;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;
import org.apache.clerezza.rdf.core.UriRef;
import org.apache.clerezza.rdf.utils.GraphNode;
import org.osgi.framework.BundleContext;

/**
 *
 * @author  reto
 */
class TypeRenderletRendererImpl implements Renderer {

	private URI renderSpecUri = null;
	private TypeRenderlet renderlet = null;
	private MediaType mediaType = null;
	private final RendererFactory rendererFactory;
	private final BundleContext bundleContext;

	TypeRenderletRendererImpl(UriRef renderingSpecification,
			TypeRenderlet renderlet, MediaType mediaType,
			RendererFactory rendererFactory,
			BundleContext bundleContext) {
		this.renderlet = renderlet;
		this.mediaType = mediaType;
		this.rendererFactory = rendererFactory;
		if (renderingSpecification != null) {
			try {
				renderSpecUri = new URI(renderingSpecification.getUnicodeString());
			} catch (URISyntaxException ex) {
				throw new WebApplicationException(ex);
			}
		}
		this.bundleContext = bundleContext;
	}




	@Override
	public MediaType getMediaType() {
		return mediaType;
	}


	@Override
	public void render(GraphNode resource, GraphNode context,
			String mode,
			UriInfo uriInfo,
			HttpHeaders requestHeaders,
			MultivaluedMap<String, Object> responseHeaders,
			Map<String, Object> sharedRenderingValues,
			OutputStream entityStream) throws IOException {
		CallbackRenderer callbackRenderer =
				new CallbackRendererImpl(rendererFactory,
				uriInfo, requestHeaders, responseHeaders, mediaType, sharedRenderingValues);
		TypeRenderlet.RequestProperties requestProperties =
				new TypeRenderlet.RequestProperties(uriInfo, requestHeaders,
				responseHeaders, mode, mediaType, bundleContext);
		renderlet.render(resource, context, sharedRenderingValues,
				callbackRenderer, requestProperties, entityStream);
	}



}
