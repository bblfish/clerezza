/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.clerezza.platform.accountcontrolpanel

import org.apache.clerezza.platform.accountcontrolpanel.ontologies.CONTROLPANEL
import org.osgi.service.component.ComponentContext
import javax.ws.rs._
import javax.ws.rs.core.Context
import javax.ws.rs.core.UriInfo
import collection.JavaConversions._
import org.slf4j.scala._
import org.apache.clerezza.rdf.utils.{UnionMGraph, GraphNode}
import java.security.{PrivilegedAction, AccessController}
import org.apache.clerezza.rdf.core._
import access.TcManager
import impl.SimpleMGraph
import org.apache.clerezza.rdf.scala.utils._
import org.apache.clerezza.rdf.ontologies._

object FoafBrowser {
	def removeHash(uri: UriRef) = {
		val uriStr =uri.getUnicodeString
		val hashpos = uriStr.indexOf("#")
		if (hashpos>0)  new UriRef(uriStr.substring(0,hashpos))
		else uri
	}
}

/**
 * A Panel for browsing linked data of friends. This is a publicly accessible browser.
 * It is different from the PersonPanel, which is for people with local accounts who wish
 * to add friend to their local accounts.
 *
 * @author bblfish
 */
@Path("/browse")
class FoafBrowser extends Logging {
	import org.apache.clerezza.rdf.scala.utils.Preamble._
	import org.apache.clerezza.platform.accountcontrolpanel.FoafBrowser._

	protected def activate(componentContext: ComponentContext): Unit = {
//		this.componentContext = componentContext
	}

	/**
	 * Specialised for browsing people profiles
	 */
	@GET
	@Path("person")
	def viewPerson(@Context uriInfo: UriInfo,
						@QueryParam("uri") uriref: UriRef): GraphNode = {

		if (uriref != null) {//show some error page
			logger.info("id =="+uriref.getUnicodeString)
		}

		//val foaf = descriptionProvider.fetchSemantics(uri, Cache.Fetch)
		//so here the initial fetch could be used to decide if information is available at all,
		//ie, if the URL is accessible, if there are error conditions - try later for example...
		 val profile = AccessController.doPrivileged(new PrivilegedAction[Graph]() {
			 def run() = tcManager.getGraph(removeHash (uriref))
		 });

		val gr = new context(new UnionMGraph(new SimpleMGraph(),profile)) {
			//add a bit of inferencing for persons, until we have some reasoning
			for (kn: Triple <- profile.filter(null, FOAF.knows, null)) {
				node(kn.getSubject) a FOAF.Person
				if (kn.getObject.isInstanceOf[NonLiteral])
					node(kn.getObject) a FOAF.Person
			}

			lazy val doc = (
				node(uriInfo.getRequestUri()).a(PLATFORM.HeadedPage)
					                       .a(CONTROLPANEL.ProfileViewerPage)
		            -- FOAF.primaryTopic --> uriref
			)
		}

		//todo: if possible get a bit more info about remote profiles, if these are in the db

		//Here we make a BNode the subject of the properties as a workaround to CLEREZZA-447
		return gr.doc
	}

	protected var tcManager: TcManager = null;

	protected def bindTcManager(tcManager: TcManager) = {
		this.tcManager = tcManager
	}

	protected def unbindTcManager(tcManager: TcManager) = {
		this.tcManager = null
	}



}