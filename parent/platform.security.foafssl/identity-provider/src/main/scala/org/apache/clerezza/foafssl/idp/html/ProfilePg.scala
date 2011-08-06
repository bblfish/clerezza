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

package org.apache.clerezza.foafssl.idp.html

import org.apache.clerezza.foafssl.ontologies.WEBIDPROVIDER
import org.apache.clerezza.platform.typerendering.scala.{XmlResult, SRenderlet}
import org.apache.clerezza.rdf.ontologies.FOAF
import org.apache.clerezza.rdf.scala.utils._
import org.apache.clerezza.rdf.core.UriRef
import java.net.{URL, URLEncoder}
import org.apache.clerezza.platform.security.UserUtil
import org.apache.clerezza.foafssl.auth.X509Claim
import org.apache.clerezza.platform.security.auth.WebIdPrincipal
import xml.{Elem, NodeSeq, Node}

/**
 * @author bblfish
 * @created: 14/07/2011
 */


class ProfilePg extends SRenderlet {
	def getRdfType() = WEBIDPROVIDER.ProfileSelector


	override def renderedPage(arguments: XmlResult.Arguments) = new XhtmlProfilePg(arguments)
}

object XhtmlProfilePg {
   val emptyText=new scala.xml.Text("")
	//the code here is the same as in org.apache.clerezza.platform.accountcontrolpanel.html.PersonPanel
	//should be refactored into a library

	def ifE[T](arg:T)(template: T=>Node ):NodeSeq = {
		def isEmpty(arg: Any): Boolean = {
			arg match {
				case prod: Product => prod.productIterator.forall(isEmpty(_))
				case str: String => (str.size == 0)
				case it: CollectedIter[RichGraphNode] => (it.size == 0)
				case node: RichGraphNode => (null == node)
				case other: AnyRef => (null == other)
				case _ => false //literals can't be empty
			}
		}
		if (isEmpty(arg)) return emptyText else template(arg)
	}





	def firstOf(node: RichGraphNode, uris: UriRef*): CollectedIter[RichGraphNode] = {
		for (uri <- uris) {
			val res : CollectedIter[RichGraphNode] = node/uri
			if (res.size>0) return res
		}
		return new CollectedIter[RichGraphNode]()
	}

	/**
	 * get a usable name from the properties available including nick
	 */
	def getName(p: RichGraphNode): String =  {
		 val name = p/FOAF.name*;
		 if ("" != name ) { return name }
		 val firstNm: String = p/FOAF.firstName*;
		 val fmlyNm :String = firstOf(p, FOAF.family_name,FOAF.familyName)*;
  		 if ("" != firstNm || "" != fmlyNm) { return firstNm+" "+fmlyNm }
		 return p*
	}

	def encode(url: String): String =  URLEncoder.encode(url,"UTF8")

	/**
	 * Show a picture a link to their local profile
	 *
	 * assumes the p is WebID node (can change later)
	 */
	def getAgentPix(p: RichGraphNode) = {
		val pix = firstOf(p, FOAF.depiction, FOAF.logo, FOAF.img).getNode match {
			case uri: UriRef => uri.getUnicodeString
			case _ => "http://upload.wikimedia.org/wikipedia/commons/0/0a/Gnome-stock_person.svg"
		}
		<a href={"/browse/person?uri="+encode(p*)}><img class="mugshot" src={pix}/></a>
	}


}

class XhtmlProfilePg(arguments: XmlResult.Arguments) extends XmlResult(arguments )  {
	import XhtmlProfilePg._
	import collection.JavaConversions._

	resultDocModifier.setTitle("WebId Profile Selector")
	resultDocModifier.addNodes2Elem("tx-module", <h1>WebId Service</h1>)
	resultDocModifier.addNodes2Elem("tx-module-tabs-ol", <li><a href="/srvc/webidp">Info</a></li>);
	resultDocModifier.addNodes2Elem("tx-module-tabs-ol", <li class="tx-active"><a href="#">Profile</a></li>)
	resultDocModifier.addNodes2Elem("tx-module-tabs-ol", <li class="tx-active"><a href="/test/WebId">Test</a></li>)
	resultDocModifier.addNodes2Elem("tx-module-tabs-ol", <li><a href="/srvc/webidp/about">About</a></li>);
	resultDocModifier.addNodes2Elem("tx-module-tabs-ol", <li><a href="legal">Legal</a></li>)
	resultDocModifier.addNodes2Elem("head", <style type="text/css">.login {{ visibility:hidden; }}</style> )

	lazy val agents  = res / FOAF.primaryTopic
	lazy val loginUrl = res/WEBIDPROVIDER.authLink
	lazy val hostcgi = {
		val url = new URL(loginUrl*)
		new URL(url.getProtocol,url.getHost,url.getPort,url.getPath)
	}
	lazy val subject = UserUtil.getCurrentSubject();
   lazy val x509claims = subject.getPublicCredentials(classOf[X509Claim])
	lazy val sentCertWithNoVerifiableWebID :Boolean =
		 x509claims.size > 0 && subject.getPrincipals.filter(p=>p.isInstanceOf[WebIdPrincipal]).size ==0


   def hasWebID: Elem = {
	   <div>
		   <p>You wish to login  {hostcgi.getHost}</p>
		   <ul>{for (id <- agents) yield <li>{id}</li>}
		   </ul>
		   <table>
			   <tr><td><a href={loginUrl*}>login</a></td></tr>
		   </table>
		   <p>Or would you rather user a different Identity?</p>
		   {changeCertForm("Change Identity")}
	   </div>
   }

	def hasCertButNoWebID: Elem = {
		val webids = x509claims.flatMap(xclaim=>xclaim.webidclaims)
		<div>
			<p>Your browser sent us a certificate, but it contains no WebID that we could verify.</p>
			{if (webids.size>0) <p>The WebIds it contained were:</p>
			<ul>{for(wid<-webids) yield <li>{wid.webId}</li>}</ul>}
			<p>See <a href="/test/WebId">the more detailed report</a> of what the problem is.</p>
			<p>If you have another certificate</p>
			{changeCertForm("Switch certificate")}
			<p>Or else return to your service provider</p>
			<form method="GET" action={loginUrl *}>
				<input type="hidden" name="error" value="noVerifiedWebId"/>
				<input type="submit" value="return"/>
			</form>
		</div>
	}

	def hasNoCert: Elem = {
		<div>
			<p>You have not selected a certificate.</p>
			{changeCertForm("Select Identity")}
			<p>If you don't have a WebID Certificate get if from <a href="http://www.w3.org/wiki/Foaf%2Bssl/IDP">one of these services</a></p>
			<p>Return to your service provider</p>
			<form method="GET" action={loginUrl *}>
				<input type="hidden" name="error" value="nocert"/>
				<input type="submit" value="return"/>
			</form>
		</div>
	}

	override def content =  <div id="tx-content">
		<p>Welcome {getName(agents)}</p>
	   { if (agents.size > 0) hasWebID
		  else if (sentCertWithNoVerifiableWebID) hasCertButNoWebID
		  else hasNoCert
	   }
		<p>The certificate your browser <a href="/test/WebId/x509">sent in more detail</a>.</p>
		</div>


	def changeCertForm(buttonTxt: String) = {
		<form id="logout" method="POST" action="/srvc/webidp/logout" onsubmit="logout()">
			<input type="hidden" name="session" value={res/WEBIDPROVIDER.sessionId*}/>
		   <input type="hidden" name="rs" value={hostcgi.toString}/>
		   <input type="hidden" name="pause" value="true"/>
		   <input type="submit" value={buttonTxt}/>
	   </form>
		}


}