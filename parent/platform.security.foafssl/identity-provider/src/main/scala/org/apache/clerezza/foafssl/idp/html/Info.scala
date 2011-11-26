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

import org.apache.clerezza.platform.typerendering.scala.{XmlResult, SRenderlet}
import org.apache.clerezza.rdf.scala.utils._
import org.apache.clerezza.rdf.ontologies.RDF
import org.apache.clerezza.foafssl.ontologies.{CERT, WEBIDPROVIDER}
import java.net.URLEncoder

/**
 * @author bblfish
 * @created: 01/04/2011
 */

class InfoPg extends SRenderlet {
	def getRdfType() = WEBIDPROVIDER.IDPService

	override def renderedPage(arguments: XmlResult.Arguments) = new XhtmlInfoPg(arguments)
}

object XhtmlInfoPg {
   val emptyxml=new scala.xml.Text("")
}

class XhtmlInfoPg(arguments: XmlResult.Arguments) extends XmlResult(arguments )  {

	resultDocModifier.setTitle("WebId Identity Provider Info Page");
	resultDocModifier.addNodes2Elem("tx-module", <h1>WebId Service</h1>);
	resultDocModifier.addNodes2Elem("tx-module-tabs-ol", <li class="tx-active"><a href="#">Info</a></li>);
	resultDocModifier.addNodes2Elem("tx-module-tabs-ol", <li><a href={"/srvc/webidp?rs="+URLEncoder.encode("http://foaf.me/index.php","UTF-8")+"&pause=on"}>Profile</a></li>)
	resultDocModifier.addNodes2Elem("tx-module-tabs-ol", <li><a href="/test/WebId">Test</a></li>);
	resultDocModifier.addNodes2Elem("head", <style type="text/css">.login {{ visibility:hidden; }}</style> )


	lazy val key  = res / WEBIDPROVIDER.signingKey


   override def content = <div id="tx-content">
	   <p>This is a simple Identity Provider for <a href="http://webid.info/">WebID</a>. It is meant to help
		   sites that would like to provide WebID authentication to their users quickly.</p>
	   <p>If you are hosting such a site then you can rely on this service to help authenticate your users with WebID,
		   without your needing to set up https on your server. When you are satisfied of its usefulness you can deploy it
		   to your site.</p>
	   <p>There are two stages to get going. First you need to create the login button linking to this service. Then you need to
		   understand how to interpret what will be returned, so that you can write a script to authenticate
		   your users with the given WebID - ie, set a cookie for them.</p>

	   <h2>Create your login link</h2>
	   <p>Create a login button or link that points to this service. This needs to contain an attribute as a URL to a
		   script on your site so that we can send you the response. This will be done by redirecting the user's browser
		   with a signed response containing his WebID. To create such a link enter the URL of your login service here:</p>
      <p><form action='' method='get'>Requesting auth service URL:
	      <input type='text' size='80' name='rs'/>
	      <input type='submit' value='Log into this service provider'/>
         </form>
	   </p>
	   <p>By clicking on the form you will land on a page whose URL is the one you should enter into your
		   login button/link. You will also see what identity you were logged in as, and given some options to change
	      it.
	   </p>

	   <h2>Understanding the response</h2>
	   <p>The redirected to URL is constructed on the following pattern: </p>
		   <pre><b>$relyingService?webid=$webid&amp;ts=$timeStamp</b>&amp;sig=$URLSignature</pre>
	   <p>Where the above variables have the following meanings: </p>
			<ul>
				<li><code>$relyingService</code> is the URL passed by the server in
				the initial request as the <code>rs</code> parameter, and is the service to which the response is sent.</li>
				<li><code>$webid</code> is the WebID of the user connecting.</li>
				<li><code>$timeStamp</code> is a time stamp in XML Schema format
				(same as used by Atom). This is needed to reduce the ease of developing
				replay attacks.</li>
				<li><code>$URLSignature</code> is the signature of the whole URL
				in bold above using the public key shown below, and encoded in a
			   <a href="http://commons.apache.org/codec/apidocs/org/apache/commons/codec/binary/Base64.html#encodeBase64URLSafeString%28byte[]%29">URL friendly base64</a> encoding.</li>
			</ul>

   <h3>Error responses</h3>
		<p>In case of error the service gets redirected to <pre>$relyingService?error=$code</pre>Where
		$code can be either one of</p>
		<ul>
			<li><code>nocert</code>: when the client has no cert. </li>
			<li><code>noVerifiedWebId</code>: no verified WebId was found in the certificate</li>
			<li><code>noWebId</code>: todo: show this error when there are no webids at all</li>
			<li><code>IdPError</code>: for some error in the IdP setup. Warn
			the IdP administrator!</li>
			<li>other messages, not standardised yet</li>
		</ul>

		<h2>Verifiying the WebId</h2>

		<p>In order for the Relying Party to to be comfortable that the returned WebId
		was not altered in transit, the whole URL is signed by this server as
		shown above. Here are the public keys and algorithms this us using:</p>


		<p>The signature uses the RSA with SHA-1 algorithm.</p>

		<p>The public key used by this service that verifies the signature is: </p>

		<ul>
			<li>Key Type: <pre>{key/RDF.`type`*}</pre></li>
		   <li>public exponent (decimal): <pre>{key/CERT.exponent*}</pre> </li>
		   <li>modulus (decimal):<br/>
			   <pre>{key/CERT.modulus*}</pre>
		   </li>
		</ul>

	</div>
}