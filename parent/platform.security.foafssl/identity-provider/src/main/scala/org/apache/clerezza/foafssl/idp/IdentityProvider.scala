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

package org.apache.clerezza.foafssl.idp

import org.slf4j.scala.Logging
import java.text.SimpleDateFormat
import java.security.cert._
import org.apache.clerezza.foafssl.ontologies.{RSA, WEBIDPROVIDER, CERT}
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import collection.immutable.StringOps
import org.apache.clerezza.rdf.scala.utils.EasyGraph
import javax.ws.rs._
import core.{MultivaluedMap, UriInfo, Context, Response}
import org.apache.clerezza.platform.security.UserUtil
import org.apache.clerezza.platform.security.auth.WebIdPrincipal
import java.net.{URL, URLEncoder}
import java.security.{Signature, KeyStore}
import org.apache.clerezza.rdf.core.impl.util.Base64
import org.apache.clerezza.jaxrs.utils.RedirectUtil
import collection.mutable.Set
import org.apache.clerezza.rdf.ontologies.FOAF
import org.apache.clerezza.rdf.utils.GraphNode
import org.osgi.service.component.ComponentContext
import javax.xml.ws.RequestWrapper
import org.apache.clerezza.utils.Uri
import org.apache.clerezza.rdf.core.UriRef
import java.lang.reflect.Constructor
import java.lang.Boolean
import com.sun.xml.internal.bind.v2.model.annotation.AnnotationSource
import java.util.{List, Calendar}
import apple.laf.JRSUIState.ValueState


/**
 * A service that allows remote users to authenticate on this
 * server in order to login to remote servers.
 *
 * @author Henry Story, Bruno Harbulot
 */

@Path("/srvc/webidp")
class IdentityProvider extends Logging {

	import org.apache.clerezza.foafssl.ssl.Activator._
	import collection.JavaConversions._
	import org.apache.clerezza.rdf.scala.utils.EasyGraph._

	var keyPair: KeyPair = null

	class KeyPair(val privKey: RSAPrivateKey, val cert: Certificate ) {
		val pubKey = cert.getPublicKey.asInstanceOf[RSAPublicKey]

		val sigAlg = privKey.getAlgorithm match {
						case "RSA" =>  "SHA1withRSA"
						case "DSA" =>  "SHA1withDSA"
						//else will throw a case exception
					}

		val signature = Signature.getInstance(sigAlg)

		signature.initSign(privKey)

	   val eg=  new EasyGraph()

		private def publicKeyGrph = (
			eg.bnode ∈ RSA.RSAPublicKey
				⟝ RSA.modulus ⟶ { val pkstr = pubKey.getModulus.toString(16)
								new StringOps(if (pkstr.size % 2 == 0) pkstr else " "+pkstr).
									  grouped(2).foldRight("")(_+":"+_)^^CERT.hex
					  }
				⟝ RSA.public_exponent ⟶ ( pubKey.getPublicExponent.toString^^CERT.int_  )
			)

			val serviceGraph = (eg.bnode ∈ WEBIDPROVIDER.IDPService
												  ⟝ WEBIDPROVIDER.signingKey ⟶ publicKeyGrph
					)

		def sign(message: String) = synchronized {
			signature.update(message.getBytes("UTF-8"))
		   signature.sign
		}

	}

	/**
	 * finds the public and private key to be used for this service
	 *
	 * Currently finds the key used by TLS. It may be better to use a weaker key that
	 * can be changed more often. The service itself could create such a key and store it in
	 * a personal store
	 */

	protected def activate(context: ComponentContext) {
		try {
			val bundleContext = context.getBundleContext
			val https = bundleContext.getProperty("org.osgi.service.http.secure.enabled")
			if (https != null && "true".equals(https)) {
				val store: KeyStore = getServerCertKeyStore(bundleContext)
				val keypairs = for (alias <- store.aliases()
				                    if store.isKeyEntry(alias);
				                    key = store.getKey(alias, getKeyStorePassword(bundleContext).toCharArray)
					                 if key.isInstanceOf[RSAPrivateKey])
					yield new KeyPair(
						key.asInstanceOf[RSAPrivateKey],
						store.getCertificate(alias)
						)
				if (!keypairs.hasNext) {
					logger.error("Won't be able to sign webid References")
				} else {
					keyPair = keypairs.next()
					if (keypairs.hasNext) {
						logger.warn("More than one key pair available for signing. Could lead to random signing behavior " +
						"between restarts")
					}
				}
			} else {
				logger.warn("Cannot activate foaf+ssl Identity Provider. Server secure port needs to be enabled")
			}
		}



	}


	def displayProfile(ids: Set[WebIdPrincipal], relyingPartySrvc: URL) = {
		val eg = new EasyGraph()
		val profile = (eg.bnode ∈  WEBIDPROVIDER.ProfileSelector
			⟝ FOAF.primaryTopic ⟶* ids.map(f=>f.getWebId)
			⟝ WEBIDPROVIDER.relyingParty ⟶ relyingPartySrvc
			⟝ WEBIDPROVIDER.authLink ⟶ createSignedResponse(ids, relyingPartySrvc)
			)
		Response.ok(profile).build()
	}


	def userPrincipals: Set[WebIdPrincipal] = {
		val subject = UserUtil.getCurrentSubject();
		val principals = subject.getPrincipals collect {
			case wid: WebIdPrincipal => wid
		}
		principals
	}

	/**
	 * Sadly jax-rs does not do pattern matching on attributes passed to select best method
	 * So we do this here in a method.
	 */
	@GET
	def request(@Context uriInfo: UriInfo) {
		val params = asScalaMap[String,java.util.List[String]](uriInfo.getQueryParameters)
		for (keyVal <- params) yield keyVal match {
			case ("authreqissuer",lst) => {}

		}
	}



	def init[T](clzz: Class[T], params: MultivaluedMap[String,String]) = {
		import scala.collection.JavaConversions._
		for (cnstrct <- clzz.getConstructors.sortWith (_.getParameterTypes.size > _.getParameterTypes.size);
			ann = cnstrct.getParameterAnnotations.map(
				_.filter(_.isInstanceOf[QueryParam]).headOption.map(_.asInstanceOf[QueryParam].value))
		) yield {
			ann.zip(cnstrct.getParameterTypes).map((name,clz: Class[_])=>{
				val valStr: List[String] = params.get(name)
				clz.getConstructors.sortWith(_.getParameterTypes.size > _.getParameterTypes.size)
			}

		}

	}

	case class params(@QueryParam("authreqissuer") relyingPartySrvc: Option[URL],
		               @QueryParam("pause") pause: Boolean)

	/**
	 * A very simple GET returns an info page, explaining how the service works and what the public key
	 * is.
	 */
	def infoPage() : Response = {
		Response.ok(keyPair.serviceGraph).build()
	}

	/**
	 * If the authreqissuer field is set then this service will redirect immediately to the
	 * requestor with identity information if it exists
	 * (what should it do if there is none?)
	 */
	def authenticate(@QueryParam("authreqissuer") relyingPartySrvc: URL ): Response = {
		if (null == relyingPartySrvc) return infoPage()
		val url = createSignedResponse(userPrincipals,relyingPartySrvc)
		RedirectUtil.createSeeOtherResponse(url)
	}

	/**
	 * response on get when authrequestissuer and pause is set
	 *
	 * @param pause if true then pause on a profile page to let the user select if he wishes to login
	 */
	def authenticate(@QueryParam("authreqissuer") relyingPartySrvc: URL ,
		     @QueryParam("pause") pause: Boolean): Response = {
		if (pause) displayProfile(userPrincipals,relyingPartySrvc)
		else authenticate(relyingPartySrvc)
	}

	/**
	 * @param verifiedWebIDs
	 *            a list of webIds identifying the user (only the fist will be
	 *            used)
	 * @param replyTo
	 *            the service that the response is sent to
	 * @return the URL of the response with the webid, timestamp appended and
	 *         signed
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	private def createSignedResponse(verifiedWebIDs: scala.collection.Set[WebIdPrincipal], replyTo: URL): URL = {
		var uri = "?"+ verifiedWebIDs.slice(0,3).foldRight("") {
			(wid,str) => "webid="+  URLEncoder.encode(wid.getWebId.getUnicodeString, "UTF-8")+"&"
		}
		uri = uri + "ts=" + URLEncoder.encode(dateFormat.format(Calendar.getInstance.getTime), "UTF-8")
		val signedUri =	uri +"&sig=" + URLEncoder.encode(new String(Base64.encode(keyPair.sign(uri))), "UTF-8")
		return new URL(replyTo,signedUri)
	}

	private val dateFormat: SimpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")


}
