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
import org.apache.clerezza.foafssl.ontologies.{WEBIDPROVIDER, CERT}
import org.apache.clerezza.rdf.scala.utils._
import javax.ws.rs._
import core._
import org.apache.clerezza.platform.security.UserUtil
import org.apache.clerezza.platform.security.auth.WebIdPrincipal
import org.apache.clerezza.jaxrs.utils.RedirectUtil
import org.osgi.service.component.ComponentContext
import org.bouncycastle.openssl.PEMWriter
import java.io.StringWriter
import org.apache.clerezza.foafssl.auth.X509Claim
import org.apache.clerezza.rdf.core.access.TcManager
import java.security.{PrivilegedAction, AccessController, Signature, KeyStore}
import org.apache.clerezza.rdf.utils.UnionMGraph
import org.apache.clerezza.platform.users.WebIdGraphsService
import org.apache.clerezza.foafssl.ssl.X509TrustManagerWrapperService
import java.net.{URL, URLEncoder}
import java.util.Calendar
import java.security.cert._
import org.apache.commons.codec.binary.Base64
import collection.immutable.{WrappedString, StringOps}
import org.apache.clerezza.rdf.core.impl.SimpleMGraph
import org.apache.clerezza.rdf.core.{Literal, UriRef}
import collection.mutable.WrappedArray
import org.apache.clerezza.rdf.ontologies.{XSD, PLATFORM, FOAF}
import java.security.interfaces.{RSAKey, RSAPrivateKey, RSAPublicKey}
import org.apache.clerezza.rdf.scala.utils


object IdentityProvider {
	def removeHash(uri: UriRef) = {
		val uriStr =uri.getUnicodeString
		val hashpos = uriStr.indexOf("#")
		if (hashpos>0)  new UriRef(uriStr.substring(0,hashpos))
		else uri
	}
	val EMPTY_LIST = new java.util.LinkedList[String]()
}

/**
 * A service that allows remote users to authenticate on this
 * server in order to login to remote servers.
 *
 * @author Henry Story, Bruno Harbulot
 */

@Path("/srv/idp")
class IdentityProvider extends Logging {

	import org.apache.clerezza.foafssl.ssl.Activator._
	import collection.JavaConversions._
	import IdentityProvider._

	var keyPair: KeyPair = null

	class KeyPair(val privKey: RSAPrivateKey, val cert: Certificate ) extends RdfContext {
		val pubKey = cert.getPublicKey.asInstanceOf[RSAPublicKey]

		val sigAlg = privKey.getAlgorithm match {
						case "RSA" =>  "SHA1withRSA"
						case "DSA" =>  "SHA1withDSA"
						//else will throw a case exception
					}

		val signature = Signature.getInstance(sigAlg)

		signature.initSign(privKey)


		val pubKeyPem = {
			val pemw = new StringWriter()
			val pemWriter = new PEMWriter(pemw);
         pemWriter.writeObject(pubKey);
         pemWriter.flush();
			new WrappedString(pemw.toString).linesIterator.filter(s=>(! s.startsWith("---"))).mkString("\n")
		}

		private def publicKeyNode = (
			bnode.a( CERT.RSAPublicKey)
				-- CERT.modulus --> {
						val mod = pubKey.getModulus.toByteArray.dropWhile(_ == 0).map("%02X" format _).mkString
						mod^^XSD.hexBinary
					  }
				-- CERT.exponent --> ( pubKey.getPublicExponent.toString^^XSD.int_  )
//			  -- CERT.base64der --> pubKeyPem
			)

		val serviceGraph = (
				bnode.a( WEBIDPROVIDER.IDPService)
					  .a(PLATFORM.HeadedPage)
						  -- WEBIDPROVIDER.signingKey --> publicKeyNode
					)

		def sign(message: String) = synchronized {
			signature.update(message.getBytes("UTF-8"))
		   signature.sign
		}

	}


  def trySome[T](body: => T): Option[T] =
    try {
      val res = body;
      if (res == null) None else Option(res)
    } catch {
      case _ => None
    }


	/**
	 * finds the public and private key to be used for this service
	 *
	 * Currently finds the key used by TLS. It may be better to use a weaker key that
	 * can be changed more often. The service itself could create such a key and store it in
	 * a personal store
	 */

	protected def activate(context: ComponentContext) {
    val bundleContext = context.getBundleContext
    val https = bundleContext.getProperty("org.osgi.service.http.secure.enabled")
    if (https != null && "true".equals(https)) {
      val store: KeyStore = getServerCertKeyStore(bundleContext)
      val pass = getKeyStorePassword(bundleContext)
      val keypairs =  for (alias <- store.aliases().toList
                           if store.isKeyEntry(alias);
                           key = store.getKey(alias, pass.toCharArray)
                           if key.isInstanceOf[RSAPrivateKey])
      yield new KeyPair(
          key.asInstanceOf[RSAPrivateKey],
          store.getCertificate(alias)
        )
      if (keypairs.size >0) {
        keyPair = keypairs.head
        if (keypairs.size > 1) {
          logger.warn("More than one key pair available for signing. Could lead to random signing behavior " +
            "between restarts")
        }
      } else {
        logger.error("Won't be able to sign webid References")
      }
    }
  }





	/**
   * //this does not seem to work btw, or not very reliably.
   *
	 * server request of client logout using TLS
   *
	 * @param uriInfo path info for this request
	 * @param headers of the request for the Referer field
	 */
	@POST
	@Path("logout")
	def logout(@Context uriInfo: UriInfo, @Context headers: HttpHeaders,
	           @FormParam("certsig") reqCertSig: String,
		        @FormParam("session") reqSession: String,
		        @FormParam("authreqissuer") authreqissuer: String, //
	           @FormParam("rs") rs: String //same as authrequissuer
		       ): Response = {

		val relyingService = if (null != rs && "" != rs ) rs else authreqissuer

		def responseUrl: scala.StringBuilder = {
			val urlbuilder = new StringBuilder(300, "/srv/idp?") //the signature takes a lot of space
			if (relyingService != null) urlbuilder append "rs=" append URLEncoder.encode(relyingService,"UTF-8") append "&"
			urlbuilder
		}


		//1. we only try to break a session when it is shown that the request comes from a page made in the
		//    same session. Ie. we try to only break the session the user wanted breaking.
		val session = headers.getRequestHeader("ssl_session_id")
		val redirectLoc = if (session.contains(reqSession)) {
	      //then we are in the same session and we can break it
	      val subj = UserUtil.getCurrentSubject
		   session.foreach(s=>tlsTM.breakConnectionFor(s,subj))

	      val answerTo = responseUrl

	      //but we pass the signature of this certificate in the response, so that on receiving the redirect request
	      //we can clear the cache, if by that time the certificate has changed - which it should have, since we just
			//broke the session above.
			val sig = subj.getPublicCredentials(classOf[X509Claim]).map(x509c=>
				Base64.encodeBase64URLSafeString(x509c.cert.getSignature))
	      sig.foreach(sig=>answerTo append  "ocs="+sig+"&")
	      answerTo.toString()
      } else {
	      responseUrl.toString()
      }


		//3. set up redirect

		val response = RedirectUtil.createSeeOtherResponse(redirectLoc, uriInfo)

		//4. make sure TCP connection  will be broken
		response.getMetadata.add("Connection","close")

		response
	}


	/**
	 * Display a simple profile of the user gathered from his WebId, with links to allow him to
	 * <ul><li>switch identity</li>
	 *     <li>information to what may be wrong with his WebID Certificate</li>
	 *     <li>a button to login to the Relying Party when satisfied</li>
	 * </ul>
	 *
	 * @param relyingPartySrvc the url to login when satisfied
	 * @param sessions the TLS session used in building this page, passed as a string as
	 *    specified by the "javax.servlet.request.ssl_session_id" attribute in the Servlet 3.0 API.
	 *    This needed so the breaking of the session can be tied to the one shown in displaying this page, and not
	 *    some session that may be the one used when this form is posted to the server
	 */
	def displayProfile(relyingPartySrvc: URL, sessions: Iterable[String], certChange: Option[Boolean]) = {
		val ids=userPrincipals()
		val webids = ids.map(f=>f.getWebId)

		val profiles = AccessController.doPrivileged(new PrivilegedAction[UnionMGraph]() {
			def run() = {
				val graphs =for (uri <- webids) yield {
//					tcManager.getGraph(removeHash(uri))
				   new RichGraphNode(uri, webIdService.getWebIdInfo(uri).publicProfile).getNodeContext
				}
				//todo: UnionMGraph should be changed to make it easier to append a graph to a list
				new UnionMGraph(new SimpleMGraph()::graphs.toList : _*) //put the graphs together and add a buffer in front for writing
			}
		});

		val cnt= new context(profiles) {


			val profileGn: RichGraphNode = (
				bnode.a(WEBIDPROVIDER.ProfileSelector)
					  .a(PLATFORM.HeadedPage)
					-- FOAF.primaryTopic -->> webids
					-- WEBIDPROVIDER.relyingParty --> relyingPartySrvc
					-- WEBIDPROVIDER.authLink --> createSignedResponse(ids, relyingPartySrvc)
				   -- WEBIDPROVIDER.sessionId -->> sessions.map(s=>new EzLiteral(s))
					-- WEBIDPROVIDER.certChanged -->> certChange.map(s=>s: Literal)
				)
		}
		val p=cnt.profileGn
		val rb=Response.ok(p)
		rb.build()
	}


	/**
	 * Entry point for any of the GET requests.
	 * Theses can be either <ul>
	 *  <li> a simple service information page</li>
	 *  <li> a profile viewing page</li>
	 *  <li> or an automatic authentication redirect </li>
	 * </ul>
	 * @param uriInfo passes all the parameter information
	 * @param headers needed for to get the ssl-session id for the profile page
	 */
	@GET
	def request(@Context uriInfo: UriInfo, @Context headers: HttpHeaders): Response = {
		val params: scala.collection.Map[String,java.util.List[String]] = uriInfo.getQueryParameters

		val relyingPartySrvcs = params.getOrElse("rs",params.getOrElse("authreqissuer", EMPTY_LIST)).
			flatMap(v => try {Option(new URL(v))} catch {case _ => None})

		if (Nil == relyingPartySrvcs) infoPage()
		else  {
			val oldSigStr = params.getOrElse("ocs",EMPTY_LIST)
			val change = if (oldSigStr.size() > 0) {
				val oldSig =oldSigStr.map(sig => Base64.decodeBase64(sig):WrappedArray[Byte]).toSet
				val nowSig = x509Creds.map(claim => claim.cert.getSignature: WrappedArray[Byte])
				if (!oldSig.containsAll(nowSig)) { //really these containers contain only one or none
					//then the certificate has been changed, and one can remove the blocking of the old cert from the DB
					//this is in order to avoid having the certificate block changes later
					tlsTM.clearBreak(oldSig.head.array)
					Option(true)
				} else {
					Option(false)
				}
			} else None //there was no request to change
			displayProfile(relyingPartySrvcs.head,headers.getRequestHeader("ssl_session_id"),change)
		}
	}


//	def init[T](clzz: Class[T], params: MultivaluedMap[String,String]) = {
//		import scala.collection.JavaConversions._
//		for (cnstrct <- clzz.getConstructors.sortWith (_.getParameterTypes.size > _.getParameterTypes.size);
//			ann = cnstrct.getParameterAnnotations.map(
//				_.filter(_.isInstanceOf[QueryParam]).headOption.map(_.asInstanceOf[QueryParam].value))
//		) yield {
//			ann.zip(cnstrct.getParameterTypes).map((name,clz: Class[_])=>{
//				val valStr: List[String] = params.get(name)
//				clz.getConstructors.sortWith(_.getParameterTypes.size > _.getParameterTypes.size)
//			}
//
//		}
//
//	}

	/**
	 * A very simple GET returns an info page, explaining how the service works and what the public key
	 * is.
	 */
	def infoPage() : Response = {
		Response.ok(keyPair.serviceGraph).build()
	}


	def userPrincipals(): scala.collection.mutable.Set[WebIdPrincipal] = {
		val subject = UserUtil.getCurrentSubject();
		val principals = subject.getPrincipals collect {
			case wid: WebIdPrincipal => wid
		}
		principals
	}

	def x509Creds() =  asScalaSet(UserUtil.getCurrentSubject.getPublicCredentials(classOf[X509Claim]))

	/**
	 * redirect to the requestor with identity information and sign it
	 * Now that we do logout, the direct method would need to be developed more carefully
	 */
	private def authenticate(relyingPartySrvc: URL): Response = {
		val ids = userPrincipals()
		val url = if (0==ids.size) {
			val creds = x509Creds().iterator
			val uriStr = if (creds.hasNext) "?error=nocert"
			else {
				val claim: X509Claim = creds.next
				if (claim.webidclaims.size == 0) "?error=noWebId"
				else "?error=noVerifiedWebId"
				//todo missing: how to send errors that occur along the line. ie we are missing "?IdPError=..."
			}
			new URL(relyingPartySrvc,uriStr)
		} else {
		  createSignedResponse(userPrincipals,relyingPartySrvc)
		}
		RedirectUtil.createSeeOtherResponse(url.toURI)
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
		var uri = replyTo.toExternalForm+"?"+ verifiedWebIDs.slice(0,3).foldRight("") {
			(wid,str) => "webid="+  URLEncoder.encode(wid.getWebId.getUnicodeString, "UTF-8")+"&"
		}
		uri = uri + "ts=" + URLEncoder.encode(dateFormat.format(Calendar.getInstance.getTime), "UTF-8")
		val signedUri =	uri +"&sig=" + URLEncoder.encode(new String(Base64.encodeBase64URLSafeString(keyPair.sign(uri))), "UTF-8")
		return new URL(signedUri)
	}

	private val dateFormat: SimpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")

	protected var tcManager: TcManager = null;

	protected def bindTcManager(tcManager: TcManager) = {
		this.tcManager = tcManager
	}

	protected def unbindTcManager(tcManager: TcManager) = {
		this.tcManager = null
	}

	protected var webIdService: WebIdGraphsService = _

	protected def bindWebIDService(service: WebIdGraphsService) {
		this.webIdService = service
	}

	protected def unbindWebIDService(service: WebIdGraphsService) {
		this.webIdService = null
	}

	protected var tlsTM: X509TrustManagerWrapperService = _

	protected def bindTLSEndPoint(tlsendpoint: X509TrustManagerWrapperService) {
		this.tlsTM = tlsendpoint
	}

	protected def unbindTLSEndPoint(tlsendpoint: X509TrustManagerWrapperService) {
		this.tlsTM = tlsendpoint
	}

}
