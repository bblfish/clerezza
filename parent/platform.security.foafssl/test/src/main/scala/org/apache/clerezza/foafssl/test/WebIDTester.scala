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

package org.apache.clerezza.foafssl.test

import org.apache.clerezza.platform.security.UserUtil
import org.osgi.service.component.ComponentContext
import org.apache.clerezza.rdf.utils.GraphNode
import javax.ws.rs._
import org.apache.clerezza.rdf.ontologies._
import org.slf4j.{LoggerFactory, Logger}
import java.security.interfaces.RSAPublicKey
import org.apache.clerezza.rdf.core._
import access.NoSuchEntityException
import impl.{SimpleMGraph, PlainLiteralImpl, TypedLiteralImpl}
import org.apache.clerezza.platform.security.auth.WebIdPrincipal
import org.apache.clerezza.foafssl.auth.{WebIDClaim, Verification, X509Claim}
import java.util.Date
import serializedform.Serializer
import java.io.ByteArrayOutputStream
import javax.security.auth.Subject
import scala.collection.mutable
import scala.collection.immutable
import collection.JavaConversions._
import org.apache.clerezza.platform.users.WebIdGraphsService
import org.apache.clerezza.rdf.scala.utils._
import org.apache.clerezza.foafssl.ontologies._
import collection.JavaConversions._
import java.security.{PublicKey, PrivilegedAction, AccessController}
import org.apache.commons.codec.binary.Base64

/**
 * implementation of (very early) version of test server for WebID so that the following tests
 * can be checked.
 *
 * http://lists.w3.org/Archives/Public/public-xg-webid/2011Jan/0107.html
 *
 * @author bblfish
 */

object WebIDTester {
  val testCls = new UriRef("https://localhost/test/WebID/ont/tests")   //todo: change url
  private val logger: Logger = LoggerFactory.getLogger(classOf[WebIDTester])

}

@Path("/test/WebId")
class WebIDTester {


  protected def activate(componentContext: ComponentContext) = {
    //		configure(componentContext.getBundleContext(), "profile-staticweb");
  }


   /**
	 * return a graph describing the tests that succeeded or failed for this resource
	 */
   @GET
   def getTestAuthentication(): GraphNode = {
	   val subject = UserUtil.getCurrentSubject()
	   return AccessController.doPrivileged(new PrivilegedAction[GraphNode] {
			def run = new CertTests(subject, webIdGraphsService).thisDoc
	   })
   }

//	@GET
//	@Produces(Array("application/xhtml+xml","text/html"))
//	def getTestAuthHtml(): GraphNode = {
//		import WebIDTester._
//		new context {
//			val doc = (
//			bnode.a(FOAF.Document)
//				  .a(testCls)
//				  .a(PLATFORM.HeadedPage)
//			)
//		}.doc
//	}


	@GET
	@Produces(Array("text/n3","text/rdf+n3","text/turtle"))
	@Path("n3")
	def getTestMe_N3() = getTestAuthentication()


	@GET
	@Path("x509")
	@Produces(Array("text/plain"))
	def getTestX509(): String = {
	  val subject = UserUtil.getCurrentSubject();
	  val creds = subject.getPublicCredentials
      if (creds.size == 0) return "No public keys found"
	  return creds.iterator.next match {
	    case x509: X509Claim => "X509 Certificate found. " + x509.cert.toString
	    case other: Any => "no X509 certificate found: found " + other.getClass()
	  }

	}

	private var webIdGraphsService: WebIdGraphsService = null
	protected def bindWebIdGraphsService(webIdGraphsService: WebIdGraphsService): Unit = {
		this.webIdGraphsService = webIdGraphsService
	}

	protected def unbindWebIdGraphsService(webIdGraphsService: WebIdGraphsService): Unit = {
		this.webIdGraphsService = null
	}

}


abstract class ClassMap[T: Manifest]()  {
	def clazz = manifest[T].erasure
	/**
	 * Map the object to the graph
	 * @param obj: the object to map
	 * @param optional reference to a Sommer class for cases where references inside obj need themselves to be mapped
	 */
	 def map(obj: T, sommer: Sommer): GraphNode
}

/**
 * Ties an object to its class explicitly, and verifiably
 */
case class ClassObject[T : Manifest](obj: T) {
	def clazz = manifest[T].erasure
}


/**
 * Framework class to map java objects to graphs
 * TODO: sommer should be a
 */
class Sommer(graph: MGraph)  {
	val java2rdf = new mutable.HashMap[Any, Resource]
	val javaClzzMappers = new mutable.HashMap[Class[_],ClassMap[_]]
	
	def addMapper(classMapper: ClassMap[_]) {
		javaClzzMappers.put(classMapper.clazz, classMapper)
	}
	
	def map(classObj: ClassObject[_]): Option[Resource] = {
		java2rdf.get(classObj.obj) match {
			case res @ Some(_) => res
			case None => {
				val option: Option[ClassMap[_]] = javaClzzMappers.get(classObj.clazz)
				option match {
					case Some(cm: ClassMap[_]) => {
						val triples = cm.map(classObj.obj, this)
						graph.addAll(triples.getGraph)
						java2rdf.put(classObj.obj, triples.getNode)
						Some(triples.getNode)
					}
					case None => None
				}
			}
		}
	}
}



/** All the cert tests are placed here */
class CertTests(subj: Subject, webIdGraphsService: WebIdGraphsService) extends Assertions {
	import WebIDTester._
	
	//TODO: This is really just a mapper from a WebIDClaim to a node, that names it
	case class WIDClaim(node: Resource, webid: Literal, claim: WebIDClaim)


	sommer.addMapper(new ClassMap[X509Claim]() {
		def map(x509c: X509Claim, sommer: Sommer): GraphNode =
				( bnode.a(CERT.Certificate)
		          -- CERT.base64der --> new String(Base64.encodeBase64Chunked(x509c.cert.getEncoded()),"UTF-8")
					 -- CERT.principal_key -->> sommer.map(ClassObject(x509c.cert.getPublicKey))
					 -- LOG.semantics --> ( bnode -- LOG.includes -->> x509c.webidclaims.flatMap(c=>sommer.map(ClassObject(c))))
				)
	})

	sommer.addMapper(new ClassMap[WebIDClaim]() {
		def map(idclaim: WebIDClaim, sommer: Sommer) =
			( bnode.a(TEST.WebIDClaim)
				  -- TEST.claimedIdentity --> { idclaim.webId.getUnicodeString^^XSD.anyURI }
				  -- TEST.claimedKey -->> { sommer.map(ClassObject(idclaim.key)) }
			)
	})
	
	sommer.addMapper(new ClassMap[PublicKey]() {
		def map(pubkey: PublicKey, sommer: Sommer) =
			pubkey match {
				case rsa: RSAPublicKey =>
					 val mod =rsa.getModulus.toString(16)
					 val nicemod = mod.grouped(2).grouped(40).map(_.mkString(" ")).mkString("\n")
					 (bnode.a(RSA.RSAPublicKey)
						-- RSA.modulus --> (nicemod^^CERT.hex )
						-- RSA.public_exponent --> (rsa.getPublicExponent.toString(10)^^CERT.int_ )
						)
				case other => (
					bnode.a(CERT.PublicKey)
					   -- RDFS.comment --> ("We don't have ontologies for this key format. This one is using the algorithm "+other.getAlgorithm)
					)
			}
	})
	

	import EARL.{passed, failed, cantTell, untested}

	/**
	 *  Collection of Sommer mapped certificates. Calculating this also builds the RDF graph for it.
	 *  (Note, this is where specialised mappers may be interesing. All that one need to do is write mappers
	 *   for objects)
	 */
	protected val x509creds = {

		val creds: mutable.Set[X509Claim]= subj.getPublicCredentials(classOf[X509Claim])
		val certProvidedTest = create(TEST.certificateProvided,thisSession)

		val credNodes = for (x509 <- creds) yield sommer.map(ClassObject(x509))

		val eC = creds.size > 0

		certProvidedTest.result(
			if (eC) "Certificate available" else "No Certificate Found",
			if (eC) EARL.passed else EARL.failed
		)

		for (r <- credNodes) certProvidedTest.result.pointer(r)
		
		creds
	};

	protected lazy val now = new Date()

	/**
	 * A node to refer to this session.
	 */
	protected lazy val thisSession = { bnode.a(TEST.Session) }.getNode

	protected val thisDocRef : Resource =
       ( bnode.a(FOAF.Document)    //this should be a relative URI pointing to this document, not a bnode...
				  .a(testCls)
				  .a(PLATFORM.HeadedPage)
               -- DCTERMS.created --> now
		         -- FOAF.primaryTopic --> thisSession
			).getNode


	override lazy val thisDoc = {
		  describeTests
		  toRdf
		  node(thisDocRef)
	}

	/**
	 * Collection of WebID Claims mapped to nodes
	 */
	protected val webidClaims: mutable.Set[WebIDClaim] = x509creds.flatMap(certClaim => {
		val certNode = sommer.map(ClassObject(certClaim)).get

		//
		// Assertion public key
		//
		val testCertKey = create(TEST.certificatePubkeyRecognised, certNode) //we should always have a result here.
		val pk = certClaim.cert.getPublicKey
		//TODO: it is important to use the pk object as the class used by the mapper is currently PublicKey, not the subclasses!!!
		//TODO: improve Sommer, so that it can find the best match
		val pkNode =  sommer.map(ClassObject(pk))
		pk match {
			case rsa: RSAPublicKey => {
				val res = testCertKey.result;
				res.description = "Certificate contains RSA key which is recognised"
				res.outcome = EARL.passed
				res.pointer(pkNode)
			}
			case _ => {
				testCertKey.result.description = "Certificate contains key that is not understood by WebID layer " +
					"Pubkey algorith is " + pk.getAlgorithm
				testCertKey.result.outcome = EARL.failed
				None
			}
		}

		//
		// Assertion of existence of SAN
		//

		val sanInCert = create(TEST.certificateProvidedSAN, certNode)
		
		certClaim.webidclaims.size match {
			case 0 =>
				sanInCert.result("The certificate does not contain any WebIDs in the Subject Alternative Name field.",failed)
			case 1 =>
				sanInCert.result("The certificate contains one WebID in the Subject Alternative Name field.",passed ,
										certClaim.webidclaims.head.webId)
			case _ => {
				sanInCert.result("The certificate contains"+certClaim.webidclaims.size+
				" WebIDs in the Subject Alternative Name field.",passed)
				sanInCert.result.pointers = certClaim.webidclaims.map(_.webId).toSeq
			}
		}

		//
		// Assertion time stamp of certificate
		//
		val dateOkAss = create(TEST.certificateDateOk, certNode)

		val notBefore = certClaim.cert.getNotBefore
		val notAfter = certClaim.cert.getNotAfter

		if (now.before(notBefore)) {
			dateOkAss.result("The certificate will only be valid on "+notBefore+" This type of issue can be due to time " +
				"synchronisation issues accross servers", failed, "tested at "+now)
		} else if (now.after(notAfter)) {
			dateOkAss.result("Certificate validity time expired on "+notAfter, failed, "tested at "+now )
		} else {
			dateOkAss.result("Certificate time is valid. It is between "+notBefore+" and "+notAfter, passed, "tested at "+now)
		}
		
		certClaim.webidclaims
		//TODO, having all this happen in the setting of a variable, that would be easy to get otherwise is odd.
		//TODO perhaps it would be better to move these to methods, placed in an init or in the body of the class (same thing)
	})
	
	
	protected def describeTests() {

		//
		// WebID authentication succeeded
		//
		val principals = for (p <- subj.getPrincipals
		                      if p.isInstanceOf[WebIdPrincipal]) yield p.asInstanceOf[WebIdPrincipal]
		(
		bnode.a(EARL.Assertion)
			-- EARL.test --> TEST.webidAuthentication
			-- EARL.subject -->> x509creds.flatMap(credential => sommer.map(ClassObject(credential)))
			-- EARL.result --> (bnode.a(EARL.TestResult)
						-- DC.description --> {"found " + principals.size + " valid principals"}
						-- EARL.outcome --> {if (principals.size > 0) EARL.passed else EARL.failed}
						-- EARL.pointer -->> principals.map(p => p.getWebId.getUnicodeString^^XSD.anyURI)
						)
		)


		//
		// Iterate through each claim
		//

		for (widc <- webidClaims) {
			import Verification._
			val webidAss = create(TEST.webidClaim, ClassObject(widc)) //todo, we need to add a description of the profileKeys as found in the remote file
			val result = webidAss.result
			result.exceptions = widc.errors
			widc.verified match {
				case Verified => {
					result("claim for WebId " + widc.webId + " was verified", passed)
					claimTests(widc)
				}
				case Failed => {
					result("claim for WebID " + widc.webId + " failed", failed)
					claimTests(widc)
				}
				case Unverified => {
					result("claim for WebId " + widc.webId + " was not verified", untested)
				}
				case Unsupported => {
					result("this webid is unsupported ", cantTell)
				}
			}
		}
	}

	// more detailed tester for claims that passed or failed
	// even tester that succeed could be just succeeding by chance (if public profileKeys are badly written out for eg)
	protected def claimTests(claim: WebIDClaim) {
		val sem: Option[GraphNode] = try {
			Some(new GraphNode(claim.webId, webIdGraphsService.getWebIdInfo(claim.webId).publicProfile)) //webProxy.fetchSemantics(claim.webId, Cache.CacheOnly)
		} catch {
			case e: NoSuchEntityException => None
		}
		val profileXst = create(TEST.profileGet, claim.webId)

		sem match {
			case Some(profile) => {
				if (profile.getGraph.size() > 0) {
					profileXst.result("Profile was fetched. The information about when this was done is not yet very detailed" +
						" in Clerezza.", passed)
					val results = testKeys(profile /- CERT.identity)

		         val allKeysGood = create(TEST.profileAllKeysWellFormed, claim.webId)

					results.fold(true)((a,b)=>a & b) match {
						case true =>
							allKeysGood.result("All keys were found to be good in this profile",passed)
						case false =>
							allKeysGood.result("Some keys were found problematic. This is not necessarily fatal.",failed)
					}

				} else {
					profileXst.result("Profile seems to have been fetched but it contains no machine readable information", cantTell)
				}

			}
			case None => {
				profileXst.result("No profile was found or is in store", failed)
			}
		}

	}

	/**
	 * @param exponentNode the node in the remote profile descrbing the modulus - can be a literal or a resource
	 * @param litRef a resource to the literal as described in the test graph
	 * @return true, if the modulus is recognised as parsing
	 */
	protected def testRSAModulus(modulusNode: RichGraphNode, litRef: Resource):Boolean = {
		val asrtKeyModulusLit = create(TEST.pubkeyRSAModulusLiteral, litRef)
		val asrtKeyMod = create(TEST.pubkeyRSAModulus, litRef)
		val asrtKeyModulusOldFunc = create(TEST.pubkeyRSAModulusOldFunctional,litRef)
		var result = false

		modulusNode! match {
			case ref: NonLiteral => {
				asrtKeyModulusLit.result("the modulus of this key is not described directly as" +
					" a literal. It is currently the preferred practice.", failed)
				val hex = modulusNode / CERT.hex
				if (hex.size == 0) {
					asrtKeyModulusOldFunc.result("no hexadecimal value for the modulus found", failed)
				} else if (hex.size > 1) {
					asrtKeyModulusOldFunc.result((hex.size - 1) + " too many hexadecimal values for " +
						"the modulus found. 1 is enough. If the numbers don't end up matching this is very likely" +
						" to cause random behavior ", failed)
				} else {
					asrtKeyModulusOldFunc.result("one hex value for modulus", EARL.passed)
					val kmres = asrtKeyMod.result
					hex(0) ! match {
						case refh: NonLiteral => {
							asrtKeyMod.result("The modulus is using old notation and it's hex is not " +
								"a literal. Going further would require reasoning engines which it is currently unlikely" +
								"many sites have access to.", failed)
						}
						case lith: Literal => {
							lith match {
								case plainLit: PlainLiteral => {
									if (plainLit.getLanguage != null)
										kmres("keymodulus exists and is parseable", passed)
									else
										kmres("keymodulus exists and is parseable, but has a language tag", passed)
									result = true
								}
								case typedLit: TypedLiteral => {
									if (typedLit.getDataType == null ||
										XSD.string == typedLit.getDataType) {
										kmres("keymodulus exists and is parseable", passed)
										result = true
									} else {
										kmres("keymodulus exists but does not have a string type", failed)
									}
								}
								case lit => {
									// cert:hex cannot be mistyped, since anything that is odd in the string is
									//removed
									kmres("keymodulus exists and is parseable", passed)
									result = true
								}
							}
						}
					}
				}

			}
			case numLit: Literal => {
				val reskeyModLit = asrtKeyModulusLit.result
				numLit match {
					case tl: TypedLiteral => tl.getDataType match {
						case CERT.int_ => {
							try {
								BigInt(tl.getLexicalForm)
								reskeyModLit("Modulus is of type cert:int. It parsed ok.", passed, tl)
								result = true
							} catch {
								case e: NumberFormatException => {
									reskeyModLit("Modulus cert:int failed to parse as one", failed, tl)
								}
							}
						}
						case CERT.decimal => {
							//todo: need to add cert:decimal parsing flexibility to ontology
								reskeyModLit("Modulus is of type cert:decimal. It always parses ok", passed, tl)
								result = true
						}
						case CERT.hex => {
							result = true
							reskeyModLit("Modulus is of type cert:hex. It will always parse to a positive number.", passed, tl)
						}
						case XSD.int_ => {
							try {
								BigInt(tl.getLexicalForm)
								reskeyModLit("Modulus is of type xsd:int. It parsed but it is certainly too small for " +
									"a modulus", failed)
							} catch {
								case e: NumberFormatException => {
									reskeyModLit("Modulus cert:decimal failed to parse", failed, tl)
								}
							}
						}
						case XSD.base64Binary => reskeyModLit("Base 64 binaries are not numbers. If you wish to have " +
							"a base64 integer notation let the WebId Group know. We can define one easily.", failed, tl)
						case XSD.hexBinary => reskeyModLit("Base hex binary literals are not a numbers. If you wish to have a hex " +
							" integer notation use the " + CERT.hex +
							" relation. It is easier for people to write out.", failed, tl)
						case XSD.nonNegativeInteger => {
							try {
								val bi = BigInt(tl.getLexicalForm)
								if (bi >= 0) {
									reskeyModLit("Modulus is declared to be of type non-negative integer and it is", passed, tl)
									result = true
								} else {
									reskeyModLit("Modulus is declared to be of type non-negative integer but it is negative", failed, tl)
								}
							} catch {
								case e: NumberFormatException => {
									reskeyModLit("Modulus xsd:int is very likely too short a number for a modulus. It also " +
										"failed to parse as one", failed, tl)
								}
							}

						}
						case XSD.integer => {
							try {
								BigInt(tl.getLexicalForm)
								reskeyModLit("Modulus is of type xsd:integer. It parsed.", passed, tl)
								result = true
							} catch {
								case e: NumberFormatException => {
									reskeyModLit("Modulus xsd:integer is failed to parse", failed, tl)
								}
							}

						}
						case XSD.positiveInteger => {
							try {
								val bi = BigInt(tl.getLexicalForm)
								if (bi > 0) {
									reskeyModLit("Modulus is declared to be of type positive integer and it is", passed, tl)
									result = true
								} else if (bi == 0) {
									reskeyModLit("Modulus is 0 which is certainly too small", failed, tl)
								} else {
									reskeyModLit("Modulus is declared to be of type positive integer but it is not", failed, tl)
								}
							} catch {
								case e: NumberFormatException => {
									reskeyModLit("Modulus xsd:positiveInteger failed to parse", failed, tl)
								}
							}

						}
						case littype => reskeyModLit("We don't know how to interpret numbers of type " + littype +
							"It would be better to use either cert:hex or cert:int", cantTell, tl)
					}
					case lit: Literal => reskeyModLit("The literal needs to be of a number type, not a string", failed, lit)
				}
			}


			//its ok, and do other modulus verification
		}
		return result
	}


	/**
	 * @param exponentNode the node in the remote profile describing the expontent - can be a literal or a resource
	 * @param litRef a reference to the literal as described in the test graph
	 * @return true if the exponent parses correctly
	 */
	protected def testRSAExp(exponentNode: RichGraphNode, litRef: Resource) : Boolean = {
		val asrtKeyExpLit = create(TEST.pubkeyRSAExponentLiteral, litRef)
		val asrtKeyExp = create(TEST.pubkeyRSAExponent, litRef)
		val asrtKeyExpOldFunc = create(TEST.pubkeyRSAExponentOldFunctional,litRef)
		var result = false

		exponentNode! match {
			case ref: NonLiteral => {
				asrtKeyExpLit.result("the exponent of this key is not described directly as" +
					" a literal. It is currently the preferred practice.", failed)
				val decml = exponentNode / CERT.decimal
				if (decml.size == 0) {
					asrtKeyExpOldFunc.result("no decimal value for the exponent found", failed)
				} else if (decml.size > 1) {
					asrtKeyExpOldFunc.result((decml.size - 1) + " too many decimal values for " +
						"the exponent found. 1 is enough. If the numbers don't end up matching this is very likely" +
						" to cause random behavior ", failed)
				} else {
					asrtKeyExpOldFunc.result("one hex value for modulus", EARL.passed)
					val kExpres = asrtKeyExp.result
					decml(0) ! match {
						case refh: NonLiteral => {
							asrtKeyExp.result("The exponent is using old notation and it's cert:decimal relation is not " +
								"to a literal. Going further would require reasoning engines which it is currently unlikely" +
								"many sites have access to.", failed)
						}
						case lith: Literal => {
							lith match {
								case plainLit: PlainLiteral => {
									if (plainLit.getLanguage != null)
										kExpres("key exponent exists and is parseable", passed)
									else
										kExpres("key exponent exists and is parseable, but has a language tag", passed)
									result = true
								}
								case typedLit: TypedLiteral => {
									if (typedLit.getDataType == null ||
										XSD.string == typedLit.getDataType) {
										kExpres("keymodulus exists and is parseable", passed)
										result = true
									} else {
										kExpres("keymodulus exists but does not have a string type", failed)
									}
								}
								case lit => {
									//todo: can cert:int not be mistyped?
									kExpres("keymodulus exists and is parseable", passed)
								}
							}
						}
					}
				}

			}
			case numLit: Literal => {
				val reskeyExpLit = asrtKeyExpLit.result
				numLit match {
					case tl: TypedLiteral => tl.getDataType match {
						case CERT.int_ => {
							try {
								BigInt(tl.getLexicalForm)
								reskeyExpLit("Exponent is of type cert:int. It parsed ok.", passed, tl)
								result = true
							} catch {
								case e: NumberFormatException => {
									reskeyExpLit("Exponent cert:int failed to parse as one", failed, tl)
								}
							}
						}
						case CERT.hex => {
							reskeyExpLit("Exponent is of type cert:hex. It will always parse to a positive number.", passed, tl)
							result = true
						}
						case CERT.decimal => {
							try {
								BigInt(tl.getLexicalForm)
								reskeyExpLit("Exponent is of type xsd:int. It parsed ok.", passed,tl)
								result = true
							} catch {
								case e: NumberFormatException => {
									reskeyExpLit("Exeponent of type cert:decimal failed to parse", failed, tl)
								}
							}
						}
						case XSD.base64Binary => reskeyExpLit("Base 64 binaries are not numbers. If you wish to have " +
							"a base64 integer notation let the WebId Group know. We can define one easily.", failed, tl)
						case XSD.hexBinary => reskeyExpLit("Base hex binary literals are not a numbers. If you wish to have a hex " +
							" integer notation use the " + CERT.hex +
							" relation. It is easier for people to write out.", failed, tl)
						case XSD.nonNegativeInteger => {
							try {
								val bi = BigInt(tl.getLexicalForm)
								if (bi >= 0) {
									reskeyExpLit("Exponent is declared to be of type non-negative integer and it is", passed, tl)
									result = true
								} else {
									reskeyExpLit("Exponent is declared to be of type non-negative integer but it is negative", failed, tl)
								}
							} catch {
								case e: NumberFormatException => {
									reskeyExpLit("Exponent xsd:nonNegativeInteger failed to parse as one", failed, tl)
								}
							}

						}
						case XSD.integer => {
							try {
								BigInt(tl.getLexicalForm)
								reskeyExpLit("Exponent is of type xsd:integer. It parsed.", passed, tl)
								result = true
							} catch {
								case e: NumberFormatException => {
									reskeyExpLit("Exponent xsd:integer is failed to parse", failed, tl)
								}
							}

						}
						case XSD.positiveInteger => {
							try {
								val bi = BigInt(tl.getLexicalForm)
								if (bi > 0) {
									reskeyExpLit("Exponent is declared to be of type positive integer and it is", passed, tl)
									result = true
								} else if (bi == 0) {
									reskeyExpLit("Exponent is 0 which is certainly too small", failed, tl)
								} else {
									reskeyExpLit("Exponent is declared to be of type positive integer but it is not", failed, tl)
								}
							} catch {
								case e: NumberFormatException => {
									reskeyExpLit("Exponent xsd:positiveInteger failed to parse", failed, tl)
								}
							}

						}
						case littype => reskeyExpLit("We don't know how to interpret numbers of type " + littype +
							"It would be better to use either cert:hex or cert:int", cantTell, tl)
					}
					case lit: Literal => reskeyExpLit("The literal needs to be of a number type, not a string", failed, lit)
				}
			}
		}
		return result
	}


	protected def testKeys(profileKeys: CollectedIter[RichGraphNode]) =
		for (pkey <- profileKeys) yield {
			//
			//create a pointer to this key, so that future tester can refer to it
			//
			val graph: Graph = pkey.getNodeContext
			val sout = Serializer.getInstance()
			val out = new ByteArrayOutputStream(512)
			sout.serialize(out, graph, "text/n3")
			val n3String = out.toString("UTF-8")
			//todo: turtle mime type literal?
			val keylit: GraphNode = bnode.a(LOG.Formula) --  LOG.n3String --> n3String


			//
			// some of the tests we will complete here
			//
			val asrtKeyModulusFunc = create(TEST.pubkeyRSAModulusFunctional, keylit.getNode)
			val asrtKeyExpoFunc = create(TEST.pubkeyRSAExponentFunctional, keylit.getNode)
			val asrtWffkey = create(TEST.profileWellFormedPubkey, keylit.getNode)


			var claimsTobeRsaKey = pkey.hasProperty(RDF.`type`, RSA.RSAPublicKey)

			val mods = pkey / RSA.modulus
			val exps = pkey / RSA.public_exponent

			claimsTobeRsaKey = claimsTobeRsaKey || mods.size > 0 || exps.size > 0

			if (!claimsTobeRsaKey) {
				asrtWffkey.result("Do not recognise the type of this key", cantTell)
			}

			var rsaExpOk, rsaModOk: Boolean = false

			if (mods.size == 0) {
				if (claimsTobeRsaKey) {
					asrtKeyModulusFunc.result("Missing modulus in RSA key", failed)
				}
				else {
					asrtKeyModulusFunc.result("Can't tell if this is an RSA key", cantTell)
				}
			} else if (mods.size > 1) {
				asrtKeyModulusFunc.result("Found more than one modulus. Careful, unless the numbers are" +
					" exactly the same, there is a danger of erratic behavior", failed)
			} else {
				asrtKeyModulusFunc.result("Found one Modulus", passed)

				rsaModOk = testRSAModulus(mods, keylit.getNode)
			}

			if (exps.size == 0) {
				if (claimsTobeRsaKey) {
					asrtKeyExpoFunc.result("Missing exponent in RSA key", failed)
				}
				else {
					asrtKeyExpoFunc.result("Can't tell if this is an RSA key", cantTell)
				}
			} else if (exps.size > 1) {
				asrtKeyExpoFunc.result("Found more than one exponents. Careful, unless the numbers are" +
					" exactly the same, there is a danger of erratic behavior", failed)
				//we could have a problem
			} else {
				asrtKeyExpoFunc.result("Found one Modulus", passed)
				rsaExpOk = testRSAExp(exps, keylit.getNode)
			}

			if (rsaExpOk && rsaModOk) {
				asrtWffkey.result("Modulus and Exponent of key good", passed)
				true
			} else false

		}

}

/**
  * Assertions on tests
  *
  * Assertions created with such an object will be added to the list
  * when describeTests information is added - and only then. This is a convenience
  * to make the Assertions keep track of tests
  *
  * subclass Assertions for specific types of describeTests suites
  */
abstract class Assertions extends context(new SimpleMGraph())  {

	val sommer = new Sommer(graph)
	
   val thisDoc: GraphNode

	var assertions: List[Assertion] = Nil

	protected def add(newAssertion: Assertion) = {
		assertions = newAssertion :: assertions
		newAssertion
	}

	def create(testName: UriRef, subject: Resource) = new Assertion(testName, Seq[Resource](subject))

	def create(testName: UriRef, obj: ClassObject[_]) = {
		sommer.map(obj) match {
			case Some(ref) => new Assertion(testName, Seq[Resource](ref))
			case None => new Assertion(testName,Seq[Resource]())
		}
	}

	def toRdf(): TripleCollection =  {
		for (test <- assertions) {
			test.toRdf()
		}
		graph
	}

	class Assertion(testName: UriRef,
	                subjects: Seq[Resource]) extends context(graph) {

		//only add this describeTests to the list of assertions if there is a result
		//this makes it easier to write code that keeps track of assertions, without ending up having to
		//publish all of them
		lazy val result = {
			add(this)
			new TstResult
		}

		def toRdf() = (
			bnode.a(EARL.Assertion)
				-- EARL.test --> testName
				-- EARL.result --> result.toRdf()
				-- EARL.subject -->> subjects
		)
	}

	class TstResult extends context(graph) {
		var description: String = _
		var outcome: UriRef = _
		var pointers: Seq[Resource] = Nil
		var exceptions: Iterable[java.lang.Throwable] = Nil

		def pointer(point: NonLiteral) {
			pointers = Seq(point)
		}
		
		def pointer(point: Option[Resource]) {
			point match {
				case Some(ref) => pointers = Seq(ref)
				case None => Seq()
			}
		}



		// a method to deal with most usual case
		def apply(desc: String, success: UriRef) {
			description = desc
			outcome = success
		}

		def apply(desc: String, success: UriRef, pointer: Resource) {
			description = desc
			outcome = success
			pointers = Seq(pointer)
		}


		def toRdf() =
				(bnode.a(EARL.TestResult)
					-- DC.description --> description
					-- EARL.outcome --> outcome
					-- EARL.pointer -->> pointers
				   -- EARL.info -->> { for (e <- exceptions) yield new PlainLiteralImpl(e.toString)  }
				)

	}

}
