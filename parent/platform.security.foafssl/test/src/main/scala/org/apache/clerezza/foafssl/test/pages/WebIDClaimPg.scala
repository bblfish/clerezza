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

package org.apache.clerezza.foafssl.test.pages

import org.apache.clerezza.platform.typerendering.scala.{XmlResult, SRenderlet}
import org.apache.clerezza.foafssl.test.WebIDTester
import org.apache.clerezza.rdf.scala.utils.Preamble._
import org.apache.clerezza.rdf.core._
import org.apache.clerezza.rdf.scala.utils.RichGraphNode
import org.apache.clerezza.rdf.storage.web.WebProxy
import java.util.Date
import org.apache.clerezza.rdf.ontologies.{DC, RDF, DCTERMS}
import scala.collection.mutable
import xml.Elem
import org.apache.clerezza.foafssl.ontologies._

/**
 * @author bblfish
 * @created: 01/04/2011
 */

class WebIDClaimPg extends SRenderlet {
	def getRdfType() = WebIDTester.testCls

	override def renderedPage(arguments: XmlResult.Arguments) = new XhtmlWebIDClaimPg(arguments, testVocab)

	//TODO a renderlet should not need services,

	private var webProxy: WebProxy = null
	
	private var testVocab : Graph  = null

	protected def bindGraphService(webProxyService: WebProxy ): Unit = {
		this.webProxy = webProxyService
		val ontStr = TEST.THIS_ONTOLOGY.getUnicodeString
		val doc = ontStr.substring(0,ontStr.indexOf('#'))
		testVocab = webProxy.getGraph(new UriRef(doc))
	}

	protected def unbindGraphService(webProxyService: WebProxy): Unit = {
		this.webProxy = null
	}



}

object XhtmlWebIDClaimPg {
   val emptyxml=new scala.xml.Text("")
}

class XhtmlWebIDClaimPg(arguments: XmlResult.Arguments, testOnt: Graph) extends XmlResult(arguments )  {
  resultDocModifier.setTitle("WebId Tests");
	resultDocModifier.addNodes2Elem("head", <style type="text/css">.login {{ visibility:hidden; }}</style> )

	lazy val tests = new RichGraphNode(EARL.Assertion,res.getGraph)/-RDF.`type`


	override def content =
	<div id="tx-content">
	   <h1>WebID Login Test Page</h1>
      <p>This page describes in detail the state of your <a href="http://webid.info/">WebID authentication</a> session
      on {new Date()}. </p>

		<p>{testView(TEST.webidAuthentication) }</p>

		<h2>WebID Claims Tested</h2>
		<p>{testView(TEST.webidClaim) }</p>

		<h2>Certificate Test</h2>
		<p>These tests were run on the certificate sent to us.</p>
		<p>{testView(TEST.certificateOk) }</p>
		<p>{testView(TEST.certificateProvided) }</p>
		<p>{testView(TEST.certificateProvidedSAN) }</p>
		<p>{testView(TEST.certificateDateOk) }</p>
		<p>{testView(TEST.certificatePubkeyRecognised) }</p>
		<p>{testView(TEST.certificateCriticalExtensionsOk) }</p>

		<h2>Profile Tests</h2>
		<p>These tests were run on the profiles fetched</p>
		<p>{testView(TEST.profileOk) }</p>
		<p>{testView(TEST.profileGet) }</p>
		<p>{testView(TEST.profileWellFormed) }</p>
		<p>{testView(TEST.profileAllKeysWellFormed) }</p>
		<p>{testView(TEST.pubkeyRSAModulus) }</p>
		<p>{testView(TEST.pubkeyRSAModulusFunctional) }</p>
		<p>{testView(TEST.pubkeyRSAModulusLiteral) }</p>
		<p>{testView(TEST.pubkeyRSAExponent) }</p>
		<p>{testView(TEST.pubkeyRSAExponentFunctional) }</p>
		<p>{testView(TEST.pubkeyRSAExponentLiteral) }</p>

		<h2>Certificate Sent</h2>
		<p>You sent us <a name="cert">the following certificate</a> in PEM format</p>
		<pre>{new RichGraphNode(CERT.Certificate,res.getGraph)/-RDF.`type`/CERT.base64der*}
		</pre>

		<h2>Further Reference</h2>
	  <p>For very detailed test information to send to support <a href="WebId/n3">download this n3 file</a>.</p>
  </div>



	def selectTest(testNme: UriRef) =  new RichGraphNode(testNme, res.getGraph)/-EARL.test

	def testresult(resource: Resource) = resource match {
		case EARL.passed => <font color="green">passed</font>
		case EARL.failed => <font color="red">failed</font>
		case EARL.untested => <span>untested</span>
		case EARL.inapplicable => <span>inapplicable</span>
		case EARL.cantTell => <span>cannot tell</span>
		case _ => <font>untested</font>
	}

	def testView(testName: UriRef) = {

		<table width="100%" rules="groups">
			<caption>{
				new RichGraphNode(testName,testOnt)/DCTERMS.title*
		  }</caption>
			<thead><tr><td>description</td><td>{new RichGraphNode(testName,testOnt)/DCTERMS.description*}</td></tr></thead>
			{ for ( testNd <- selectTest(testName)) yield {
			val res = testNd/EARL.result
			<tbody>
			<tr><td>subject</td><td>{subjectView(testNd/EARL.subject)}</td></tr>
			<tr><td>test result</td><td>{testresult(res/EARL.outcome!)}</td></tr>
			<tr><td>result description</td><td>{res/DC.description*}</td></tr>
			<tr><td></td><td>{subjectView(res/EARL.pointer)}</td></tr>
			</tbody>
			}}
		</table>

	}

	//TODO: Why does this have to be a lazy val? If it's not a lazy val the node_description is null! (29 Sept 2011, OSX Lion, java 7)
	lazy val node_descriptions = new mutable.HashMap[Resource,Elem]()

	def tag = "pnt"+node_descriptions.size

	var webidclaimnum = 0
	
	def linkTo(node: RichGraphNode) : Elem = {
		node_descriptions.get(node.getNode) match {
			case None => {
				val types = (node/RDF.`type`).map(gn=>gn.getNode)
				if (types.contains(CERT.Certificate)) {
					val res = <a href="#cert">the certificate sent by your browser</a>
					node_descriptions.put(node.getNode,res)
					res
				} 
				else if (types.contains( TEST.WebIDClaim) )  {
					//the first time return the claim & the 2nd time the pointer to the claim (and give them a name)
					val tagname = tag
					val id = node/TEST.claimedIdentity*
					val next = <a href={"#"+tagname}>WebID Claim {id}</a>
					node_descriptions.put(node.getNode,next)
					val first = <span><a name={tag}>claimed identity</a>: {id}<br/>
						key: {linkTo(node/TEST.claimedKey)}
					</span>
					first
				}
				else if (types.contains(LOG.Formula)) {
					webidclaimnum += 1
				   val tagid = "widclaim"+webidclaimnum
					val tagtxt = "WebID Claim n."+{webidclaimnum}
					val first = <span><a name={tagid}>{tagtxt}</a><br/><code>{node/LOG.n3String*}</code></span>
					val other = <a href={"#"+tagid}>{tagtxt}</a>
					node_descriptions.put(node.getNode,other)
					first
				} 
				else if (types.contains(RSA.RSAPublicKey)) {
					<dl>
						<dt>modulus  (hex):</dt><dd>{node/RSA.modulus*}</dd>
						<dt>exponent (dec):</dt><dd>{node/RSA.public_exponent*}</dd>
					</dl>
				}
			   else if (types.contains(TEST.Session)) {
					<span>This TLS session</span>
				}
				else <span>not done yet for a {node/RDF.`type`!}</span>
			}
			case Some(node) => node
		}
	}

	def subjectView(subj: RichGraphNode) = {
		subj! match {
			case lit: Literal => <span>{lit.getLexicalForm}</span>
			case bnode: BNode => linkTo(subj)
			case uri: UriRef => <a href={uri.getUnicodeString}>{uri.getUnicodeString}</a>
		}
	}


}
