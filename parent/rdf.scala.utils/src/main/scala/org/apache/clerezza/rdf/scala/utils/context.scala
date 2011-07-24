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

package org.apache.clerezza.rdf.scala.utils

import org.apache.clerezza.rdf.core.impl._
import scala.collection.mutable.HashMap
import org.apache.clerezza.rdf.core._
import org.apache.clerezza.rdf.utils.GraphNode._
import org.apache.clerezza.rdf.utils.{GraphNode, UnionMGraph}
import org.apache.clerezza.rdf.ontologies.RDF



/**
 * a context for creating and filling up a given graph.
 *
 * @param graph: a Triple collection
 * @author bblfish, reto
 * @created: 20/04/2011
 */
class context(val graph: MGraph)  {

	def this() = this (new SimpleMGraph())

	/**
	 * create a new bnode
	 */
	protected def bnode = new ContextGraphNode(new BNode)

	private val namedBnodes = new HashMap[String,BNode]

	/**
	 * create a new named bnode based EzGraphNode with the preferred writing style
	 */
	protected def b_(name: String): ContextGraphNode = {
		val b =namedBnodes.get(name) match {
			case Some(bnode) => bnode
			case None => {
				val bn = new BNode
				namedBnodes.put(name, bn);
				bn
			}
		}
		new ContextGraphNode(b)
	}

	/**
	 * creates a graphNode from a resource, with this Graph as backingstore
	 */
	protected implicit def node(resource: Resource) =  new ContextGraphNode(resource)

	/**
	 * creates a graphNode from the uri made of the given string
	 * ( simple syntactic sugar )
	 */
	protected def uri(resource: String) = new ContextGraphNode(new UriRef(resource))



	protected class ContextGraphNode(resource: Resource) extends RichGraphNode(resource,graph) {

		/**
		 * relate the subject via the given relation to....
		 */
		def --(rel: Resource): DashTuple = new DashTuple(rel)

		def --(rel: RichGraphNode): DashTuple = new DashTuple(rel.getNode)


		/**
		 * relate the subject via the inverse of the given relation to....
		 */
		def <--(tuple: ContextGraphNode#DashTuple): RichGraphNode = {
			val inversePropertyRes = tuple.first.getNode
			val inverseProperty: UriRef = inversePropertyRes match {
				case p: UriRef => p
				case _ => throw new RuntimeException("DashTuple must be a UriRef")
			}
			ContextGraphNode.this.addInverseProperty(inverseProperty, tuple.second)
			ContextGraphNode.this
		}

		/**
		 *Sets the RDF:type of the subject */
		def a(rdfclass: UriRef): ContextGraphNode = {
			addProperty(RDF.`type`, rdfclass)
			return this
		}

		/**class for Inverse relations with the current RichGraphNode.ref as object */
		//TODO add support for adding many for symmetry reasons
		//	class InverseDashTuple(rel: DashTuple) {
		//
		//		/**
		//		 * ...to the following non literal
		//		 */
		//		def --(subj: NonLiteral): RichGraphNode = {
		//			RichGraphNode.this.addInverseProperty(rel, subj)
		//			RichGraphNode.this
		//		}
		//
		//		/**
		//		 * ...to the following resource (given as a string)
		//		 */
		//		def --(subj: String): RichGraphNode = --(new UriRef(subj))
		//
		//		/**
		//		 * ...to the following EzGraphNode
		//		 * (useful for opening a new parenthesis and specifying other things in more detail
		//		 */
		//		def --(subj: GraphNode): RichGraphNode = {
		//			--(subj.getNode.asInstanceOf[NonLiteral])
		//		}
		//		// since we can only have inverses from non literals (howto deal with bndoes?)
		//	}

		/**
		 *  class for relations with the current RichGraphNode.ref as subject
		 */
		class DashTuple(val second: Resource) {

			val first = ContextGraphNode.this
			/**
			 * ...to the following non resource
			 */
			def -->(obj: Resource): ContextGraphNode = {
				val property = second match {
					case u: UriRef => u;
					case _ => throw new RuntimeException("Property must be a UriRef")
				}
				ContextGraphNode.this.addProperty(property, obj)
				ContextGraphNode.this
			}


			/**
			 * ...to the EzGraphNode, which is useful for opening a parenthesis.
			 */
			def -->(sub: GraphNode): ContextGraphNode = {
				graph.addAll(sub.getGraph)
				-->(sub.getNode)
			}

			/**
			 * Add one relation for each member of the iterable collection
			 */
			def -->>>(elems: Iterable[GraphNode]): ContextGraphNode = {
				for (res <- elems) -->(res)
				ContextGraphNode.this
			}


			/**
			 * Add one relation for each member of the iterable collection
			 */
			def -->>[T <: Resource](uris: Iterable[T]): ContextGraphNode = {
				for (u <- uris) -->(u)
				ContextGraphNode.this
			}
		}

	}

}


