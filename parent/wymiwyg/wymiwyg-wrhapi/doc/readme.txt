Web Request Handler Application Programming Interface (WRHAPI)

How is WRHAPI pronounced?

Quite similarly to "we are happy".


Why is this needed, we have servelts?

Servlets provide much more and they have flaws. The goal of wrhapi is to model HTTP-Requests 
and Responses in java, not to provide a component framework or to provide features like 
sessions. Wrhapi is a mininimalitic API, it does not provide multiple methods to access
the same functionality. It provides an abstraction of the concepts of HTTP hiding irrelevant 
transportational details to the application, e.g. the application won't be able to find out the 
casing a header-name had when it went over the network, as HTTP specifies header names to be 
case insensitive, similarly whether multiple values where transferred in multiple header with the 
same name or as different values in the same line is transparent to the applicitation.


WRHAPI is just an API, how is the implemenation returned by WebServerFactory.newInstance() found?
The Jar providing the service has a file META-INF/services/org.wymiwyg.wrhapi.WebServerFactory 
containing the FQN of the implementation.


Does it support filter-chains for handling requests?

Having minimalistic interfaces for requests and responses makes it easier to wrapp, 
howere providing a mechanism for defining handler-chains is out of the scope of wrhapi.


What's the relastion between WRHAPI and RWCF?

RWCF is a component framework allowing to register handlers for different scopes and allowing
chains of handlers. WRHAPI has taken several interfaces from RWCF, a future implementation 
of RWCF will be based on WRHAPI.


How does WRHAPI compare with Restlets?

Don't know.

When is wrhapi used?

Typical usecases include:
- Integrating a webserver into an application
- As foundation for web-components framework
- Any application serving web requests which doesn't want to deal with the concepts of old file based webservers.
