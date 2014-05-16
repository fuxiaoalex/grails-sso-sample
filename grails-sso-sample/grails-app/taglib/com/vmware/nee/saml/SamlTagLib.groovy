package com.vmware.nee.saml

import grails.plugin.springsecurity.SecurityTagLib
import org.springframework.security.saml.SAMLLogoutFilter
import org.codehaus.groovy.grails.commons.GrailsApplication

class SamlTagLib extends SecurityTagLib {

	static final String LOGOUT_SLUG = '/j_spring_security_logout'

	GrailsApplication grailsApplication

	/**
	 * {@inheritDocs}
	 */
	def loggedInUserInfo = { attrs, body ->
		String field = assertAttribute('field', attrs, 'loggedInUserInfo')

		def source = springSecurityService.authentication.details."${field}"

		if (source) {
			out << source.encodeAsHTML()
		}
		else {
			out << body()
		}
	}

	/**
	 * {@inheritDocs}
	 */
	def loginLink = { attrs, body ->
		def contextPath = request.contextPath
		def url = grailsApplication.config.security.saml.loginFormUrl
		def selectIdp = attrs.remove('selectIdp')

		url = "${contextPath}${url}"
		if (!selectIdp) {
			def defaultIdp = grailsApplication.config.grails.plugin.springsecurity.saml.metadata.idp.alias
			url += "?idp=${defaultIdp}"
		}

		def elementClass = generateClassAttribute(attrs)		
		def elementId = generateIdAttribute(attrs)
				
		out << "<a href='${url}'${elementId}${elementClass}>${body()}</a>"
	}

	/**
	 * {@inheritDocs}
	 */
	def logoutLink = { attrs, body ->
		def local = attrs.remove('local')
		def contextPath = request.contextPath

		def url = LOGOUT_SLUG

		def samlEnabled = grailsApplication.config.grails.plugin.springsecurity.saml.active
		if(samlEnabled){
			url = SAMLLogoutFilter.FILTER_URL
		}

		def elementClass = generateClassAttribute(attrs)
		def elementId = generateIdAttribute(attrs)

		out << """<a href='${contextPath}${url}${local?'?local=true':''}'${elementId}${elementClass}>${body()}</a>"""
	}

	private String generateIdAttribute(Map attrs) {
		def elementId = ""
		if (attrs.id) {
			elementId = " id=\'${attrs.id}\'"
		}
		elementId
	}

	private String generateClassAttribute(Map attrs) {
		def elementClass = ""
		if (attrs.class) {
			elementClass = " class=\'${attrs.class}\'"
		}
		elementClass
	}
}
