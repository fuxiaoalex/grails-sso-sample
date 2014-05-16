package com.vmware.nee.saml

import grails.plugin.springsecurity.SpringSecurityService

class SamlSecurityService extends SpringSecurityService {

	static transactional = false
	def config

	Object getCurrentUser() {
		def userDetails
		if (!isLoggedIn()) {
			userDetails = null
		} else {
			userDetails = getAuthentication().details
			if ( config?.saml.autoCreate.active ) { 
				userDetails =  getCurrentPersistedUser(userDetails)
			}
		}
		return userDetails
	}
	
	private Object getCurrentPersistedUser(userDetails) {
		if (userDetails) {
			String className = config?.userLookup.userDomainClassName
			String userKey = config?.saml.autoCreate.key
			if (className && userKey) {
				Class<?> userClass = grailsApplication.getDomainClass(className)?.clazz
				return userClass."findBy${userKey.capitalize()}"(userDetails."$userKey")
			}
		} else { return null}
	}
}
