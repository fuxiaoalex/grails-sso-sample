security {
	saml {
		userAttributeMappings = ['firstName': 'FirstName', 'lastName': 'LastName', 'email': 'EmailAddress']
		userGroupToRoleMapping = [:]
		active = true
		afterLoginUrl = '/'
		afterLogoutUrl = '/'
		loginFormUrl = '/saml/login'
		userGroupAttribute = "memberOf"
		responseSkew = 60
		idpSelectionPath = '/'
		autoCreate {
			active =  true
			key = 'username'
			assignAuthorities = true
		}
		metadata {
			defaultIdp = 'http://idp.ssocircle.com'
			url = '/saml/metadata'
			//default idp info
			idp{
				file = 'security/idp.xml'
				alias = 'http://idp.ssocircle.com'
			}
			sp {
				file = 'security/sp.xml'
				alias = 'grails_saml_test' 
				defaults{
					local = true
					alias = 'grails_saml_test'
					signingKey = 'ping'
					encryptionKey = 'ping'
					tlsKey = 'ping'
					requireArtifactResolveSigned = false
					requireLogoutRequestSigned = false
					requireLogoutResponseSigned = false
					idpDiscoveryEnabled = true
				}
			}
		}
		keyManager {
			storeFile = 'classpath:security/keystore.jks'
			storePass = 'nalle123'
			passwords = [ ping: 'ping123' ]
			defaultKey = 'ping'
		}
	}
}
