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
		autoCreate {
			active =  true
			key = 'username'
			assignAuthorities = true
		}
		metadata {
			defaultIdp = 'http://idp.ssocircle.com'
			url = '/saml/metadata'
			idp{
				file = 'security/idp.xml'
				alias = 'http://idp.ssocircle.com'
			}
			sp {
				file = 'security/sp.xml'
				alias = 'grails_saml_test' 
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
