package com.vmware.nee.saml

import grails.plugin.springsecurity.userdetails.GormUserDetailsService

import org.springframework.beans.BeanUtils
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.userdetails.SAMLUserDetailsService
import org.springframework.dao.DataAccessException

/**
 * A {@link GormUserDetailsService} extension to read attributes from a LDAP-backed 
 * SAML identity provider. It also reads roles from database
 *
 * @author alvaro.sanchez
 */
@SuppressWarnings("deprecation")
class SpringSamlUserDetailsService extends GormUserDetailsService implements SAMLUserDetailsService {
	// Spring bean injected configuration parameters
	String authorityClassName
	String authorityJoinClassName
	String authorityNameField
	Boolean samlAutoCreateActive
	Boolean samlAutoAssignAuthorities = true
	String samlAutoCreateKey
	Map samlUserAttributeMappings
	Map samlUserGroupToRoleMapping
	String samlUserGroupAttribute
	String userDomainClassName

	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
				
		if (credential) {
			String username = getSamlUsername(credential)
			if (!username) {
				throw new UsernameNotFoundException("No username supplied in saml response.")
			}

			def user = generateSecurityUser(username)
			user = mapAdditionalAttributes(credential, user)
			if (user) {
				log.debug "Loading database roles for $username..."
				def authorities = getAuthoritiesForUser(credential)

				def grantedAuthorities = []
				if (samlAutoCreateActive) {
					user = saveUser(user.class, user, authorities)

					//TODO move to function
					Map whereClause = [:]
					whereClause.put "account", user
					Class<?> UserRoleClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz
					UserRoleClass.withTransaction {
						def auths = UserRoleClass.findAllWhere(whereClause).collect { it.role }

						auths.each { authority ->
							grantedAuthorities.add(new GrantedAuthorityImpl(authority."$authorityNameField"))

						}
					}
				}
				else {
					grantedAuthorities = authorities
				}

				return createUserDetails(user, grantedAuthorities)
			} else {
				throw new InstantiationException('could not instantiate new user')
			}
		}
	}

	protected String getSamlUsername(credential) {

		if (samlUserAttributeMappings?.username) {

			def attribute = credential.getAttributeByName(samlUserAttributeMappings.username)
			def value = attribute?.attributeValues?.value
			return value?.first()
		} else {
			// if no mapping provided for username attribute then assume it is the returned subject in the assertion
			return credential.nameID?.value
		}
	}

	protected Object mapAdditionalAttributes(credential, user) {
		samlUserAttributeMappings.each { key, value ->
			def attribute = credential.getAttributeByName(value)
			def samlValue = attribute?.attributeValues?.value
			if (samlValue) {
				user."$key" = samlValue?.first()
			}
		}
		user
	}

	protected Collection<GrantedAuthority> getAuthoritiesForUser(SAMLCredential credential) {
		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthorityImpl>()

		def samlGroups = getSamlGroups(credential)

		if(samlGroups){
			samlGroups.each { groupName ->
				def role = samlUserGroupToRoleMapping.get(groupName)
				def authority = getRole(role)
	
				if (authority) {
					authorities.add(new GrantedAuthorityImpl(authority."$authorityNameField"))
				}
			} 
		}else {
			//no group info returns from SAML assertion 
			authorities.add(new GrantedAuthorityImpl('ROLE_USER'))
		}

		return authorities
	}

	/**
	 * Extract the groups that the user is a member of from the saml assertion.
	 * Expects the saml.userGroupAttribute to specify the saml assertion attribute that holds 
	 * returned group membership data.
	 *
	 * Expects the group strings to be of the format "CN=groupName,someOtherParam=someOtherValue"
	 *
	 * @param credential
	 * @return list of groups
	 */
	protected List getSamlGroups(SAMLCredential credential) {
		def userGroups = []

		if (samlUserGroupAttribute) {
			def attributes = credential.getAttributeByName(samlUserGroupAttribute)

			attributes.each { attribute ->
				attribute.attributeValues?.each { attributeValue ->
					log.debug "Processing group attribute value: ${attributeValue}"

					def groupString = attributeValue.value
					groupString?.tokenize(',').each { token ->
						def keyValuePair = token.tokenize('=')

						if (keyValuePair.first() == 'CN') {
							userGroups << keyValuePair.last()
						}
					}
				}
			}
		}

		userGroups
	}

	private Object generateSecurityUser(username) {
		if (userDomainClassName) {
			Class<?> UserClass = grailsApplication.getDomainClass(userDomainClassName)?.clazz
			if (UserClass) {
				def user = BeanUtils.instantiateClass(UserClass)
				user.username = username
				user.password = "password"
				return user
			} else {
				throw new ClassNotFoundException("domain class ${userDomainClassName} not found")
			}
		} else {
			throw new ClassNotFoundException("security user domain class undefined")
		}
	}

	private def saveUser(userClazz, user, authorities) {
		if (userClazz && samlAutoCreateActive && samlAutoCreateKey && authorityNameField && authorityJoinClassName) {

			Map whereClause = [:]
			whereClause.put "$samlAutoCreateKey".toString(), user."$samlAutoCreateKey"
			Class<?> joinClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz

			userClazz.withTransaction {
				def existingUser = userClazz.findWhere(whereClause)
				if (!existingUser) {
					if (!user.save()) throw new UsernameNotFoundException("Could not save user ${user}");
				} else {
					user = updateUserProperties(existingUser, user)

					if (samlAutoAssignAuthorities) {
						joinClass.removeAll user
					}
					user.save()
				}
				if (samlAutoAssignAuthorities) {
					authorities.each { grantedAuthority ->
						def role = getRole(grantedAuthority."${authorityNameField}")
						joinClass.create(user, role)
					}
				}

			}
		}
		return user
	}

	private Object updateUserProperties(existingUser, user) {
		samlUserAttributeMappings.each { key, value ->
			existingUser."$key" = user."$key"
		}
		return existingUser
	}

	private Object getRole(String authority) {
		if (authority && authorityNameField && authorityClassName) {
			Class<?> Role = grailsApplication.getDomainClass(authorityClassName).clazz
			if (Role) {
				Map whereClause = [:]
				whereClause.put "$authorityNameField".toString(), authority
				Role.findWhere(whereClause)
			} else {
				throw new ClassNotFoundException("domain class ${authorityClassName} not found")
			}
		}
	}
}
