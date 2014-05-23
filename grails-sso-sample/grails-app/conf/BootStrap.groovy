import com.vmware.nee.saml.Account
import com.vmware.nee.saml.Role
import com.vmware.nee.saml.AccountRole
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.SecurityFilterPosition

class BootStrap {

    def init = { servletContext ->
		SpringSecurityUtils.clientRegisterFilter 'samlEntryPoint', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 1
//		SpringSecurityUtils.clientRegisterFilter 'metadataFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 2
		SpringSecurityUtils.clientRegisterFilter 'samlProcessingFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 3
		SpringSecurityUtils.clientRegisterFilter 'samlLogoutFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 4
		SpringSecurityUtils.clientRegisterFilter 'samlLogoutProcessingFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 5
		SpringSecurityUtils.clientRegisterFilter 'samlIDPDiscovery', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 6
		
		
		def adminRole = new Role(authority: 'ROLE_ADMIN').save(flush: true)
		def userRole = new Role(authority: 'ROLE_USER').save(flush: true)

		assert Role.count() == 2
    }
    def destroy = {
    }
}
