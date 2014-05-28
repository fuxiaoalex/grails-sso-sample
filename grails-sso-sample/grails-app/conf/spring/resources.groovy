import org.codehaus.groovy.grails.compiler.GrailsClassLoader;

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.SecurityFilterPosition

import org.springframework.core.io.ClassPathResource;

import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationFailureHandler

import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.saml.SAMLBootstrap
import org.springframework.security.saml.SAMLEntryPoint
import org.springframework.security.saml.SAMLProcessingFilter
import org.springframework.security.saml.SAMLLogoutFilter
import org.springframework.security.saml.SAMLDiscovery
import org.springframework.security.saml.SAMLLogoutProcessingFilter
import org.springframework.security.saml.websso.WebSSOProfileOptions
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl
import org.springframework.security.saml.websso.WebSSOProfileImpl
import org.springframework.security.saml.websso.WebSSOProfileECPImpl
import org.springframework.security.saml.websso.SingleLogoutProfileImpl
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl
import org.springframework.security.saml.processor.HTTPPostBinding
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding
import org.springframework.security.saml.processor.HTTPArtifactBinding
import org.springframework.security.saml.processor.HTTPSOAP11Binding
import org.springframework.security.saml.processor.HTTPPAOS11Binding
import org.springframework.security.saml.processor.SAMLProcessorImpl
import org.springframework.security.saml.metadata.ExtendedMetadata
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate
import org.springframework.security.saml.metadata.MetadataDisplayFilter
import org.springframework.security.saml.metadata.MetadataGenerator
import org.springframework.security.saml.metadata.CachingMetadataManager
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.util.VelocityFactory
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider
import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.opensaml.xml.parse.BasicParserPool
import org.apache.commons.httpclient.HttpClient

import com.vmware.nee.saml.SpringSamlUserDetailsService
import com.vmware.nee.saml.GrailsSAMLAuthenticationProvider
import com.vmware.nee.saml.SamlTagLib
import com.vmware.nee.saml.SamlSecurityService;

beans = {
	
	def conf = SpringSecurityUtils.securityConfig
	if (!conf || !conf.active) { return }

	SpringSecurityUtils.loadSecondaryConfig 'SamlSecurityConfig'
	conf = SpringSecurityUtils.securityConfig
	if (!conf.saml.active) { return }
	
	
	println 'Configuring Spring Security SAML ...'

	//Due to Spring DSL limitations, need to import these beans as XML definitions
	def beansFile = "classpath:security/springSecuritySamlBeans.xml"
	delegate.importBeans beansFile
	
	xmlns context:"http://www.springframework.org/schema/context"
	context.'annotation-config'()
	context.'component-scan'('base-package': "org.springframework.security.saml")
	
	SpringSecurityUtils.registerProvider 'samlAuthenticationProvider'
	SpringSecurityUtils.registerLogoutHandler 'successLogoutHandler'
	SpringSecurityUtils.registerLogoutHandler 'logoutHandler'

	
	successRedirectHandler(SavedRequestAwareAuthenticationSuccessHandler) {
		alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
		defaultTargetUrl = conf.saml.afterLoginUrl
	}
	
	successLogoutHandler(SimpleUrlLogoutSuccessHandler) {
		defaultTargetUrl = conf.saml.afterLogoutUrl
	}
	
	samlLogger(SAMLDefaultLogger)
	
	keyManager(JKSKeyManager,
		conf.saml.keyManager.storeFile, conf.saml.keyManager.storePass, conf.saml.keyManager.passwords, conf.saml.keyManager.defaultKey)
	
	samlEntryPoint(SAMLEntryPoint) {
		println "Entry point process url is ${conf.saml.loginFormUrl}"
		filterProcessesUrl = conf.saml.loginFormUrl 						// '/saml/login'
		defaultProfileOptions = ref('webProfileOptions')
	}
	
	webProfileOptions(WebSSOProfileOptions) {
		includeScoping = false
	}
	
//	metadataFilter(MetadataDisplayFilter) {
//		println "metadataFilter process url: ${conf.saml.metadata.url }"
//		filterProcessesUrl = conf.saml.metadata.url 		    //'/saml/metadata'
//	}
//	
//	metadataGenerator(MetadataGenerator)
		
	log.debug "Defining the default idp metadata provider... "
	def idpResource
	def idpFile = conf.saml.metadata.idp.file
	
	if(idpFile){
		idpResource = new ClassPathResource(idpFile)	
		defaultIdpMetadata(ExtendedMetadataDelegate) { extMetaDataDelegateBean ->
			idpMetadataProvider(FilesystemMetadataProvider) { bean ->
				bean.constructorArgs = [idpResource.getFile()]
				parserPool = ref('parserPool')
			}

			extMetaDataDelegateBean.constructorArgs = [ref('idpMetadataProvider')]
			
		}
	}
	
	def spFile = conf.saml.metadata.sp.file
	if (spFile) {
		def spResource = new ClassPathResource(spFile)
		spMetadata(ExtendedMetadataDelegate) { spMetadataBean ->
			spMetadataProvider(FilesystemMetadataProvider) { spMetadataProviderBean ->
				spMetadataProviderBean.constructorArgs = [spResource.getFile()]
				parserPool = ref('parserPool')
			}
			
			def spDefaults = conf.saml.metadata.sp.defaults
			spMetadataDefaults(ExtendedMetadata) { extMetadata ->
				local = spDefaults.local
				alias = spDefaults.alias
				signingKey = spDefaults.signingKey
				encryptionKey = spDefaults.encryptionKey
				tlsKey = spDefaults.tlsKey
				requireArtifactResolveSigned = spDefaults.requireArtifactResolveSigned
				requireLogoutRequestSigned = spDefaults.requireLogoutRequestSigned
				requireLogoutResponseSigned = spDefaults.requireLogoutResponseSigned
				idpDiscoveryEnabled = spDefaults.idpDiscoveryEnabled
			}
			
			spMetadataBean.constructorArgs = [ref('spMetadataProvider'), ref('spMetadataDefaults')]
		}	
	}

	metadata(CachingMetadataManager,[ref('spMetadata'), ref('defaultIdpMetadata')]){
		hostedSPName = conf.saml.metadata.sp?."alias"
		defaultIDP = conf.saml.metadata.defaultIdp
	}
		
	userDetailsService(SpringSamlUserDetailsService) {
		grailsApplication = ref('grailsApplication')
		authorityClassName = conf.authority.className
		authorityJoinClassName = conf.userLookup.authorityJoinClassName
		authorityNameField = conf.authority.nameField
		samlAutoCreateActive = conf.saml.autoCreate.active
		samlAutoAssignAuthorities = conf.saml.autoCreate.assignAuthorities
		samlAutoCreateKey = conf.saml.autoCreate.key
		samlUserAttributeMappings = conf.saml.userAttributeMappings
		samlUserGroupAttribute = conf.saml.userGroupAttribute
		samlUserGroupToRoleMapping = conf.saml.userGroupToRoleMapping
		userDomainClassName = conf.userLookup.userDomainClassName
	}
	
	samlAuthenticationProvider(GrailsSAMLAuthenticationProvider) {
		userDetails = ref('userDetailsService')
		hokConsumer = ref('webSSOprofileConsumer')
	}
	
	contextProvider(SAMLContextProviderImpl)
	
	samlProcessingFilter(SAMLProcessingFilter) {
		authenticationManager = ref('authenticationManager')
		authenticationSuccessHandler = ref('successRedirectHandler')
		sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
		authenticationFailureHandler = ref('authenticationFailureHandler')
	}
	
	authenticationFailureHandler(AjaxAwareAuthenticationFailureHandler) {
		redirectStrategy = ref('redirectStrategy')
		defaultFailureUrl = conf.failureHandler.defaultFailureUrl //'/login/authfail?login_error=1'
		useForward = conf.failureHandler.useForward // false
		ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
		exceptionMappings = conf.failureHandler.exceptionMappings // [:]
	}
	
	redirectStrategy(DefaultRedirectStrategy) {
		contextRelative = conf.redirectStrategy.contextRelative // false
	}

	sessionFixationProtectionStrategy(SessionFixationProtectionStrategy)
	
	logoutHandler(SecurityContextLogoutHandler) {
		invalidateHttpSession = true
	}
	
	samlLogoutFilter(SAMLLogoutFilter,
		ref('successLogoutHandler'), ref('logoutHandler'), ref('logoutHandler'))
	
	samlLogoutProcessingFilter(SAMLLogoutProcessingFilter,
		ref('successLogoutHandler'), ref('logoutHandler'))
	
	webSSOprofileConsumer(WebSSOProfileConsumerImpl){
		responseSkew = conf.saml.responseSkew
	}
	
	webSSOprofile(WebSSOProfileImpl)
	
	ecpprofile(WebSSOProfileECPImpl)
	
	logoutprofile(SingleLogoutProfileImpl)
	
	postBinding(HTTPPostBinding, ref('parserPool'), ref('velocityEngine'))
	
	redirectBinding(HTTPRedirectDeflateBinding, ref('parserPool'))
	
	artifactBinding(HTTPArtifactBinding,
		ref('parserPool'),
		ref('velocityEngine'),
		ref('artifactResolutionProfile')
	)
	
	artifactResolutionProfile(ArtifactResolutionProfileImpl, ref('httpClient')) {
		processor = ref('soapProcessor')
	}
	
	httpClient(HttpClient)
	
	soapProcessor(SAMLProcessorImpl, ref('soapBinding'))
	
	soapBinding(HTTPSOAP11Binding, ref('parserPool'))
	
	paosBinding(HTTPPAOS11Binding, ref('parserPool'))
	
	bootStrap(SAMLBootstrap)
	
	velocityEngine(VelocityFactory) { bean ->
		bean.factoryMethod = "getEngine"
	}
	
	parserPool(BasicParserPool)
	
	securityTagLib(SamlTagLib) {
		springSecurityService = ref('springSecurityService')
		webExpressionHandler = ref('webExpressionHandler')
		webInvocationPrivilegeEvaluator = ref('webInvocationPrivilegeEvaluator')
	}
	
	springSecurityService(SamlSecurityService) {
		config = conf
		authenticationTrustResolver = ref('authenticationTrustResolver')
		grailsApplication = ref('grailsApplication')
		passwordEncoder = ref('passwordEncoder')
		objectDefinitionSource = ref('objectDefinitionSource')
		userDetailsService = ref('userDetailsService')
		userCache = ref('userCache')
	}

	println '...finished configuring Spring Security SAML'
}
