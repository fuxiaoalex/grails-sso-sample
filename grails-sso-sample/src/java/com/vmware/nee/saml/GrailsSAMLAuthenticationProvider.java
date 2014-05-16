package com.vmware.nee.saml;

import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

/**
 * A {@link org.springframework.security.saml.SAMLAuthenticationProvider} subclass to return 
 * principal as UserDetails Object. 
 * 
 * @author feroz.panwaskar
 */
public class GrailsSAMLAuthenticationProvider extends SAMLAuthenticationProvider {
	public GrailsSAMLAuthenticationProvider() {
		super();
	}
	
	/**
     * @param credential credential used to authenticate user
     * @param userDetail loaded user details, can be null
     * @return principal to store inside Authentication object
     */
	@Override
    protected Object getPrincipal(SAMLCredential credential, Object userDetail) {
		if (userDetail != null) {
			return userDetail;
		}
        
		return credential.getNameID().getValue();
    }
}
