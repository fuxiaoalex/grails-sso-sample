package com.vmware.nee.saml

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.saml.SAMLDiscovery

class newSAMLDiscovery extends SAMLDiscovery {
	
	protected void sendIDPSelection(HttpServletRequest request, HttpServletResponse response, String responseURL, String returnParam) throws IOException, ServletException {
		response.sendRedirect(request.getContextPath() + getIdpSelectionPath());
	}
}
