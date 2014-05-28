<!doctype html>
<html>
	<head>
		<meta name="layout" content="main"/>
		<title>Index</title>
	</head>
	<body>
		<div style="margin-left: 20px;">
			<h1>IDP selection</h1>
		
			<form action="${request.contextPath}${grailsApplication.config.grails.plugin.springsecurity.saml.loginFormUrl}" method="GET">
		    <%-- We send this attribute to tell the processing filter that we want to initialize login --%>
		    <input type="hidden" name="login" value="true"/>
		    <table>
		        <tr>
		            <td><b>Select IDP: </b></td>
		            <td>
						<g:each in="${applicationContext.getBean('metadata').IDPEntityNames}" var="idpItem">
		                    <input type="radio" name="idp" id="idp_${idpItem}" value="${idpItem}"/>
		                    <label for="idp_${idpItem}">${idpItem}</label>
		                    <br/>						
						</g:each>		            
		            </td>
		        </tr>
		        <tr>
		            <td>&nbsp;</td>
		            <td><input type="submit" value="Login"/></td>
		        </tr>
		    </table>
		</form>	
		</div>	
	</body>
</html>		
