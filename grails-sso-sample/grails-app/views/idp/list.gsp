<!doctype html>
<html>
	<head>
		<meta name="layout" content="main"/>
		<title>Add/Remove Idp</title>
	</head>
	<body>
		<div style="margin-left: 20px;">
			<h1>Add/Remove IDP</h1>
		
			<g:form controller="idp">
		    <%-- We send this attribute to tell the processing filter that we want to initialize login --%>
		    <input type="hidden" name="login" value="true"/>
		    <table>
		        <tr>
		            <td><b>Existing IDPs: </b></td>
		            <td>
						<g:each in="${applicationContext.getBean('metadata').IDPEntityNames}" var="idpItem">
		                    <label for="idp_${idpItem}">${idpItem}</label>
		                    <br/>						
						</g:each>		            
		            </td>
		        </tr>
		        <tr>
		            <td><b>File Location: </b><input type="text" name="file"/></td>
		            <td><g:actionSubmit value="Add" action="add"/></td>
		        </tr>
		        <tr>
		            <td><b>Idp Name: </b><input type="text" name="idp"/></td>
		            <td><g:actionSubmit value="Remove" action="remove"/></td>
		        </tr>
		    </table>
		</g:form>	
		</div>	
	</body>
</html>