<!doctype html>
<html>
	<head>
		<meta name="layout" content="main"/>
		<title>Index</title>
	</head>
	<body>
		<div style="margin-left: 20px;">	
			<h1>Login/Logout</h1>
			<sec:ifLoggedIn>
			     Welcome back, <sec:username/> | <sec:logoutLink local="true">Local logout</sec:logoutLink> | <sec:logoutLink>Global logout</sec:logoutLink>
			     <p>User has the following roles: <sec:ifAnyGranted roles="ROLE_USER">USER</sec:ifAnyGranted></p> 
			</sec:ifLoggedIn>
				
			<sec:ifNotLoggedIn>
				<sec:loginLink>Login (default IDP)</sec:loginLink> | <sec:loginLink selectIdp="true">Login (selecting IDP)</sec:loginLink> 	| <g:link controller="idp" action="list">Manage IDP</g:link>			
			</sec:ifNotLoggedIn>
		</div>	
	</body>
</html>		
