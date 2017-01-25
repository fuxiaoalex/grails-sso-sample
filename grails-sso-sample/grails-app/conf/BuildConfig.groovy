grails.servlet.version = "3.0" // Change depending on target container compliance (2.5 or 3.0)
grails.project.class.dir = "target/classes"
grails.project.test.class.dir = "target/test-classes"
grails.project.test.reports.dir = "target/test-reports"
grails.project.work.dir = "target/work"
grails.project.target.level = 1.6
grails.project.source.level = 1.6
//grails.project.war.file = "target/${appName}-${appVersion}.war"

grails.project.fork = [
    // configure settings for compilation JVM, note that if you alter the Groovy version forked compilation is required
    //  compile: [maxMemory: 256, minMemory: 64, debug: false, maxPerm: 256, daemon:true],

    // configure settings for the test-app JVM, uses the daemon by default
    test: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, daemon:true],
    // configure settings for the run-app JVM
    run: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, forkReserve:false],
    // configure settings for the run-war JVM
    war: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, forkReserve:false],
    // configure settings for the Console UI JVM
    console: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256]
]

grails.project.dependency.resolver = "maven" // or ivy
grails.project.dependency.resolution = {
    // inherit Grails' default dependencies
    inherits("global") {
        // specify dependency exclusions here; for example, uncomment this to disable ehcache:
        // excludes 'ehcache'
    }
    log "error" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    checksums true // Whether to verify checksums on resolve
    legacyResolve false // whether to do a secondary resolve on plugin installation, not advised and here for backwards compatibility

    repositories {
        inherits true // Whether to inherit repository definitions from plugins

        grailsPlugins()
        grailsHome()
        mavenLocal()
        grailsCentral()
        mavenCentral()
		mavenRepo "http://repo.spring.io/milestone/"
		
        // uncomment these (or add new ones) to enable remote dependency resolution from public Maven repositories
        //mavenRepo "http://repository.codehaus.org"
        //mavenRepo "http://download.java.net/maven/2/"
        //mavenRepo "http://repository.jboss.com/maven2/"
    }

    dependencies {
        // specify dependencies here under either 'build', 'compile', 'runtime', 'test' or 'provided' scopes e.g.
        // runtime 'mysql:mysql-connector-java:5.1.24'
		compile('commons-httpclient:commons-httpclient:3.1') {
			excludes 'commons-codec', 'commons-logging', 'junit'
		}

		compile('ca.juliusdavies:not-yet-commons-ssl:0.3.9') {
			excludes 'commons-httpclient', 'log4j'
		}

		compile('org.opensaml:opensaml:2.6.1') {
			excludes 'commons-codec', 'commons-collections', 'commons-lang', 'esapi', 'jcip-annotations', 'jcl-over-slf4j', 'joda-time', 'jul-to-slf4j', 'junit', 'log4j-over-slf4j', 'logback-classic', 'openws', 'serializer', 'servlet-api', 'slf4j-api', 'spring-core', 'spring-mock', 'testng', 'velocity', 'xalan', 'xercesImpl', 'xml-apis', 'xml-resolver', 'xmlunit'
		}

		compile('org.opensaml:xmltooling:1.3.4') {
			excludes 'bcprov-jdk15', 'commons-codec', 'jcip-annotations', 'jcl-over-slf4j', 'joda-time', 'jul-to-slf4j', 'junit', 'log4j-over-slf4j', 'logback-classic', 'not-yet-commons-ssl', 'serializer', 'slf4j-api', 'testng', 'xalan', 'xercesImpl', 'xml-apis', 'xml-resolver', 'xmlsec', 'xmlunit'
		}

		compile('org.apache.velocity:velocity:1.7') {
			excludes 'ant', 'commons-collections', 'commons-lang', 'commons-logging', 'hsqldb', 'jdom', 'junit', 'log4j', 'logkit', 'oro', 'servlet-api', 'werken-xpath'
		}

		compile 'joda-time:joda-time:1.6.2'

		compile('org.opensaml:openws:1.4.4') {
			excludes 'commons-codec', 'commons-httpclient', 'jcip-annotations', 'jcl-over-slf4j', 'joda-time', 'jul-to-slf4j', 'junit', 'log4j-over-slf4j', 'logback-classic', 'serializer', 'servlet-api', 'slf4j-api', 'spring-core', 'spring-mock', 'testng', 'xalan', 'xercesImpl', 'xml-apis', 'xml-resolver', 'xmltooling', 'xmlunit'
		}

		compile 'org.bouncycastle:bcprov-jdk15:1.45'

		compile 'org.apache.santuario:xmlsec:1.4.4'

		compile('org.owasp.esapi:esapi:2.0.1') {
			excludes 'antisamy', 'bsh-core', 'commons-beanutils-core', 'commons-collections', 'commons-configuration', 'commons-fileupload', 'commons-io', 'jsp-api', 'junit', 'log4j', 'servlet-api', 'xom'
		}

        compile 'commons-collections:commons-collections:3.2.1'
		compile('org.springframework.security.extensions:spring-security-saml2-core:1.0.0.RC2') {
            excludes 'spring-security-core'
            excludes 'spring-security-web'
        }
	}

    plugins {
        // plugins for the build system only
        build ":tomcat:7.0.47"

        // plugins for the compile step
        compile "org.grails.plugins:scaffolding:2.1.2"
        //compile 'org.grails.plugins:cache:1.1.8'
		compile "org.grails.plugins:spring-security-core:2.0.0"

        // plugins needed at runtime but not for compilation
        runtime ":hibernate:3.6.10.6" // or ":hibernate4:4.1.11.6"
        runtime ":database-migration:1.3.8"
        runtime "org.grails.plugins:jquery:1.11.1"
        runtime "org.grails.plugins:resources:1.2.14"
        // Uncomment these (or add new ones) to enable additional resources capabilities
        //runtime ":zipped-resources:1.0.1"
        //runtime ":cached-resources:1.1"
        //runtime ":yui-minify-resources:0.1.5"
    }
}
