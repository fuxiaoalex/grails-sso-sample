package com.vmware.nee.saml

import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider
import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.opensaml.xml.parse.BasicParserPool
import org.springframework.security.saml.metadata.ExtendedMetadata
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate

class IdpController {

	def metadata
	
    def index() {
		render view:"index"
	}
	
	def add(params){
		def filename = params?.file?.trim()
		if(filename){
			def file = new File(filename)
			FilesystemMetadataProvider provider = new FilesystemMetadataProvider(file)
			provider.setParserPool(new BasicParserPool())
			provider.initialize()
			MetadataProvider metadataProvider = new ExtendedMetadataDelegate(provider)
			metadata.addMetadataProvider(metadataProvider)
			metadata.setRefreshRequired(true)
			metadata.refreshMetadata()
		}
		redirect action: "list"
	}
	
	def remove(params){
		def entityName = params?.idp?.trim()
		if(entityName){
			metadata.providers.each{
				def name = metadata.parseProvider(it)[0] //if there is multiple entities in provider..This may not be right
				if(name == entityName) metadata.removeMetadataProvider(it)
				metadata.refreshMetadata()
			}
		}
		redirect action: "list"
	}
	
	def list(){
		render view: "list"
	}
}
