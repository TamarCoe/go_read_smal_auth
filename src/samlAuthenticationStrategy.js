const fs = require('fs')
const path = require('path')
const rp = require('request-promise')
const { Strategy: SamlStrategy } = require('@node-saml/passport-saml')
const { parseIDPMetadataFromFile } = require("metadata-saml2");
const config = require('./config')



const createSamlStrategy = async () => {
  console.log('Getting Identity Provider metadata...')
  const idpMetadata = await parseIDPMetadataFromFile("idp-metadata-stage.xml");
  console.log('Identity Provider metadata parsed sucessfully')
  return new SamlStrategy({
    callbackUrl: "https://go-read-smal-auth.vercel.app/login/callback",
    entryPoint: idpMetadata.HTTPRedirect,
    issuer: "https://go-read-smal-auth.vercel.app/",
    idpCert: idpMetadata.X509Certificates,
    identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    protocol: "https://",
    validateInResponseTo: "never",
    disableRequestedAuthnContext: true,
    passReqToCallback: true,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    additionalParams: { RelayState: "default" }

  }, (req, profile, done,) => {
    console.log("Fdssssssssssssssss")
    const user = {
      displayName: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname'],
      id: profile['http://schemas.education.gov.il/ws/2015/01/identity/claims/zehut'],
      mosad: profile['http://schemas.education.gov.il/ws/2015/01/identity/claims/orgrolesyeshuyot'],
      mosad_2: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/shibutznosaf'],
      mosad_3: profile['http://schemas.education.gov.il/ws/2015/01/identity/claims/studentmosad'],
      isStudent: profile['http://schemas.education.gov.il/ws/2015/01/identity/claims/isstudent'] === 'Yes',
      kita: profile['http://schemas.education.gov.il/ws/2015/01/identity/claims/studentkita']
    }
    console.log(`Logged in 2: ${JSON.stringify(user, ' ', 2)}`)


    return done(null, user)
  })
}

module.exports = createSamlStrategy
