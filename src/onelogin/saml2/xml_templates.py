# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Auth class

Copyright (c) 2010-2018 OneLogin, Inc.
MIT License

Main class of OneLogin's Python Toolkit.

Initializes the SP SAML instance

"""


class OneLogin_Saml2_Templates(object):

    ATTRIBUTE = """
        <saml2:Attribute Name="%s" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml2:AttributeValue xsi:type="xs:string">%s</saml2:AttributeValue>
        </saml2:Attribute>"""

    AUTHN_REQUEST = """\
                <saml2p:AuthnRequest\
                    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"\
                    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"\
                    ID="%(id)s"\
                    Version="2.0"%(provider_name)s%(force_authn_str)s%(is_passive_str)s\
                    IssueInstant="%(issue_instant)s"\
                    Destination="%(destination)s"\
                    AssertionConsumerServiceURL="%(assertion_url)s"%(attr_consuming_service_str)s>\
                    <saml2:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%(entity_id)s</saml2:Issuer>%(nameid_policy_str)s\
                    %(requested_authn_context_str)s\
                </saml2p:AuthnRequest>"""

    LOGOUT_REQUEST = """\
                <saml2p:LogoutRequest\
                xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"\
                xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"\
                ID="%(id)s"\
                Version="2.0"\
                IssueInstant="%(issue_instant)s"\
                Destination="%(single_logout_url)s">\
                    <saml2:Issuer>%(entity_id)s</saml2:Issuer>\
                    %(name_id)s\
                    %(session_index)s\
                </saml2p:LogoutRequest>"""

    LOGOUT_RESPONSE = """\
<saml2p:LogoutResponse
  xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="%(id)s"
  Version="2.0"
  IssueInstant="%(issue_instant)s"
  Destination="%(destination)s"
  InResponseTo="%(in_response_to)s">
    <saml2:Issuer>%(entity_id)s</saml2:Issuer>
    <saml2p:Status>
        <saml2p:StatusCode Value="%(status)s" />
    </saml2p:Status>
</saml2p:LogoutResponse>"""

    MD_CONTACT_PERSON = """\
    <md:ContactPerson contactType="%(type)s">
        <md:GivenName>%(name)s</md:GivenName>
        <md:EmailAddress>%(email)s</md:EmailAddress>
    </md:ContactPerson>"""

    MD_SLS = """\
        <md:SingleLogoutService Binding="%(binding)s"
                                Location="%(location)s" />\n"""

    MD_REQUESTED_ATTRIBUTE = """\
            <md:RequestedAttribute Name="%(req_attr_name)s"%(req_attr_nameformat_str)s%(req_attr_isrequired_str)s%(req_attr_aux_str)s"""

    MD_ATTR_CONSUMER_SERVICE = """\
        <md:AttributeConsumingService index="1">
            <md:ServiceName xml:lang="en">%(service_name)s</md:ServiceName>
%(attr_cs_desc)s%(requested_attribute_str)s
        </md:AttributeConsumingService>\n"""

    MD_ENTITY_DESCRIPTOR = """\
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     %(valid)s
                     %(cache)s
                     entityID="%(entity_id)s">
    <md:SPSSODescriptor AuthnRequestsSigned="%(authnsign)s" WantAssertionsSigned="%(wsign)s" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%(sls)s        <md:NameIDFormat>%(name_id_format)s</md:NameIDFormat>
        <md:AssertionConsumerService Binding="%(binding)s"
                                     Location="%(location)s"
                                     index="1" />
%(attribute_consuming_service)s    </md:SPSSODescriptor>
%(organization)s
%(contacts)s
</md:EntityDescriptor>"""

    MD_ORGANISATION = """\
    <md:Organization>
        <md:OrganizationName xml:lang="%(lang)s">%(name)s</md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="%(lang)s">%(display_name)s</md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="%(lang)s">%(url)s</md:OrganizationURL>
    </md:Organization>"""

    RESPONSE = """\
<saml2p:Response
  xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="%(id)s"
  InResponseTo="%(in_response_to)s"
  Version="2.0"
  IssueInstant="%(issue_instant)s"
  Destination="%(destination)s">
    <saml2:Issuer>%(entity_id)s</saml2:Issuer>
    <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode
          xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
          Value="%(status)s">
        </saml2p:StatusCode>
    </saml2p:Status>
    <saml2:Assertion
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xs="http://www.w3.org/2001/XMLSchema"
        Version="2.0"
        ID="%(assertion_id)s"
        IssueInstant="%(issue_instant)s">
        <saml2:Issuer>%(entity_id)s</saml2:Issuer>
        <saml2:Subject>
            <saml2:NameID
              NameQualifier="%(entity_id)s"
              SPNameQualifier="%(requester)s"
              Format="%(name_id_policy)s">%(name_id)s</saml2:NameID>
            <saml2:SubjectConfirmation Method="%(cm)s">
                <saml2:SubjectConfirmationData
                  NotOnOrAfter="%(not_after)s"
                  InResponseTo="%(in_response_to)s"
                  Recipient="%(destination)s">
                </saml2:SubjectConfirmationData>
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="%(not_before)s" NotOnOrAfter="%(not_after)s">
            <saml2:AudienceRestriction>
                <saml2:Audience>%(requester)s</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement
          AuthnInstant="%(issue_instant)s"
          SessionIndex="%(session_index)s"
          SessionNotOnOrAfter="%(not_after)s">
%(authn_context)s
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
%(attributes)s
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>"""
