# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Authn_Request class

Copyright (c) 2010-2018 OneLogin, Inc.
MIT License

AuthNRequest class of OneLogin's Python Toolkit.

"""

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates


class OneLogin_Saml2_Authn_Request(object):
    """

    This class handles an AuthNRequest. It builds an
    AuthNRequest object.

    """

    def __init__(self, settings, force_authn=False, is_passive=False, set_nameid_policy=True):
        """
        Constructs the AuthnRequest object.

        :param settings: OSetting data
        :type settings: OneLogin_Saml2_Settings

        :param force_authn: Optional argument. When true the AuthNRequest will set the ForceAuthn='true'.
        :type force_authn: bool

        :param is_passive: Optional argument. When true the AuthNRequest will set the Ispassive='true'.
        :type is_passive: bool

        :param set_nameid_policy: Optional argument. When true the AuthNRequest will set a nameIdPolicy element.
        :type set_nameid_policy: bool
        """
        self.__settings = settings

        sp_data = self.__settings.get_sp_data()
        idp_data = self.__settings.get_idp_data()
        security = self.__settings.get_security_data()

        uid = OneLogin_Saml2_Utils.generate_unique_id()
        self.__id = uid
        issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

        destination = idp_data['singleSignOnService']['url']

        provider_name_str = ''
        organization_data = settings.get_organization()
        if isinstance(organization_data, dict) and organization_data:
            langs = organization_data
            if 'en-US' in langs:
                lang = 'en-US'
            else:
                lang = sorted(langs)[0]

            display_name = 'displayname' in organization_data[lang] and organization_data[lang]['displayname']
            if display_name:
                provider_name_str = "\n" + '    ProviderName="%s"' % organization_data[lang]['displayname']

        force_authn_str = ''
        if force_authn is True:
            force_authn_str = "\n" + '    ForceAuthn="true"'

        is_passive_str = ''
        if is_passive is True:
            is_passive_str = "\n" + '    IsPassive="true"'

        nameid_policy_str = ''
        if set_nameid_policy:
            name_id_policy_format = sp_data['NameIDFormat']
            if security['wantNameIdEncrypted']:
                name_id_policy_format = OneLogin_Saml2_Constants.NAMEID_ENCRYPTED

            nameid_policy_str = """
    <saml2p:NameIDPolicy
        Format="%s"
        AllowCreate="true" />""" % name_id_policy_format

        requested_authn_context_str = ''
        if security['requestedAuthnContext'] is not False:
            authn_comparison = 'exact'
            if 'requestedAuthnContextComparison' in security.keys():
                authn_comparison = security['requestedAuthnContextComparison']

            if security['requestedAuthnContext'] is True:
                requested_authn_context_str = """    <saml2p:RequestedAuthnContext Comparison="%s">
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>""" % authn_comparison
            else:
                requested_authn_context_str = '     <saml2p:RequestedAuthnContext Comparison="%s">' % authn_comparison
                for authn_context in security['requestedAuthnContext']:
                    requested_authn_context_str += '<saml2:AuthnContextClassRef>%s</saml2:AuthnContextClassRef>' % authn_context
                requested_authn_context_str += '    </saml2p:RequestedAuthnContext>'

        attr_consuming_service_str = ''
        if 'attributeConsumingService' in sp_data and sp_data['attributeConsumingService']:
            attr_consuming_service_str = "\n    AttributeConsumingServiceIndex=\"1\""

        request = OneLogin_Saml2_Templates.AUTHN_REQUEST % \
            {
                'id': uid,
                'provider_name': provider_name_str,
                'force_authn_str': force_authn_str,
                'is_passive_str': is_passive_str,
                'issue_instant': issue_instant,
                'destination': destination,
                'assertion_url': sp_data['assertionConsumerService']['url'],
                'entity_id': sp_data['entityId'],
                'nameid_policy_str': nameid_policy_str,
                'requested_authn_context_str': requested_authn_context_str,
                'attr_consuming_service_str': attr_consuming_service_str,
            }

        self.__authn_request = request

    def get_request(self, deflate=True):
        """
        Returns unsigned AuthnRequest.
        :param deflate: It makes the deflate process optional
        :type: bool
        :return: AuthnRequest maybe deflated and base64 encoded
        :rtype: str object
        """
        if deflate:
            request = OneLogin_Saml2_Utils.deflate_and_base64_encode(self.__authn_request)
        else:
            request = OneLogin_Saml2_Utils.b64encode(self.__authn_request)
        return request

    def get_id(self):
        """
        Returns the AuthNRequest ID.
        :return: AuthNRequest ID
        :rtype: string
        """
        return self.__id

    def get_xml(self):
        """
        Returns the XML that will be sent as part of the request
        :return: XML request body
        :rtype: string
        """
        return self.__authn_request
