####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################

from binascii import unhexlify
import datetime
import logging
import os
from impacket.krb5 import constants
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap3 import KERBEROS, SASL, Server, Connection, NTLM, ALL
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.operation.bind import bind_operation
from impacket.krb5.asn1 import AP_REQ, AS_REP, Authenticator, TGS_REP, seq_set
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.krb5.ccache import CCache
from pyasn1.codec.der import decoder, encoder
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from pyasn1.type.univ import noValue

"""
Active Directory authentication helper
"""
class ADAuthentication(object):
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aes_key='', kdc=None):
        self.username = username
        self.domain = domain
        if '@' in self.username:
            self.username, self.domain = self.username.rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aes_key = aes_key
        self.kdc = kdc


    def getLDAPConnection(self, hostname='', baseDN='', protocol='ldaps', gc=False):
        if gc:
            # Global Catalog connection
            if protocol == 'ldaps':
                # Ldap SSL
                server = Server("%s://%s:3269" % (protocol, hostname), get_info=ALL)
            else:
                # Plain LDAP
                server = Server("%s://%s:3268" % (protocol, hostname), get_info=ALL)
        else:
            server = Server("%s://%s" % (protocol, hostname), get_info=ALL)
        # ldap3 supports auth with the NT hash. LM hash is actually ignored since only NTLMv2 is used.
        if self.nt_hash != '':
            ldappass = self.lm_hash + ':' + self.nt_hash
        else:
            ldappass = self.password
        ldaplogin = '%s\\%s' % (self.domain, self.username)
        conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=NTLM, receive_timeout=60, auto_range=True)

        # TODO: Kerberos auth for ldap
        if self.kdc is not None:
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=SASL, sasl_mechanism=KERBEROS)
            bound = self.ldap_kerberos(conn, hostname)
        else:
            logging.debug('Authenticating to LDAP server')
            bound = conn.bind()
        if not bound:
            result = conn.result
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and protocol == 'ldap':
                logging.warning('LDAP Authentication is refused because LDAP signing is enabled. '
                                'Trying to connect over LDAPS instead...')
                return self.getLDAPConnection(hostname, baseDN, 'ldaps')
            else:
                logging.error('Failure to authenticate with LDAP! Error %s' % result['message'])
                return None
        return conn
    
    # def check_binding(self, )

    def ldap_kerberos(self, connection, hostname):
        # Hackery to authenticate with ldap3 using impacket Kerberos stack
    
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        # kdc is used, because 
        servername = Principal('ldap/%s' % self.kdc, type=constants.PrincipalNameType.NT_SRV_INST.value)
        kdc_rep = self.tgt['KDC_REP']
        kdc_cipher = self.tgt['cipher']
        kdc_session = self.tgt['sessionKey']
        tgs, cipher, oldSessionKey, sessionkey = getKerberosTGS(servername, self.domain, self.kdc,
                                                                kdc_rep, kdc_cipher, kdc_session)
    
        # Let's build a NegTokenInit with a Kerberos AP_REQ
        blob = SPNEGO_NegTokenInit()
    
        # Kerberos
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]
    
        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])
    
        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    
        opts = []
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)
    
        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.domain
        seq_set(authenticator, 'cname', username.components_to_asn1)
        now = datetime.datetime.utcnow()
    
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)
    
        encodedAuthenticator = encoder.encode(authenticator)
    
        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionkey, 11, encodedAuthenticator, None)
    
        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator
    
        blob['MechToken'] = encoder.encode(apReq)
    
        # From here back to ldap3
        connection.open(read_server_info=False)
        request = bind_operation(connection.version, SASL, None, None, connection.sasl_mechanism, blob.getData())
        response = connection.post_send_single_response(connection.send('bindRequest', request, None))[0]
        connection.result = response
        if response['result'] == 0:
            connection.bound = True
            connection.refresh_server_info()
        return response['result'] == 0
    
    def get_tgt(self):
        """
        Request a Kerberos TGT given our provided inputs.
        """
        print("username is {}".format(self.username))
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        logging.info('Getting TGT for user')
        tgt, cipher, _, session_key = getKerberosTGT(username, self.password, self.domain,
                                                     unhexlify(self.lm_hash), unhexlify(self.nt_hash),
                                                     self.aes_key,
                                                     self.kdc)
        TGT = dict()
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = session_key
        self.tgt = TGT
    
    def load_ccache(self):
        """
        Extract a TGT from a ccache file.
        """
        # If the kerberos credential cache is known, use that.
        krb5cc = os.getenv('KRB5CCNAME')
    
        # Otherwise, guess it.
        if krb5cc is None:
            krb5cc = '/tmp/krb5cc_%u' % os.getuid()
    
        if os.path.isfile(krb5cc):
            logging.debug('Using kerberos credential cache: %s', krb5cc)
        else:
            logging.debug('No Kerberos credential cache file found, manually requesting TGT')
            return False
    
        # Load TGT for our domain
        ccache = CCache.loadFile(krb5cc)
        # print(self.__dict__.items())
        principal = 'krbtgt/%s@%s' % (self.domain.upper(), self.domain.upper())
        # ccache.getCredential('krbtgt/{}@{}'.format('testing.pvt'.upper(),'testing.pvt'.upper()))
        creds = ccache.getCredential(principal, anySPN=False)
        if creds is not None:
            TGT = creds.toTGT()
            # This we store for later
            self.tgt = TGT
            tgt, cipher, session_key = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
            logging.info('Using TGT from cache')
        else:
            logging.debug("No valid credentials found in cache. ")
            return False
    
        # Verify if this ticket is actually for the specified user
        ticket = Ticket()
        decoded_tgt = decoder.decode(tgt, asn1Spec = AS_REP())[0]
        ticket.from_asn1(decoded_tgt['ticket'])
    
        tgt_principal = Principal()
        tgt_principal.from_asn1(decoded_tgt, 'crealm', 'cname')
        expected_principal = '%s@%s' % (self.username.lower(), self.domain.upper())
        if expected_principal != str(tgt_principal):
            logging.warning('Username in ccache file does not match supplied username! %s != %s', tgt_principal, expected_principal)
            return False
        else:
            logging.info('Found TGT with correct principal in ccache file.')
        return True
