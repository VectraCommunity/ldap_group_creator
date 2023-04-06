import vat.vectra as vectra
import requests
import logging
import yaml
import os
import sys
import ldap3.core.exceptions
import ldap3.utils.dn
import ssl
from ldap3 import Server, Connection, SAFE_SYNC, Tls, NTLM, KERBEROS
from ssl import CERT_NONE, PROTOCOL_TLSv1_2
from logging.handlers import TimedRotatingFileHandler
from logging.handlers import TimedRotatingFileHandler
from requests.packages.urllib3.exceptions import InsecureRequestWarning


__author__ = "Aurélien Hess"
__copyright__ = "Copyright 2022, Vectra AI"
__credits__ = []
__license__ = "GPL"
__version__ = "1.0"
__maintainer__ = "Aurélien Hess"
__email__ = "ahess@vectra.ai"
__status__ = "Production"


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)


class LDAPClient():
    def __init__(self, server_url:str, base_dn:str, username:str, password:str) -> None:
        self.logger = logging.getLogger('LDAPClient')
        server = Server(server_url)
        try:
            self.connection = Connection(
                server=server, 
                user=username, 
                password=password, 
                auto_bind=True
            )
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            self.logger.error('Cannot connect to LDAP server: {}'.format(str(e)))
            exit(99)
        self.base_dn = base_dn
        
    def get_domain_controllers(self) -> list:
        self.connection.search(
            search_base=f'OU=Domain Controllers,{self.base_dn}', 
            search_filter='(objectCategory=computer)'
            )
        results = set()
        for entry in self.connection.response:
            base_name = ldap3.utils.dn.parse_dn(entry['dn'])[0][1]
            results.add(base_name)
        return list(results)


class VectraGroupManager(vectra.VectraClientV2_2):
    def __init__(self, vectra_appliance_url:str, api_token:str)->None:
        self.logger = logging.getLogger('ADGroupCreator')
        #self.hosts = self._load_all_hosts()
        super().__init__(url=vectra_appliance_url, token=api_token)

    def _load_all_hosts(self)->dict:
        """
        Get a dict of all host_id:host_name
        """
        self.logger.info('Loading all hosts into memory for Regex matching')
        # Limit to hosts with active traffic to reduce memory footprint
        host_generator = self.get_all_hosts(has_active_traffic=True, page_size='5000', fields='id,name')
        count = 0
        results = {}
        for page in host_generator:
            count += 1
            self.logger.debug('Processed page {} of hosts'.format(str(count)))
            for host in page.json()['results']:
                results[host['id']] = host['name']
        return results

    def _get_host_id_advanced_search(self, hostname:str) -> set:
        matching_hosts = []
        r = self.advanced_search(stype='hosts', page_size=50, query='host.name:"{dn}" OR host.name:{dn}.*'.format(dn=hostname))
        for page in r:
            for host in page.json()['results']:
                matching_hosts.append(host)
        if len(matching_hosts) > 1:
            self.logger.warning('More than one host found matching dn {}'.format(hostname))
        return set([host['id'] for host in matching_hosts])
        
    def get_matching_host_ids(self, ldap_hostnames:list, use_regex=False)->list:
        host_ids = set()
        if use_regex:
            raise NotImplementedError()
        else:
            for hostname in ldap_hostnames:
                host_ids.update(self._get_host_id_advanced_search(hostname=hostname))
        return list(host_ids)

    def manage_groups(self, group_name:str, description:str, host_ids:list)->None:
        # See if there is already a group with that name
        response = self.get_all_groups(name=group_name, type='host')
        group = None
        for page in response:
            for g in page.json()['results']:
                # We want exact matching
                if g['name'] == group_name:
                    group = g
                    break
        if group: 
            group_id = group['id']
            self.logger.info('Found a matching group with ID {}'.format(str(group_id)))
            self.update_group(
                group_id=group_id,
                name=group_name,
                description=description,
                members=list(host_ids),
                append=False
                )
            self.logger.info('Group {} updated'.format(group_name))
        # If the group does not exist yet, create it
        else:
            self.logger.info('No group found matching name {}'.format(group_name))
            response = self.create_group(
                name=group_name,
                description=description,
                type='host',
                members=list(host_ids)
                )
            new_group_id = response.json()['group']['id']
            self.logger.info('Created new group with ID {}'.format(str(new_group_id)))


if __name__ == "__main__":
    # Read the configuration
    with open(os.path.dirname(os.path.abspath(sys.modules[__name__].__file__))+"/config.yaml", 'r') as stream:
        try:
            config=yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    
    # Logging setup
    if config['log']['log_to_file']:
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s %(levelname)s %(name)s - %(message)s', 
            datefmt='%Y-%m-%d %H:%M:%S', 
            handlers=[TimedRotatingFileHandler(config['log']['log_file'], when="w0", interval=1, backupCount=config['log']['log_backups'], encoding='utf-8')]
            )
    else:
        logging.basicConfig(level=logging.INFO)    
    logger = logging.getLogger('ADGroupCreator')
    vgm = VectraGroupManager(
        vectra_appliance_url=config['vectra']['url'], 
        api_token=config['vectra']['api_token']
        )

    ldap_client = LDAPClient(
        server_url=config['ldap']['url'], 
        base_dn=config['ldap']['base_dn'], 
        username=config['ldap']['ldap_user'], 
        password=config['ldap']['ldap_password']
        )
    
    logger.info('Retrieving Domain Controllers from AD')
    domain_controllers = ldap_client.get_domain_controllers()
    logger.info('Got {} domain controller object'.format(str(len(domain_controllers))))
    host_ids = vgm.get_matching_host_ids(domain_controllers)
    vgm.manage_groups(group_name='Domain Controllers', description='Group automatically synced from Active Directory', host_ids=host_ids)
