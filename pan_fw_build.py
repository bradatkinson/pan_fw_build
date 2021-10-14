#!/usr/bin/env python3
#
#  AUTHOR: Brad Atkinson
#    DATE: 10/6/2020
# PURPOSE: To perform initial build tasks on a firewall

import sys
import time
from panos import base
from panos import device
from panos import policies
from panos import network
import config


def connect_device(fw_ip, num):
    """Connect To Device

    Returns:
        fw_conn (PanDevice): A panos object for device
        num (int): An integer of 0 or 1 representing the device in a list
    """
    if num == 0:
        hostname = config.hostname1
    elif num == 1:
        hostname = config.hostname2

    print('\nConnecting to {}...'.format(hostname))
    username = config.paloalto['username']
    password = config.paloalto['password']
    try:
        fw_conn = base.PanDevice.create_from_device(
            hostname=fw_ip,
            api_username=username,
            api_password=password)
        print('-- Connected')
        return fw_conn
    except:
        print('Host was unable to connect to device. Please check '
              'connectivity to device.\n', file=sys.stderr)
        sys.exit(1)


def get_device_config_settings(fw_conn):
    """Get Device Config Settings

    Args:
        fw_conn (PanDevice): A panos object for device

    Returns:
        results (Element): XML results from firewall
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system")
    results = fw_conn.xapi.get(xpath=base_xpath)
    return results


def process_device_config_settings(results):
    """Process Device Config Settings

    Args:
        results (Element): XML results from firewall

    Returns:
        device_settings_list (list): A list of config setting string values from the firewall
    """
    try:
        hostname = results.find('./result/system/hostname').text
        timezone = results.find('./result/system/timezone').text
        dns_primary = results.find('./result/system/dns-setting/servers/primary').text
        dns_secondary = results.find('./result/system/dns-setting/servers/secondary').text
        pano_primary = results.find('./result/system/panorama/local-panorama/panorama-server').text
        pano_secondary = results.find('./result/system/panorama/local-panorama/panorama-server-2').text
        ntp_primary = results.find('./result/system/ntp-servers/primary-ntp-server/ntp-server-address').text
        ntp_secondary = results.find('./result/system/ntp-servers/secondary-ntp-server/ntp-server-address').text
        device_setttings_list = [hostname, timezone, dns_primary, dns_secondary, pano_primary, pano_secondary, ntp_primary, ntp_secondary]
    except AttributeError:
        device_setttings_list = ['', '', '', '', '', '', '', '']

    return device_setttings_list


def set_device_config_settings(fw_conn, num, device_settings_list, needs_commit):
    """Set Device Config Settings

    Args:
        fw_conn (PanDevice): A panos object for device
        num (int): An integer of 0 or 1 representing the device in a list
        device_settings_list (list): A list of config setting string values from the firewall
        needs_commit (bool): True or false if configuration needs committing

    Returns:
        needs_commit (bool): True or false if configuration needs committing
    """
    print('Applying management configs...')

    if num == 0:
        hostname = config.hostname1
        config_settings_list = config.device1_settings_list
    elif num == 1:
        hostname = config.hostname2
        config_settings_list = config.device2_settings_list

    if device_settings_list == config_settings_list:
        print('-- Already applied')
    else:
        fw_settings = device.SystemSettings(
            hostname=hostname,
            timezone=config.timezone,
            panorama=config.pano_primary,
            panorama2=config.pano_secondary,
            dns_primary=config.dns_primary,
            dns_secondary=config.dns_secondary)
        fw_conn.add(fw_settings)
        fw_settings.create()

        base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                    "/deviceconfig/system/ntp-servers/primary-ntp-server")
        entry_element = ('<ntp-server-address>{}</ntp-server-address>'.format(config.ntp_primary))
        fw_conn.xapi.set(xpath=base_xpath, element=entry_element)

        base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                    "/deviceconfig/system/ntp-servers/secondary-ntp-server")
        entry_element = ('<ntp-server-address>{}</ntp-server-address>'.format(config.ntp_secondary))
        fw_conn.xapi.set(xpath=base_xpath, element=entry_element)
        print('-- Applied')
        needs_commit = True

    return needs_commit


def get_security_rulebase(fw_conn):
    """Get Security Rules

    Args:
        fw_conn (PanDevice): A panos object for device

    Returns:
        rule_list (list): List of security rules
        rulebase (object): A panos object for Rulebase
    """
    rulebase = policies.Rulebase()
    fw_conn.add(rulebase)
    rule_list = policies.SecurityRule.refreshall(rulebase)
    return rule_list, rulebase


def remove_default_rule(rule_list, rulebase, needs_commit):
    """Remove Default Security Rule

    Args:
        rule_list (list): List of security rules
        rulebase (object): A panos object for Rulebase
        needs_commit (bool): True or false if configuration needs committing

    Returns:
        needs_commit (bool): True or false if configuration needs committing
    """
    for rule in rule_list:
        if rule.name == 'rule1':
            rulebase.add(policies.SecurityRule(name='rule1')).delete()
            needs_commit = True

    return needs_commit


def get_fw_setting(fw_conn, items_xpath):
    """Get FW Setting Info

    Args:
        fw_conn (PanDevice): A panos object for device
        items_xpath (str): The items xpath for the setting

    Returns:
        xml_data (Element): XML data from firewall
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  + items_xpath)
    xml_data = fw_conn.xapi.get(xpath=base_xpath)
    return xml_data


def process_xml(xml_data, path):
    """Process XML Data

    Args:
        xml_data (Element): XML data from firewall
        path (str): A string containing the path to the expected result

    Returns:
        item_list (list): List of item names
    """
    xml_list = xml_data.findall(path)
    item_list = []
    for item in xml_list:
        item_list.append(item.attrib.get('name'))
    return item_list


def remove_default_setting(fw_conn, item_list, needs_commit):
    """Remove Default Setting

    Args:
        fw_conn (PanDevice): A panos object for device
        item_list (list): List of item names
        needs_commit (bool): True or false if configuration needs committing

    Returns:
        needs_commit (bool): True or false if configuration needs committing
    """
    for item in item_list:
        if item == 'default':
            fw_conn.add(network.VirtualRouter(name='default')).delete()
            needs_commit = True
        elif item == 'default-vwire':
            fw_conn.add(network.VirtualWire(name='default-vwire')).delete()
            needs_commit = True
        elif item == 'untrust':
            fw_conn.add(network.Zone(name='untrust')).delete()
            needs_commit = True
        elif item == 'trust':
            fw_conn.add(network.Zone(name='trust')).delete()
            needs_commit = True
        elif item == 'ethernet1/1':
            fw_conn.add(network.interface(name='ethernet1/1')).delete()
            needs_commit = True
        elif item == 'ethernet1/2':
            fw_conn.add(network.interface(name='ethernet1/2')).delete()
            needs_commit = True

    return needs_commit


def fetch_licenses(fw_conn):
    """Fetch Licenses

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    try:
        fw_conn.fetch_licenses_from_license_server()
        print('Licenses retrieved from Palo Alto Networks')
        return True
    except:
        print('WARNING: Not able to retrieve licenses!')
        return False


def enable_multivsys(fw_conn):
    """Enable Multi-vsys

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    command = '<set><system><setting><multi-vsys>on</multi-vsys></setting></system></set>'
    fw_conn.op(cmd=command, cmd_xml=False)


def process_multivsys(results):
    """Process Multi-vsys Info

    Args:
        results (Element): XML results from firewall

    Returns:
        multivsys_status (str): A string containing the status of multi-vsys
    """
    multivsys_status = results.find('./result/system/multi-vsys').text
    return multivsys_status


def configuring_multivsys(fw_conn):
    """Configuring Multi-vsys

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    system_info_results = get_system_info(fw_conn)
    multivsys_status = process_multivsys(system_info_results)

    if multivsys_status == 'off':
        print('Enabling multi-vsys...')
        enable_multivsys(fw_conn)
        system_info_results = get_system_info(fw_conn)
        multivsys_status = process_multivsys(system_info_results)
        print('--- Multi-vsys is {}'.format(multivsys_status))
        time.sleep(30)
    else:
        print('Multi-vsys is already enabled!')


def get_system_info(fw_conn):
    """Get System Info

    Args:
        fw_conn (PanDevice): A panos object for device

    Returns:
        results (Element): XML results from firewall
    """
    results = fw_conn.op(cmd='show system info')
    return results


def process_system_info(results):
    """Process System Info

    Args:
        results (Element): XML results from firewall

    Returns:
        app_version (str): A string containing the App-ID version
        panos_version (str): A string containing the PAN-OS version
    """
    app_version = results.find('./result/system/app-version').text
    panos_version = results.find('./result/system/sw-version').text
    return app_version, panos_version


def check_content_updates(fw_conn):
    """Check Content Updates

    Args:
        fw_conn (PanDevice): A panos object for device

    Returns:
        results (Element): XML results from firewall
    """
    results = fw_conn.op(cmd='request content upgrade check')
    return results


def process_content_updates(results):
    """Process Content Updates

    Args:
        results (Element): XML results from firewall

    Returns:
        max_app_version (str): A string containing the latest App-ID version
    """
    app_version_list = []
    version_list = results.findall('./result/content-updates/entry')
    for version in version_list:
        app_version = version.find('./version').text
        app_version_list.append(app_version)
    max_app_version = max(app_version_list)
    return max_app_version


def update_content(fw_conn, command):
    """Update App-ID Content

    Args:
        fw_conn (PanDevice): A panos object for device
        command (str): Command for content update

    Returns:
        results (Element): XML output containing the job ID
    """
    results = fw_conn.op(cmd=command, cmd_xml=False)
    return results


def process_jobid(results):
    """Process Job ID Results

    Args:
        results (Element): XML output containing the job ID

    Returns:
        job_id (str): The job ID number
    """
    job_id = results.find('./result/job').text
    return job_id


def check_job(fw_conn, job_id):
    """Check Job Status

    Args:
        fw_conn (PanDevice): A panos object for device
        job_id (str): The job ID number
    """
    status = 'PEND'
    while status == 'PEND':
        job_results = get_job_status(fw_conn, job_id)
        status = process_job_status(job_results)
        time.sleep(10)

        if status == 'FAIL':
            print('Commit or Update failed. Check the system logs on '
                  'the device.', file=sys.stderr)
            sys.exit(1)


def get_job_status(fw_conn, job_id):
    """Get Job ID Status

    Args:
        fw_conn (PanDevice): A panos object for device
        job_id (str): The job ID number

    Returns:
        results (Element): XML output containing the job ID status details
    """
    command = '<show><jobs><id>' + job_id + '</id></jobs></show>'
    results = fw_conn.op(cmd=command, cmd_xml=False)
    return results


def process_job_status(results):
    """Process Job Status Results

    Args:
        results (Element): XML output containing the job ID status details

    Returns:
        status (str): The job ID status
    """
    status = results.find('./result/job/result').text
    return status


def commit_config(fw_conn):
    """Commit Configuration

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    results = fw_conn.commit()
    return results


def check_ha_state(fw_conn):
    """Check HA State

    Args:
        fw_conn (PanDevice): A panos object for device

    Returns:
        results (Element): XML results from firewall
    """
    command = 'show high-availability state'
    results = fw_conn.op(cmd=command)
    return results


def process_ha_state(results):
    """Process HA State Results

    Args:
        results (Element): XML results from firewall

    Returns:
        state (str): A string containing the HA enabled state
    """
    state = results.find('./result/enabled').text
    return state


def enable_ha(fw_conn):
    """Enable HA

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability")
    entry_element = "<enabled>yes</enabled>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_group_id(fw_conn):
    """Set HA Group ID

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    group_id = '1'
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group")
    entry_element = "<group-id>{}</group-id>".format(group_id)
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha_mode_ap(fw_conn):
    """HA Mode Active/Passive

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group/mode")
    entry_element = "<active-passive/>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_passive_link_state(fw_conn):
    """Set Passive Link State To Auto

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group/mode/active-passive")
    entry_element = "<passive-link-state>auto</passive-link-state>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha_mode_aa(fw_conn):
    """HA Mode Active/Active

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group/mode")
    entry_element = "<active-active/>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_device_id(fw_conn, num):
    """Set Device ID

    Args:
        fw_conn (PanDevice): A panos object for device
        num (int): An integer of 0 or 1 representing the device in a list
    """
    if num == 0:
        device_id = '0'
    elif num == 1:
        device_id = '1'

    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group/mode/active-active")
    entry_element = "<device-id>{}</device-id>".format(device_id)
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha1_peer_ip(fw_conn, num):
    """Set HA1 Peer IP

    Args:
        fw_conn (PanDevice): A panos object for device
        num (int): An integer of 0 or 1 representing the device in a list
    """
    if num == 0:
        peer_ip = '1.1.1.2'
    elif num == 1:
        peer_ip = '1.1.1.1'

    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group")
    entry_element = "<peer-ip>{}</peer-ip>".format(peer_ip)
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha1_backup_peer_ip(fw_conn, num):
    """Set HA1 Backup Peer IP

    Args:
        fw_conn (PanDevice): A panos object for device
        num (int): An integer of 0 or 1 representing the device in a list
    """
    if num == 0:
        peer_ip = '1.1.1.6'
    elif num == 1:
        peer_ip = '1.1.1.5'

    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group")
    entry_element = "<peer-ip-backup>{}</peer-ip-backup>".format(peer_ip)
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def enable_heartbeat_backup(fw_conn):
    """Enable Heartbeat Backup

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group/election-option")
    entry_element = "<heartbeat-backup>yes</heartbeat-backup>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha_timer(fw_conn):
    """Set HA Timer Settings

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group/election-option"
                  "/timers")
    entry_element = "<recommended/>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha1_interface(fw_conn, num):
    """Set HA1 Interface

    Args:
        fw_conn (PanDevice): A panos object for device
        num (int): An integer of 0 or 1 representing the device in a list
    """
    if num == 0:
        ip_addr = '1.1.1.1'
    elif num == 1:
        ip_addr = '1.1.1.2'

    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/interface/ha1")
    entry_element = ("<ip-address>{}</ip-address>"
                     "<netmask>255.255.255.252</netmask>"
                     "<port>ha1-a</port>".format(ip_addr))
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha1_backup_interface(fw_conn, num):
    """Set HA1 Backup Interface

    Args:
        fw_conn (PanDevice): A panos object for device
        num (int): An integer of 0 or 1 representing the device in a list
    """
    if num == 0:
        ip_addr = '1.1.1.5'
    elif num == 1:
        ip_addr = '1.1.1.6'

    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/interface/ha1-backup")
    entry_element = ("<ip-address>{}</ip-address>"
                     "<netmask>255.255.255.252</netmask>"
                     "<port>ha1-b</port>".format(ip_addr))
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha2_interface(fw_conn):
    """Set HA3 Interface

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/interface/ha2")
    entry_element = "<port>hsci</port>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha3_interface(fw_conn):
    """Set HA3 Interface

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/interface/ha3")
    entry_element = "<port>hsci</port>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def set_ha2_keep_alive_split_datapath(fw_conn):
    """Set HA2 Keep Alive Split-Datapath

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/high-availability/group/state-synchronization"
                  "/ha2-keep-alive")
    entry_element = "<enabled>yes</enabled><action>split-datapath</action>"
    fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def configure_ha(fw_conn, num):
    """Configure HA

    Args:
        fw_conn (PanDevice): A panos object for device
        num (int): An integer of 0 or 1 representing the device in a list
    """
    print('Configuring HA...')
    enable_ha(fw_conn)
    set_group_id(fw_conn)
    set_ha1_peer_ip(fw_conn, num)
    set_ha1_backup_peer_ip(fw_conn, num)

    if config.mode == "Active/Passive":
        set_ha_mode_ap(fw_conn)
        set_passive_link_state(fw_conn)
    elif config.mode == "Active/Active":
        set_ha_mode_aa(fw_conn)
        set_device_id(fw_conn, num)
        set_ha2_keep_alive_split_datapath(fw_conn)

    enable_heartbeat_backup(fw_conn)
    set_ha_timer(fw_conn)
    try:
        set_ha1_interface(fw_conn, num)
        set_ha1_backup_interface(fw_conn, num)
    except:
        print('WARNING: Check interface port used for HA1/HA1 Backup')
    print('-- Configured')


def get_ciphers(fw_conn, service):
    """Get Ciphers

    Args:
        fw_conn (PanDevice): A panos object for device
        service (str): A string containing either mgmt or ha for ciphers

    Returns:
        results (Element): XML results from firewall
    """
    base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                  "/deviceconfig/system/ssh/ciphers/{}".format(service))
    results = fw_conn.xapi.get(xpath=base_xpath)
    return results


def process_ciphers(results, service):
    """Process Ciphers

    Args:
        results (Element): XML results from firewall
        service (str): A string containing either mgmt or ha for ciphers

    Returns:
        set_ciphers_list (list): A list of ciphers already set on the firewall
    """
    set_ciphers_list = []
    xml_list = results.findall('./result/{}/'.format(service))

    for item in xml_list:
        set_ciphers_list.append(item.tag)

    return set_ciphers_list


def set_ciphers(fw_conn, service, cipher_list):
    """Set SSH Ciphers

    Args:
        fw_conn (PanDevice): A panos object for device
        service (str): A string containing either mgmt or ha for ciphers
        cipher_list (list): A list of approved ciphers
    """
    for cipher in cipher_list:
        base_xpath = ("/config/devices/entry[@name='localhost.localdomain']"
                      "/deviceconfig/system/ssh/ciphers/{}".format(service))
        entry_element = ('<{}/>'.format(cipher))
        fw_conn.xapi.set(xpath=base_xpath, element=entry_element)


def restart_service(fw_conn):
    """Restart Mgmt & HA Services

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    command = ('<set><ssh><service-restart><mgmt>'
               '</mgmt></service-restart></ssh></set>')
    results = fw_conn.op(cmd=command, cmd_xml=False)

    xml_list = results.findall('.')

    for item in xml_list:
        status_dict = item.attrib
        status = status_dict.get('status')
        message = item.find('./result/member').text
        print('-- {}...  {}'.format(message, status))


def remediate_ciphers(fw_conn):
    """Remediate SSH Ciphers

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    print('Remediating weak SSH ciphers...')
    service_list = ('mgmt', 'ha')
    cipher_list = ('aes128-ctr', 'aes192-ctr', 'aes256-ctr',
                   'aes128-gcm', 'aes256-gcm')

    for service in service_list:
        cipher_results = get_ciphers(fw_conn, service)
        set_ciphers_list = process_ciphers(cipher_results, service)

        if list(cipher_list) == set_ciphers_list:
            print('-- Ciphers already set')
            return

        set_ciphers(fw_conn, service, cipher_list)

    commit_jobid = commit_config(fw_conn)
    check_job(fw_conn, commit_jobid)
    restart_service(fw_conn)
    print('-- Remediated')


def upgrade_device(fw_conn):
    """Upgrade Device

    Args:
        fw_conn (PanDevice): A panos object for device
    """
    print('Upgrading PAN-OS version...')
    fw_conn.software.upgrade_to_version(config.version)
    print('-- Upgraded')


def main():
    """Function Calls
    """
    for num, fw_ip in enumerate(config.paloalto['firewall_ip']):
        needs_commit = False
        fw_conn = connect_device(fw_ip, num)
        device_settings_results = get_device_config_settings(fw_conn)
        device_setttings_list = process_device_config_settings(device_settings_results)
        needs_commit = set_device_config_settings(fw_conn, num, device_setttings_list, needs_commit)
        print('Removing factory default configs...')

        # Security Rules
        rule_list, rulebase = get_security_rulebase(fw_conn)
        needs_commit = remove_default_rule(rule_list, rulebase, needs_commit)

        # Virtual Router
        vr_xpath = "/network/virtual-router"
        vr_path = './result/virtual-router/entry'
        vr_xml = get_fw_setting(fw_conn, vr_xpath)
        vr_list = process_xml(vr_xml, vr_path)
        needs_commit = remove_default_setting(fw_conn, vr_list, needs_commit)

        # Virtual Wire
        vwire_xpath = "/network/virtual-wire"
        vwire_path = './result/virtual-wire/entry'
        vwire_xml = get_fw_setting(fw_conn, vwire_xpath)
        vwire_list = process_xml(vwire_xml, vwire_path)
        needs_commit = remove_default_setting(fw_conn, vwire_list, needs_commit)

        # Zones
        zones_xpath = "/vsys/entry[@name='vsys1']/zone"
        zone_path = './result/zone/entry'
        zones_xml = get_fw_setting(fw_conn, zones_xpath)
        zone_list = process_xml(zones_xml, zone_path)
        needs_commit = remove_default_setting(fw_conn, zone_list, needs_commit)

        # Interfaces
        interfaces_xpath = "/network/interface/ethernet"
        interface_path = './result/ethernet/entry'
        interfaces_xml = get_fw_setting(fw_conn, interfaces_xpath)
        interface_list = process_xml(interfaces_xml, interface_path)
        needs_commit = remove_default_setting(fw_conn, interface_list, needs_commit)

        if needs_commit:
            print('-- Removed')
            print('Committing configs...')
            commit_jobid = commit_config(fw_conn)
            check_job(fw_conn, commit_jobid)
            print('-- Committed')
        else:
            print('-- Already removed')
            print('No commit needed!')

        if config.multivsys == 'on':
            configuring_multivsys(fw_conn)

        is_licensed = fetch_licenses(fw_conn)

        system_info_results = get_system_info(fw_conn)
        app_version, panos_version = process_system_info(system_info_results)
        content_updates_results = check_content_updates(fw_conn)
        max_app_version = process_content_updates(content_updates_results)

        if app_version == max_app_version:
            print('Newest content updates already installed')
        else:
            print('Downloading latest content update...')
            download_cmd = ('<request><content><upgrade><download><latest>'
                            '</latest></download></upgrade></content></request>')
            download_results = update_content(fw_conn, download_cmd)
            download_jobid = process_jobid(download_results)
            check_job(fw_conn, download_jobid)
            print('-- Downloaded')

            print('Installing latest content update...')
            install_cmd = ('<request><content><upgrade><install><version>latest'
                        '</version></install></upgrade></content></request>')
            install_results = update_content(fw_conn, install_cmd)
            install_jobid = process_jobid(install_results)
            check_job(fw_conn, install_jobid)
            print('-- Installed')

        if len(config.paloalto['firewall_ip']) == 2:
            ha_state_results = check_ha_state(fw_conn)
            ha_state = process_ha_state(ha_state_results)

            if ha_state == 'no':
                configure_ha(fw_conn, num)
            elif ha_state == 'yes':
                print('HA already enabled')

        if panos_version.split('.')[0] == '10':
            print('Ciphers handled by Panorama')
        else:
            remediate_ciphers(fw_conn)

        if panos_version == config.version:
            print('Firewall already at PAN-OS version {}'.format(config.version))
        else:
            if is_licensed:
                upgrade_device(fw_conn)


if __name__ == '__main__':
    main()
