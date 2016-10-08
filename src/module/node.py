'''
Written by Dmitry Chirikov <dmitry@chirikov.ru>
This file is part of Luna, cluster provisioning tool
https://github.com/dchirikov/luna

This file is part of Luna.

Luna is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Luna is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Luna.  If not, see <http://www.gnu.org/licenses/>.

'''

from config import *
import logging
import json
from bson.dbref import DBRef
from bson.objectid import ObjectId
from luna.utils import set_mac_node
from luna.base import Base
from luna.cluster import Cluster
from luna.network import Network
from luna.osimage import OsImage
from luna.bmcsetup import BMCSetup
from luna.switch import Switch
import datetime
import re
import socket
import uuid

class Node(Base):
    """
    Class for operating with node records
    """
    _logger = logging.getLogger(__name__)
    def __init__(self, name = None, mongo_db = None, create = False, id = None,
            group = None, localboot = False, setupbmc = True, service = False):
        """
        name    - can be ommited
        group   - group belongs to; should be specified
            Flags
        localboot - boot from localdisk
        setupbmc - whether we need to setup ipmi on install
        service   - do not perform install but boot to installer (dracut environment)
        """
        self._logger.debug("Arguments to function '{}".format(self._debug_function()))
        self._collection_name = 'node'
        if not bool(name) and bool(create):
            name = self._generate_name(mongo_db = mongo_db)
        mongo_doc = self._check_name(name, mongo_db, create, id)
        self._keylist = {'port': type(''), 'localboot': type(True), 'setupbmc': type(True), 'service': type(True)}
        if create:
            cluster = Cluster(mongo_db = self._mongo_db)
            group = Group(group, mongo_db = self._mongo_db)
            mongo_doc = {'name': name, 'group': group.DBRef, 'interfaces': None,
                    'mac': None, 'switch': None, 'port': None,
                    'localboot': localboot, 'setupbmc': setupbmc, 'service': service}
            self._logger.debug("mongo_doc: '{}'".format(mongo_doc))
            self._name = name
            self._id = self._mongo_collection.insert(mongo_doc)
            self._DBRef = DBRef(self._collection_name, self._id)
            for interface in group.ifs:
                self.add_ip(interface)
            self.add_bmc_ip()
            self.link(group)
            self.link(cluster)
        else:
            self._name = mongo_doc['name']
            self._id = mongo_doc['_id']
            self._DBRef = DBRef(self._collection_name, self._id)
        self._logger = logging.getLogger(__name__ + '.' + self._name)

    def _generate_name(self, mongo_db):
        cluster = Cluster(mongo_db)
        prefix = cluster.get('nodeprefix')
        digits = cluster.get('nodedigits')
        back_links = cluster.get_back_links()
        max_num = 0
        for link in back_links:
            if not link['collection'] == self._collection_name:
                continue
            node = Node(id = link['DBRef'].id, mongo_db = mongo_db)
            name = node.name
            try:
                nnode = int(name.lstrip(prefix))
            except ValueError:
                continue
            if nnode > max_num:
                max_num = nnode
        ret_name = prefix + str(max_num + 1).zfill(digits)
        return ret_name

    def change_group(self, new_group_name = None):
        if not bool(new_group_name):
            self._logger.error("Group needs to be specified")
            return None
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        new_group = Group(new_group_name, mongo_db = self._mongo_db)
        json = self._get_json()
        old_group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        old_group_json = old_group.json
        old_group_interfaces = old_group.ifs
        try:
            old_bmc_net_id = old_group._get_json()['bmcnetwork'].id
        except:
            old_bmc_net_id = None
        old_bmc_ip = None
        if bool(old_bmc_net_id):
            old_bmc_ip = self.get_human_bmc_ip()
        old_ips = {}
        for interface in old_group_interfaces:
            if_uuid = old_group.get_if_uuid(interface)
            try:
                net_id = old_group_json['interfaces'][if_uuid]['network'].id
            except:
                net_id = None
            if bool(net_id):
                old_ip = self.get_human_ip(interface)
                old_ips[net_id] = {'interface' : interface, 'ip': old_ip}
            self.del_ip(interface)
        self.del_bmc_ip()
        self.unlink(old_group)
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'group': new_group.DBRef}}, multi=False, upsert=False)
        self.link(new_group)
        try:
            newbmc_net_id = new_group.json['bmcnetwork'].id
        except:
            newbmc_net_id = None
        if bool(old_bmc_net_id) and bool(newbmc_net_id) and newbmc_net_id == old_bmc_net_id:
            self.add_bmc_ip(old_bmc_ip)
        else:
            self.add_bmc_ip()

        new_group_interfaces = new_group.ifs
        new_group_json = new_group.json
        for interface in new_group_interfaces:
            if_uuid = new_group.get_if_uuid(interface)
            if not bool(if_uuid):
                continue
            try:
                net_id = new_group_json['interfaces'][if_uuid]['network'].id
            except:
                net_id = None
            old_ip = None
            if bool(net_id):
                try:
                    old_ip = old_ips[net_id]['ip']
                except:
                    old_ip = None
            self.add_ip(interface, old_ip)
        return res['err']

    def change_ip(self, interface_name = None, reqip = None):
        if not bool(interface_name):
            self._logger.error("'interfaces' should be specified")
            return None
        if not bool(reqip):
            self._logger.error("IP address should be specified")
            return None
        self_group_name = self._get_json()['group']
        group = Group(id = self_group_name.id, mongo_db = self._mongo_db)
        if_uuid = group.get_if_uuid(interface_name)
        if not bool(group.get_num_ip(if_uuid, reqip)):
            return None
        if self.del_ip(interface_name):
            return self.add_ip(interface_name, reqip)
        return None

    def change_bmc_ip(self, reqip = None):
        if not bool(reqip):
            self._logger.error("IP address should be specified")
            return None
        self_group_name = self._get_json()['group']
        group = Group(id = self_group_name.id, mongo_db = self._mongo_db)
        if not bool(group.get_num_bmc_ip(reqip)):
            return None
        if self.del_bmc_ip():
            return self.add_bmc_ip(reqip)
        return self.add_bmc_ip(reqip)

    def add_ip(self, interface_name = None, reqip = None):
        if not bool(interface_name):
            self._logger.error("'interface_name' should be specified")
            return None
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        json = self.json
        group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        if_uuid = group.get_if_uuid(interface_name)
        if not bool(if_uuid):
            self._logger.error("No such interface '{}' for group configured.".format(interface_name))
            return None
        try:
            node_interfaces = json['interfaces'] or {}
        except:
            node_interfaces = {}
        try:
            old_ip = node_interfaces[if_uuid]
        except:
            old_ip = None
        if bool(old_ip):
            self._logger.error("IP is already configured for interface '{}'.".format(interface_name))
            return None
        ip = group.reserve_ip(if_uuid, reqip)
        if not bool(ip):
            self._logger.warning("Cannot reserve ip for interface '{}'.".format(interface_name))
        node_interfaces[if_uuid] = ip
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'interfaces': node_interfaces}}, multi=False, upsert=False)
        return not res['err']

    def del_ip(self, interface_name = None):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        json = self.json
        group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        try:
            interface_dict = json['interfaces'].copy()
        except:
            self._logger.error("No interfaces found")
            return None
        if not bool(interface_dict):
            self._logger.error("All interfaces are already deleted")
            return None
        if not bool(interface_name):  # delete all ips for the nodes
            for if_uuid in json['interfaces']:
                ip = interface_dict[if_uuid]
                if bool(ip):
                    group.release_ip(if_uuid, ip)
                interface_dict.pop(if_uuid)
            res = self._mongo_collection.update(
                    {'_id': self._id}, 
                    {'$set': {'interfaces': interface_dict} },
                    multi=False, upsert=False
                )
            return not res['err']
        # if interface_name is defined
        if_uuid = group.get_if_uuid(interface_name)
        if not bool(if_uuid):
            self._logger.error("No such interface '{}' for group configured.".format(interface_name))
            return None
        try:
            ip = json['interfaces'][if_uuid]
        except:
            self._logger.error("No such interface '{}' found. If it already deleted?".format(interface_name))
            return True
        group.release_ip(if_uuid, ip)
        interface_dict.pop(if_uuid)
        res = self._mongo_collection.update(
                {'_id': self._id},
                {'$set': {'interfaces': interface_dict}},
                multi=False, upsert=False
            )
        return not res['err']

    def add_bmc_ip(self, reqip = None):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        json = self._get_json()
        group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        ip = 0
        try:
            ip = json['bmcnetwork']
        except:
            pass
        if bool(ip):
            self._logger.error("IP is already assigned on bmc network")
            return None
        ip = group._reserve_bmc_ip(reqip)
        if not bool(ip):
            self._logger.warning("Cannot reserve ip for bmc interface")
            return None
        mongo_doc = ip
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'bmcnetwork': mongo_doc}}, multi=False, upsert=False)
        return not res['err']

    def del_bmc_ip(self):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        json = self._get_json()
        group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        try:
            ip = json['bmcnetwork']
        except:
            ip = None
        if not bool(ip):
            return None
        res = group._release_bmc_ip(ip)
        if bool(res):
            mongo_doc = None
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'bmcnetwork': mongo_doc}}, multi=False, upsert=False)
        return not res['err']

    def set_mac(self, mac = None):
        import re
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        if type(mac) == type('') and re.match('(([a-fA-F0-9]{2}:){4}([a-fA-F0-9]{2}))', mac):
            mac = mac.lower()
            set_mac_node(mac, self.DBRef, (self._mongo_db))
            #res = self._mongo_collection.update({'_id': self._id}, {'$set': {'mac': mac}}, multi=False, upsert=False)
            return True
        return None

    def get_mac(self):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        try:
            mac = str(self._mongo_db['mac'].find_one({'node': self.DBRef})['mac'])
        except:
            mac = None
        return mac

    def clear_mac(self):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        mac = self.get_mac()
        self._mongo_db['switch_mac'].remove({'mac': mac})
        res = self._mongo_db['mac'].remove({'mac': mac})
        return res['ok']

    def set_switch(self, name):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        switch = Switch(name)
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'switch': switch.DBRef}}, multi=False, upsert=False)
        if res['ok'] == 1:
            self.link(switch.DBRef)
        return bool(res['ok'])

    def clear_switch(self):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        json = self._get_json()
        try:
            switch_id = json['switch'].id
        except:
            return None
        switch = Switch(id = switch_id)
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'switch': None}}, multi=False, upsert=False)
        if res['ok'] == 1:
            self.unlink(switch.DBRef)
        return bool(res['ok'])

    def set_port(self, num):
        self.set('port', num)

    def clear_port(self):
        self.set('port', '')

    def delete(self):
        """
        Delete node
        """
        self._logger.debug("Arguments to function '{}".format(self._debug_function()))
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        mac = self.get_mac()
        back_links = self.get_back_links(resolve=True)
        if len(back_links) > 0:
            #back_links = self.get_back_links(resolve=True)
            self._logger.error("Current object is being written as a dependency for the following objects:")
            for elem in back_links:
                self._logger.error(json.dumps(elem, sort_keys=True ))
            return None
        links = self.get_links(resolve=True)
        for link in links:
            self.unlink(link['DBRef'])
        self._mongo_db['switch_mac'].remove({'mac': mac})
        self._mongo_db['mac'].remove({'mac': mac})
        self.del_bmc_ip()
        self.del_ip()
        ret = self._mongo_collection.remove({'_id': self._id}, multi=False)
        self._wipe_vars()
        return not ret['err']

    def get_interfaces(self):
        try:
            group = Group(id = self.json['group'].id, mongo_db = self._mongo_db)
            return group.ifs
        except:
            return []

    def get_human_ip(self, interface_name):
        json = self.json
        group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        if_uuid = group.get_if_uuid(interface_name)
        try:
            ipnum = json['interfaces'][if_uuid]
        except:
            # self._logger.error("No IPADDR for interface '{}' configured".format(interface))
            return None
        return group.get_human_ip(if_uuid, ipnum)

    def get_rel_ip(self, interface):
        json = self._get_json()
        #group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        try:
            num_ip = json['interfaces'][interface]
        except:
            self._logger.error("No such interface '{}' for node '{}' configured".format(interface, self.name))
            return None
        return num_ip

    def get_human_bmc_ip(self):
        json = self._get_json()
        group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        try:
            ipnum = json['bmcnetwork']
        except:
            self._logger.warning("No IPADDR for interface bmc configured")
            return None
        return group.get_human_bmc_ip(ipnum)

    def get_rel_bmc_ip(self):
        json = self._get_json()
        #group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        try:
            num_ip = json['bmcnetwork']
        except:
            self._logger.error("No BMC interface for node '{}' configured".format(self.name))
            return None
        return num_ip

    """
    @property
    def kernel(self):
        return "compute-vmlinuz-3.10.0-327.3.1.el7.x86_64"

    @property
    def initrd(self):
        return "compute-initramfs-3.10.0-327.3.1.el7.x86_64"

    @property
    def kernopts(self):
        return 'luna.ip=enp0s3:10.141.0.1:16' # luna.ip=dhcp
    """

    @property
    def boot_params(self):
        """
        will return dictionary with all needed params for booting:
        kernel, initrd, kernel opts, ip, net, prefix
        """
        params = {}
        group = Group(id = self.get('group').id, mongo_db = self._mongo_db)
        group_params = group.boot_params()
        params['boot_if'] = group_params['boot_if']
        params['kernel_file'] = group_params['kernel_file']
        params['initrd_file'] = group_params['initrd_file']
        params['kern_opts'] = group_params['kern_opts']
        params['boot_if'] = group_params['boot_if']
        params['net_prefix'] = group_params['net_prefix']
        if (params['boot_if']):
            params['ip'] = self.get_human_ip(params['boot_if'])
        params['name'] = self.name
        params['service'] = int(self.get('service'))
        params['localboot'] = self.get('localboot')
        return params

    @property
    def install_params(self):
        params = {}
        group = Group(id = self.get('group').id, mongo_db = self._mongo_db)
        params = group.install_params
        if bool(params['torrent_if']):
            params['torrent_if_ip'] = self.get_human_ip(params['torrent_if'])
        for interface in params['interfaces']:
            if bool(self.get_human_ip(interface)):
                params['interfaces'][interface] = params['interfaces'][interface].strip() + "\n" + "IPADDR=" + self.get_human_ip(interface)
        if params['bmcsetup']:
            try:
                ip = self.get_human_bmc_ip()
                params['bmcsetup']['ip'] = ip
            except:
                pass
        params['name'] = self.name
        if params['domain']:
            params['hostname'] = self.name + "." +  params['domain']
        else:
            params['hostname'] = self.name
        params['setupbmc'] = self.get('setupbmc')
        return params

    def update_status(self, step = None):
        if not bool(step):
            self._logger.error("No data to update status of the node.")
            return None
        if not bool(re.match('^[ a-zA-Z0-9\.\-_]+?$', step)):
            self._logger.error("'Step' parameter in 'update_status' function contains invalid string.".format(self.name))
            return None
        now = datetime.datetime.utcnow()
        self._mongo_collection.update({'_id': self._id}, {'$set': {'status': {'step': step, 'time': now}}}, multi=False, upsert=False)

    def get_status(self, relative = True):
        json = self._get_json()
        try:
            status = json['status']
            step = str(status['step'])
            time = status['time']
        except:
            return None
        now = datetime.datetime.utcnow()
        tracker_records = []
        tracker_record = {}
        tor_time = datetime.datetime(1, 1, 1)
        perc = 0.0
        if step == 'install.download':
            name = "%20s" % self.name
            peer_id = ''.join(["{:02x}".format(ord(l)) for l in name])
            self._mongo_db
            tracker_collection = self._mongo_db['tracker']
            tracker_records = tracker_collection.find({'peer_id': peer_id})
        for doc in tracker_records:
            try:
                tmp_time = doc['updated']
            except:
                continue
            if tmp_time > tor_time:
                tracker_record = doc
                tor_time = tmp_time
        if bool(tracker_record):
            try:
                # tor_time = tracker_record['updated'] # we have it already, actually
                downloaded = tracker_record['downloaded']
                left = tracker_record['left']
                perc = 100.0*downloaded/(downloaded+left)
            except:
                tor_time = datetime.datetime(1, 1, 1)
                perc = 0.0
        if bool(perc) and (tor_time > time):
            status = "%s (%.2f%% / last update %isec)" % (step, perc, (now - tor_time).seconds)
        else:
            status = step
        if relative:
            sec = (now - time).seconds
            ret_time = str(datetime.timedelta(seconds=sec))
        else:
            ret_time = str(time)
        return {'status': status, 'time': ret_time}

    def check_avail(self, timeout = 1, bmc = True, net = None):
        avail = {'bmc': None, 'nets': {}}
        json = self._get_json()
        bmc_ip = self.get_human_bmc_ip()
        if bool(bmc) and bool(bmc_ip):
            ipmi_message = "0600ff07000000000000000000092018c88100388e04b5".decode('hex')
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(ipmi_message, (bmc_ip, 623))
            try:
                data, addr = sock.recvfrom(1024)
                avail['bmc'] = True

            except socket.timeout:
                avail['bmc'] = False
        group = Group(id = json['group'].id, mongo_db = self._mongo_db)
        json = self._get_json()
        test_ips = []
        try:
            ifs = json['interfaces']
        except:
            ifs = {}
        for interface in ifs:
            tmp_net = group.get_net_name_for_if(interface)
            tmp_json = {'network': tmp_net, 'ip': self.get_human_ip(interface)}
            if bool(net):
                if tmp_net == net:
                    test_ips.append(tmp_json)
            else:
                if bool(tmp_net):
                    test_ips.append(tmp_json)
        for elem in test_ips:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((elem['ip'],22))
            if result == 0:
                avail['nets'][elem['network']] = True
            else:
                avail['nets'][elem['network']] = False
        return avail

class Group(Base):
    """
    Class for operating with group records
    """
    _logger = logging.getLogger(__name__)
    def __init__(self, name = None, mongo_db = None, create = False, id = None,
            prescript = None, bmcsetup = None, bmcnetwork = None,
            partscript = None, osimage = None, interface_names = None, postscript = None, boot_if = None, torrent_if = None):
        """
        prescript   - preinstall script
        bmcsetup    - bmcsetup options
        bmcnetwork  - used for bmc networking
        partscript  - parition script
        osimage     - osimage
        interface_names  - list of the newtork interfaces
        postscript  - postinstall script
        """
        self._logger.debug("Arguments to function '{}".format(self._debug_function()))
        self._collection_name = 'group'
        mongo_doc = self._check_name(name, mongo_db, create, id)
        self._keylist = {'prescript': type(''), 'partscript': type(''), 'postscript': type(''), 'boot_if': type(''), 'torrent_if': type('')}
        if create:
            cluster = Cluster(mongo_db = self._mongo_db)
            (bmcobj, bmcnetobj) = (None, None)
            if bool(bmcsetup):
                bmcobj = BMCSetup(bmcsetup).DBRef
            if bool(bmcnetwork):
                bmcnetobj = Network(bmcnetwork, mongo_db = self._mongo_db).DBRef
            osimageobj = OsImage(osimage)
            if bool(interface_names) and type(interface_names) is not type([]):
                self._logger.error("'interfaces' should be list")
                raise RuntimeError
            if_dict = {}
            if not bool(interface_names):
                interface_names = []
            for interface in interface_names:
                if_uuid = str(uuid.uuid4())
                if_dict[if_uuid] = {'name': interface, 'network': None, 'params': ''}
            if not bool(partscript):
                partscript = "mount -t tmpfs tmpfs /sysroot"
            if not bool(prescript):
                prescript = ""
            if not bool(postscript):
                postscript = """cat <<EOF>>/sysroot/etc/fstab
tmpfs   /       tmpfs    defaults        0 0
EOF"""
            mongo_doc = {'name': name, 'prescript':  prescript, 'bmcsetup': bmcobj, 'bmcnetwork': bmcnetobj,
                               'partscript': partscript, 'osimage': osimageobj.DBRef, 'interfaces': if_dict,
                               'postscript': postscript, 'boot_if': boot_if, 'torrent_if': torrent_if}
            self._logger.debug("mongo_doc: '{}'".format(mongo_doc))
            self._name = name
            self._id = self._mongo_collection.insert(mongo_doc)
            self._DBRef = DBRef(self._collection_name, self._id)
            self.link(cluster)
            if bmcobj:
                self.link(bmcobj)
            if bmcnetobj:
                self.link(bmcnetobj)
            self.link(osimageobj)
        else:
            self._name = mongo_doc['name']
            self._id = mongo_doc['_id']
            self._DBRef = DBRef(self._collection_name, self._id)
        self._logger = logging.getLogger('group.' + self._name)

    def osimage(self, osimage_name):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        osimage = OsImage(osimage_name)
        old_dbref = self._get_json()['osimage']
        self.unlink(old_dbref)
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'osimage': osimage.DBRef}}, multi=False, upsert=False)
        self.link(osimage.DBRef)
        return not res['err']

    def bmcsetup(self, bmcsetup_name):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        bmcsetup = None
        if bool(bmcsetup_name):
            bmcsetup = BMCSetup(bmcsetup_name)
        old_dbref = self._get_json()['bmcsetup']
        if bool(old_dbref):
            self.unlink(old_dbref)
        if bool(bmcsetup):
            res = self._mongo_collection.update({'_id': self._id}, {'$set': {'bmcsetup': bmcsetup.DBRef}}, multi=False, upsert=False)
            self.link(bmcsetup.DBRef)
        else:
            res = self._mongo_collection.update({'_id': self._id}, {'$set': {'bmcsetup': None}}, multi=False, upsert=False)
        return not res['err']

    def set_bmcnetwork(self, bmcnet):
        old_bmcnet_dbref = self._get_json()['bmcnetwork']
        net = Network(bmcnet, mongo_db = self._mongo_db)
        reverse_links = self.get_back_links()
        if bool(old_bmcnet_dbref):
            self._logger.error("Network is already defined for BMC interface")
            return None
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'bmcnetwork': net.DBRef}}, multi=False, upsert=False)
        self.link(net.DBRef)
        for link in reverse_links:
            if link['collection'] != 'node':
                continue
            node = Node(id=link['DBRef'].id, mongo_db = self._mongo_db)
            node.add_bmc_ip()
        return not res['err']

    def del_bmcnetwork(self):
        old_bmcnet_dbref = self._get_json()['bmcnetwork']
        if bool(old_bmcnet_dbref):
            reverse_links = self.get_back_links()
            for link in reverse_links:
                if link['collection'] != 'node':
                    continue
                node = Node(id=link['DBRef'].id, mongo_db = self._mongo_db)
                node.del_bmc_ip()
            self.unlink(old_bmcnet_dbref)
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'bmcnetwork': None}}, multi=False, upsert=False)
        return not res['err']


    def show_bmc_if(self, brief = False):
        bmcnetwork = self._get_json()['bmcnetwork']
        if not bool(bmcnetwork):
            return ''
        (NETWORK, PREFIX) = ("", "")
        try:
            net = Network(id = bmcnetwork.id, mongo_db = self._mongo_db)
            NETWORK = net.get('NETWORK')
            PREFIX =  str(net.get('PREFIX'))
        except:
            pass
        if brief:
            return "[" +net.name + "]:"+ NETWORK + "/" + PREFIX
        return NETWORK + "/" + PREFIX

    def get_net_name_for_if(self, interface):
        interfaces = self._get_json()['interfaces']
        try:
            params = interfaces[interface]
        except:
            self._logger.error("Interface '{}' does not exist".format(interface))
            return ""
        try:
            net = Network(id = params['network'].id, mongo_db = self._mongo_db)
        except:
            net = None
        if bool(net):
            return net.name
        return ""

    def get_if_uuid(self, interface_name):
        if not bool(interface_name):
            self._logger.error("Group.get_if_uuid() got wrong params.")
            return None
        interfaces = self.json['interfaces']
        if_uid = None
        for elem in interfaces:
            if interface_name == interfaces[elem]['name']:
                if_uid = elem
        return if_uid
        
    def show_if(self, interface_name, brief = False):
        if not bool(interface_name):
            self._logger.error("Group.show_if() got wrong params.")
            return ""
        if_uid = self.get_if_uuid(interface_name)
        if not bool(if_uid):
            self._logger.error("Interface '{}' does not exist".format(interface_name))
            return ""
        (outstr, NETWORK, PREFIX) = ("", "", "")
        params = self.json['interfaces'][if_uid]
        try:
            net = Network(id = params['network'].id, mongo_db = self._mongo_db)
            NETWORK = net.get('NETWORK')
            PREFIX =  str(net.get('PREFIX'))
        except:
            pass
        if NETWORK:
            if brief:
                return "[" +net.name + "]:" + NETWORK + "/" + PREFIX
            outstr = "NETWORK=" + NETWORK + "\n"
            outstr += "PREFIX=" + PREFIX
        if params['params'] and not brief:
            outstr += "\n" + params['params']
        return outstr.rstrip()

    def add_interface(self, interface_name):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        interfaces = self.json['interfaces']
        if_uid = self.get_if_uuid(interface_name)
        if bool(if_uid):
            self._logger.error("Interface already exists")
            return None
        if_uid = str(uuid.uuid4())
        interfaces[if_uid] = {'name': interface_name, 'network': None, 'params': ''}
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'interfaces': interfaces}}, multi=False, upsert=False)
        if res['err']:
            self._logger.error("Error adding interface '{}'".format(interface))
            return None
        return True
    
    @property
    def ifs(self):
        interfaces = self.json['interfaces']
        ifs = []
        for elem in interfaces:
            ifs.append(str(interfaces[elem]['name']))
        return ifs

    def get_if_parms(self, interface_name):
        interfaces = self.json['interfaces']
        if_uid = self.get_if_uuid(interface_name)
        if not bool(if_uid):
            self._logger.error("Interface '{}' does not exist".format(interface_name))
            return None
        return interfaces[if_uid]['params']

    def list_interfaces(self):
        json = self.json
        try:
            interfaces = json['interfaces']
        except:
            self._logger.error("No interfaces for group '{}' configured.".format(self.name))
            interfaces = {}
        try:
            bmcnet = json['bmcnetwork']
        except:
            self._logger.warning("No network for BMC interface for group '{}' configured.".format(self.name))
            bmcnet = None
        return {'interfaces': interfaces, 'bmcnetwork': bmcnet}

    def get_rel_ips_for_net(self, netobjid):
        rel_ips = {}

        def add_to_dict(key, val):
            try:
                rel_ips[key]
                self._logger.error("Duplicate ip detected in '{}'. Can not put '{}'".format(self.name, key))
            except:
                rel_ips[key] = val

        json = self.json
        if_dict = self.list_interfaces()
        bmcif =  if_dict['bmcnetwork']
        ifs = if_dict['interfaces']
        if bool(bmcif):
            if bmcif.id == netobjid:
                try:
                    node_links = json[usedby_key]
                except KeyError:
                    node_links = None
                if bool(node_links):
                    for node_id in node_links['node']:
                        node = Node(id = ObjectId(node_id))
                        add_to_dict(node.name, node.get_rel_bmc_ip())

        if bool(ifs):
            for if_uuid in ifs:
                if not bool(ifs[if_uuid]['network']):
                    continue
                if ifs[if_uuid]['network'].id == netobjid:
                    try:
                        node_links = json[usedby_key]
                    except KeyError:
                        node_links = None
                    if not bool(node_links):
                        continue
                    for node_id in node_links['node']:
                        node = Node(id = ObjectId(node_id))
                        add_to_dict(node.name, node.get_rel_ip(if_uuid))
        return rel_ips


    def set_if_parms(self, interface_name, parms = ''):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        interfaces = self.json['interfaces']
        if_uid = self.get_if_uuid(interface_name)
        if not bool(if_uid):
            self._logger.error("Interface '{}' does not exist".format(interface))
            return None
        interfaces[if_uid]['params'] = parms
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'interfaces': interfaces}}, multi=False, upsert=False)
        if res['err']:
            self._logger.error("Error setting network parameters for interface '{}'".format(interface))
            return None
        return True

    def set_net_to_if(self, interface_name, network):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        interfaces = self.json['interfaces']
        net = Network(network, mongo_db = self._mongo_db)
        if_uid = self.get_if_uuid(interface_name)
        if not bool(if_uid):
            self._logger.error("Interface '{}' does not exist".format(interface_name))
            return None
        old_net = interfaces[if_uid]['network']
        if bool(old_net):
            self._logger.error("Network is already defined for this interface '{}'".format(interface_name))
            return None
        interfaces[if_uid]['network'] = net.DBRef
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'interfaces': interfaces}}, multi=False, upsert=False)
        if res['err']:
            self._logger.error("Error adding network for interface '{}'".format(interface_name))
            return None
        self.link(net.DBRef)
        reverse_links = self.get_back_links()
        for link in reverse_links:
            if link['collection'] != 'node':
                continue
            # TODO sort node list
            node = Node(id=link['DBRef'].id, mongo_db = self._mongo_db)
            node.add_ip(interface_name)
        return True

    def del_net_from_if(self, interface_name):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        if_uuid = self.get_if_uuid(interface_name)
        interfaces = self.json['interfaces']
        if not bool(if_uuid):
            self._logger.error("Interface '{}' does not exist".format(interface_name))
            return None
        try:
            net_dbref = interfaces[if_uuid]['network']
        except:
            net_dbref = None
        if not bool(net_dbref):
            self._logger.error("Network is not configured for interface '{}'".format(interface_name))
            return None
        reverse_links = self.get_back_links()
        for link in reverse_links:
            if link['collection'] != 'node':
                continue
            node = Node(id=link['DBRef'].id, mongo_db = self._mongo_db)
            node.del_ip(interface_name)
        self.unlink(net_dbref)
        interfaces[if_uuid]['network'] = None
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'interfaces': interfaces}}, multi=False, upsert=False)
        if res['err']:
            self._logger.error("Error adding network for interface '{}'".format(interface))
            return None
        return True

    def del_interface(self, interface_name):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        self.del_net_from_if(interfacei_name)
        interfaces = self.json['interfaces']
        if_uid = self.get_if_uuid(interface_name)
        interfaces.pop(if_uid)
        res = self._mongo_collection.update({'_id': self._id}, {'$set': {'interfaces': interfaces}}, multi=False, upsert=False)
        if res['err']:
            self._logger.error("Error deleting interface '{}'".format(interface))
            return None
        return True

    def reserve_ip(self, if_uuid = None, ip = None):
        if not bool(if_uuid):
            self._logger.error("Interface needs to be specified")
            return None
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        try:
            net_dbref = self._get_json()['interfaces'][if_uuid]['network']
        except:
            net_dbref = None
        if not bool(net_dbref):
            self._logger.warning("No network configured for interface '{}'".format(if_uuid))
            return None
        net = Network(id = net_dbref.id, mongo_db = self._mongo_db)
        return net.reserve_ip(ip)

    def release_ip(self, if_uuid, ip):
        if not bool(if_uuid):
            self._logger.error("Interface needs to be specified")
            return None
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        try:
            net_dbref = self._get_json()['interfaces'][if_uuid]['network']
        except:
            net_dbref = None
        if not bool(net_dbref):
            self._logger.error("No network configured for interface '{}'".format(if_uuid))
            return None
        net = Network(id = net_dbref.id, mongo_db = self._mongo_db)
        if bool(ip):
            return net.release_ip(ip)
        return True

    def _reserve_bmc_ip(self, ip = None):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        try:
            net_dbref = self._get_json()['bmcnetwork']
        except:
            self._logger.error("No bmc network configured")
            return None
        if not bool(net_dbref):
            self._logger.warning("No network configured for BMC interface")
            return None
        net = Network(id = net_dbref.id, mongo_db = self._mongo_db)
        return net.reserve_ip(ip)

    def _release_bmc_ip(self, ip):
        if not self._id:
            self._logger.error("Was object deleted?")
            return None
        try:
            net_dbref = self._get_json()['bmcnetwork']
        except:
            self._logger.error("No bmc network configured")
            return None
        net = Network(id = net_dbref.id, mongo_db = self._mongo_db)
        return net.release_ip(ip)

    def get_human_ip(self, if_uuid, ipnum):
        interfaces = self._get_json()['interfaces']
        dbref = None
        try:
            dbref = interfaces[if_uuid]['network']
        except:
            self._logger.error("Network is not configured for '{}'".format(interfaces[if_uuid]['name']))
            return None
        if not bool(dbref):
            return None
        net = Network(id = dbref.id, mongo_db = self._mongo_db)
        if bool(ipnum):
            return net.relnum_to_ip(ipnum)
        return None

    def get_num_ip(self, if_uuid, ip):
        interfaces = self.json['interfaces']
        dbref = None
        try:
            dbref = interfaces[if_uuid]['network']
        except:
            self._logger.error("No key 'network' for '{}'".format(if_uuid))
            return None
        if not bool(dbref):
            self._logger.error("No network configured for interface.")
            return None
        net = Network(id = dbref.id, mongo_db = self._mongo_db)
        return net.ip_to_relnum(ip)

    def get_human_bmc_ip(self, ipnum):
        dbref = None
        try:
            dbref = self._get_json()['bmcnetwork']
        except:
            self._logger.error("Interface is not configured for BMC")
            return None
        if not bool(dbref):
            return None
        net = Network(id = dbref.id, mongo_db = self._mongo_db)
        return net.relnum_to_ip(ipnum)

    def get_num_bmc_ip(self, ip):
        dbref = None
        try:
            dbref = self._get_json()['bmcnetwork']
        except:
            self._logger.error("Interface is not configured for BMC")
            return None
        if not bool(dbref):
            return None
        net = Network(id = dbref.id, mongo_db = self._mongo_db)
        return net.ip_to_relnum(ip)

    def boot_params(self):
        params = {}
        params['boot_if'] = None
        params['net_prefix'] = None
        osimage = OsImage(id = self.get('osimage').id, mongo_db = self._mongo_db)
        try:
            params['kernel_file'] = osimage.get('kernfile')
        except:
            params['kernel_file'] = ""
        try:
            params['initrd_file'] = osimage.get('initrdfile')
        except:
            params['initrd_file'] = ""
        try:
            params['kern_opts'] = osimage.get('kernopts')
        except:
            params['kern_opts'] = ""
        try:
            params['boot_if'] = self.get('boot_if')
        except:
            params['boot_if'] = ""
            params['net_prefix'] = ""
            return params
        interfaces = self._get_json()['interfaces']
        try:
            if_params = interfaces[params['boot_if']]
        except:
            self._logger.error("Boot interface '{}' does not present in configured interface list '{}'.".format(params['boot_if'], interfaces.keys()))
            params['boot_if'] = ""
            params['net_prefix'] = ""
            return params
        net = None
        try:
            if_net = if_params['network']
            net = Network(id = if_net.id, mongo_db = self._mongo_db)
        except:
            pass
        if not bool(net):
            self._logger.error("Boot interface '{}' has no network configured".format(params['boot_if']))
            params['boot_if'] = ""
            params['net_prefix'] = ""
            return params
        params['net_prefix'] = net.get('PREFIX')
        return params

    @property
    def install_params(self):
        params = {}
        params['prescript'] = self.get('prescript')
        params['partscript'] = self.get('partscript')
        params['postscript'] = self.get('postscript')
        try:
            params['boot_if'] = self.get('boot_if')
        except:
            params['boot_if'] = ''
        try:
            params['torrent_if'] = self.get('torrent_if')
        except:
            params['torrent_if'] = ''
        json = self._get_json()
        if bool(params['torrent_if']):
            try:
                net_dbref = json['interfaces'][params['torrent_if']]['network']
                net = Network(id = net_dbref.id, mongo_db = self._mongo_db)
                params['torrent_if_net_prefix'] = str(net.get('PREFIX'))
            except:
                params['torrent_if'] = ''
        try:
            net_dbref = json['interfaces'][self.get('boot_if')]['network']
            net = Network(id = net_dbref.id, mongo_db = self._mongo_db)
            params['domain'] = str(net.name)
        except:
            params['domain'] = ""
        params['interfaces'] = {}
        try:
            interfaces = json['interfaces'].keys()
            for interface in interfaces:
                params['interfaces'][str(interface)] = str(self.get_if_parms(interface))
        except:
            pass
        try:
            interfaces = json['interfaces'].keys()
        except:
            interfaces = []

        for interface in interfaces:
            net_dbref = json['interfaces'][interface]['network']
            try:
                net = Network(id = net_dbref.id, mongo_db = self._mongo_db)
                net_prefix = "\n" + "PREFIX=" + str(net.get('PREFIX'))
            except:
                net_prefix = ""
            params['interfaces'][str(interface)] = params['interfaces'][str(interface)].strip() + net_prefix
        osimage = OsImage(id = self.get('osimage').id, mongo_db = self._mongo_db)
        try:
            params['torrent'] = osimage.get('torrent') + ".torrent"
            params['tarball'] = osimage.get('tarball') + ".tgz"
        except:
            params['torrent'] = ""
            params['tarball'] = ""
        params['kernver'] = osimage.get('kernver')
        params['kernopts'] = osimage.get('kernopts')
        params['bmcsetup'] = {}
        if self.get('bmcsetup'):
            bmcsetup = BMCSetup(id = self.get('bmcsetup').id, mongo_db = self._mongo_db)
            params['bmcsetup']['mgmtchannel'] = bmcsetup.get('mgmtchannel') or 1
            params['bmcsetup']['netchannel'] = bmcsetup.get('netchannel') or 1
            params['bmcsetup']['userid'] = bmcsetup.get('userid') or 3
            params['bmcsetup']['user'] = bmcsetup.get('user') or "ladmin"
            params['bmcsetup']['password'] = bmcsetup.get('password') or "ladmin"
            try:
                net_dbref = json['bmcnetwork']
                net = Network(id = net_dbref.id, mongo_db = self._mongo_db)
                params['bmcsetup']['netmask'] = net.get('NETMASK')
            except:
                params['bmcsetup']['netmask'] = ''
        return params
