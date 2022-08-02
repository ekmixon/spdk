#!/usr/bin/env python3


import os
import os.path
import re
import sys
import time
import json
import random
from subprocess import check_call, call, check_output, Popen, PIPE, CalledProcessError

if (len(sys.argv) == 7):
    target_ip = sys.argv[2]
    initiator_ip = sys.argv[3]
    port = sys.argv[4]
    netmask = sys.argv[5]
    namespace = sys.argv[6]

ns_cmd = f'ip netns exec {namespace}'
other_ip = '127.0.0.6'
initiator_name = 'ANY'
portal_tag = '1'
initiator_tag = '1'

rpc_param = {
    'target_ip': target_ip,
    'initiator_ip': initiator_ip,
    'port': port,
    'initiator_name': initiator_name,
    'netmask': netmask,
    'lun_total': 3,
    'malloc_bdev_size': 64,
    'malloc_block_size': 512,
    'queue_depth': 64,
    'target_name': 'Target3',
    'alias_name': 'Target3_alias',
    'disable_chap': True,
    'mutual_chap': False,
    'require_chap': False,
    'chap_group': 0,
    'header_digest': False,
    'data_digest': False,
    'log_flag': 'rpc',
    'cpumask': 0x1
}


class RpcException(Exception):

    def __init__(self, retval, msg):
        super(RpcException, self).__init__(msg)
        self.retval = retval
        self.message = msg


class spdk_rpc(object):

    def __init__(self, rpc_py):
        self.rpc_py = rpc_py

    def __getattr__(self, name):
        def call(*args):
            cmd = "{} {}".format(self.rpc_py, name)
            for arg in args:
                cmd += " {}".format(arg)
            return check_output(cmd, shell=True).decode("utf-8")
        return call


def verify(expr, retcode, msg):
    if not expr:
        raise RpcException(retcode, msg)


def verify_log_flag_rpc_methods(rpc_py, rpc_param):
    rpc = spdk_rpc(rpc_py)
    output = rpc.log_get_flags()
    jsonvalue = json.loads(output)
    verify(
        not jsonvalue[rpc_param['log_flag']],
        1,
        f"log_get_flags returned {jsonvalue}, expected false",
    )

    rpc.log_set_flag(rpc_param['log_flag'])
    output = rpc.log_get_flags()
    jsonvalue = json.loads(output)
    verify(
        jsonvalue[rpc_param['log_flag']],
        1,
        f"log_get_flags returned {jsonvalue}, expected true",
    )

    rpc.log_clear_flag(rpc_param['log_flag'])
    output = rpc.log_get_flags()
    jsonvalue = json.loads(output)
    verify(
        not jsonvalue[rpc_param['log_flag']],
        1,
        f"log_get_flags returned {jsonvalue}, expected false",
    )


    print("verify_log_flag_rpc_methods passed")


def verify_iscsi_connection_rpc_methods(rpc_py):
    rpc = spdk_rpc(rpc_py)
    output = rpc.iscsi_get_connections()
    jsonvalue = json.loads(output)
    verify(
        not jsonvalue,
        1,
        f"iscsi_get_connections returned {jsonvalue}, expected empty",
    )


    rpc.bdev_malloc_create(rpc_param['malloc_bdev_size'], rpc_param['malloc_block_size'])
    rpc.iscsi_create_portal_group(
        portal_tag, f"{rpc_param['target_ip']}:{str(rpc_param['port'])}"
    )

    rpc.iscsi_create_initiator_group(initiator_tag, rpc_param['initiator_name'], rpc_param['netmask'])

    lun_mapping = "Malloc" + str(rpc_param['lun_total']) + ":0"
    net_mapping = f"{portal_tag}:{initiator_tag}"
    rpc.iscsi_create_target_node(rpc_param['target_name'], rpc_param['alias_name'], lun_mapping,
                                 net_mapping, rpc_param['queue_depth'], '-d')
    check_output(
        f"iscsiadm -m discovery -t st -p {rpc_param['target_ip']}", shell=True
    )

    check_output('iscsiadm -m node --login', shell=True)
    name = json.loads(rpc.iscsi_get_target_nodes())[0]['name']
    output = rpc.iscsi_get_connections()
    jsonvalues = json.loads(output)
    verify(
        jsonvalues[0]['target_node_name'] == rpc_param['target_name'],
        1,
        f"target node name value is {jsonvalues[0]['target_node_name']}, expected {rpc_param['target_name']}",
    )

    verify(
        jsonvalues[0]['initiator_addr'] == rpc_param['initiator_ip'],
        1,
        f"initiator address values is {jsonvalues[0]['initiator_addr']}, expected {rpc_param['initiator_ip']}",
    )

    verify(
        jsonvalues[0]['target_addr'] == rpc_param['target_ip'],
        1,
        f"target address values is {jsonvalues[0]['target_addr']}, expected {rpc_param['target_ip']}",
    )


    check_output('iscsiadm -m node --logout', shell=True)
    check_output('iscsiadm -m node -o delete', shell=True)
    rpc.iscsi_delete_initiator_group(initiator_tag)
    rpc.iscsi_delete_portal_group(portal_tag)
    rpc.iscsi_delete_target_node(name)
    output = rpc.iscsi_get_connections()
    jsonvalues = json.loads(output)
    verify(
        not jsonvalues,
        1,
        f"iscsi_get_connections returned {jsonvalues}, expected empty",
    )


    print("verify_iscsi_connection_rpc_methods passed")


def verify_scsi_devices_rpc_methods(rpc_py):
    rpc = spdk_rpc(rpc_py)
    output = rpc.scsi_get_devices()
    jsonvalue = json.loads(output)
    verify(
        not jsonvalue,
        1,
        f"scsi_get_devices returned {jsonvalue}, expected empty",
    )


    rpc.bdev_malloc_create(rpc_param['malloc_bdev_size'], rpc_param['malloc_block_size'])
    rpc.iscsi_create_portal_group(
        portal_tag, f"{rpc_param['target_ip']}:{str(rpc_param['port'])}"
    )

    rpc.iscsi_create_initiator_group(initiator_tag, rpc_param['initiator_name'], rpc_param['netmask'])

    lun_mapping = "Malloc" + str(rpc_param['lun_total']) + ":0"
    net_mapping = f"{portal_tag}:{initiator_tag}"
    rpc.iscsi_create_target_node(rpc_param['target_name'], rpc_param['alias_name'], lun_mapping,
                                 net_mapping, rpc_param['queue_depth'], '-d')
    check_output(
        f"iscsiadm -m discovery -t st -p {rpc_param['target_ip']}", shell=True
    )

    check_output('iscsiadm -m node --login', shell=True)
    name = json.loads(rpc.iscsi_get_target_nodes())[0]['name']
    output = rpc.iscsi_get_options()
    jsonvalues = json.loads(output)
    nodebase = jsonvalues['node_base']
    output = rpc.scsi_get_devices()
    jsonvalues = json.loads(output)
    verify(
        jsonvalues[0]['device_name']
        == f"{nodebase}:" + rpc_param['target_name'],
        1,
        f"device name value is {jsonvalues[0]['device_name']}, expected {rpc_param['target_name']}",
    )

    verify(
        jsonvalues[0]['id'] == 0,
        1,
        f"device id value is {jsonvalues[0]['id']}, expected 0",
    )


    check_output('iscsiadm -m node --logout', shell=True)
    check_output('iscsiadm -m node -o delete', shell=True)
    rpc.iscsi_delete_initiator_group(initiator_tag)
    rpc.iscsi_delete_portal_group(portal_tag)
    rpc.iscsi_delete_target_node(name)
    output = rpc.scsi_get_devices()
    jsonvalues = json.loads(output)
    verify(
        not jsonvalues,
        1,
        f"scsi_get_devices returned {jsonvalues}, expected empty",
    )


    print("verify_scsi_devices_rpc_methods passed")


def create_malloc_bdevs_rpc_methods(rpc_py, rpc_param):
    rpc = spdk_rpc(rpc_py)

    for _ in range(1, rpc_param['lun_total'] + 1):
        rpc.bdev_malloc_create(rpc_param['malloc_bdev_size'], rpc_param['malloc_block_size'])

    print("create_malloc_bdevs_rpc_methods passed")


def verify_portal_groups_rpc_methods(rpc_py, rpc_param):
    rpc = spdk_rpc(rpc_py)
    output = rpc.iscsi_get_portal_groups()
    jsonvalues = json.loads(output)
    verify(
        not jsonvalues,
        1,
        f"iscsi_get_portal_groups returned {jsonvalues} groups, expected empty",
    )


    lo_ip = (target_ip, other_ip)
    for idx, value in enumerate(lo_ip):
        # The portal group tag must start at 1
        tag = idx + 1
        rpc.iscsi_create_portal_group(tag, f"{value}:{rpc_param['port']}")
        output = rpc.iscsi_get_portal_groups()
        jsonvalues = json.loads(output)
        verify(
            len(jsonvalues) == tag,
            1,
            f"iscsi_get_portal_groups returned {len(jsonvalues)} groups, expected {tag}",
        )


    tag_list = []
    for idx, value in enumerate(jsonvalues):
        verify(
            value['portals'][0]['host'] == lo_ip[idx],
            1,
            f"host value is {value['portals'][0]['host']}, expected {rpc_param['target_ip']}",
        )

        verify(
            value['portals'][0]['port'] == str(rpc_param['port']),
            1,
            f"port value is {value['portals'][0]['port']}, expected {str(rpc_param['port'])}",
        )

        tag_list.append(value['tag'])
        verify(
            value['tag'] == idx + 1,
            1,
            f"tag value is {value['tag']}, expected {idx + 1}",
        )


    for idx, value in enumerate(tag_list):
        rpc.iscsi_delete_portal_group(value)
        output = rpc.iscsi_get_portal_groups()
        jsonvalues = json.loads(output)
        verify(
            len(jsonvalues) == (len(tag_list) - (idx + 1)),
            1,
            f"get_portal_group returned {len(jsonvalues)} groups, expected {len(tag_list) - (idx + 1)}",
        )

        if not jsonvalues:
            break

        for jidx, jvalue in enumerate(jsonvalues):
            verify(
                jvalue['portals'][0]['host'] == lo_ip[idx + jidx + 1],
                1,
                f"host value is {jvalue['portals'][0]['host']}, expected {lo_ip[idx + jidx + 1]}",
            )

            verify(
                jvalue['portals'][0]['port'] == str(rpc_param['port']),
                1,
                f"port value is {jvalue['portals'][0]['port']}, expected {str(rpc_param['port'])}",
            )

            verify(
                jvalue['tag'] != value
                or jvalue['tag'] == tag_list[idx + jidx + 1],
                1,
                f"tag value is {jvalue['tag']}, expected {tag_list[idx + jidx + 1]} and not {value}",
            )


    print("verify_portal_groups_rpc_methods passed")


def verify_initiator_groups_rpc_methods(rpc_py, rpc_param):
    rpc = spdk_rpc(rpc_py)
    output = rpc.iscsi_get_initiator_groups()
    jsonvalues = json.loads(output)
    verify(
        not jsonvalues,
        1,
        f"iscsi_get_initiator_groups returned {jsonvalues}, expected empty",
    )

    for idx, value in enumerate(rpc_param['netmask']):
        # The initiator group tag must start at 1
        tag = idx + 1
        rpc.iscsi_create_initiator_group(tag, rpc_param['initiator_name'], value)
        output = rpc.iscsi_get_initiator_groups()
        jsonvalues = json.loads(output)
        verify(
            len(jsonvalues) == tag,
            1,
            f"iscsi_get_initiator_groups returned {len(jsonvalues)} groups, expected {tag}",
        )


    tag_list = []
    for idx, value in enumerate(jsonvalues):
        verify(
            value['initiators'][0] == rpc_param['initiator_name'],
            1,
            f"initiator value is {value['initiators'][0]}, expected {rpc_param['initiator_name']}",
        )

        tag_list.append(value['tag'])
        verify(
            value['tag'] == idx + 1,
            1,
            f"tag value is {value['tag']}, expected {idx + 1}",
        )

        verify(
            value['netmasks'][0] == rpc_param['netmask'][idx],
            1,
            f"netmasks value is {value['netmasks'][0]}, expected {rpc_param['netmask'][idx]}",
        )


    for idx, value in enumerate(rpc_param['netmask']):
        tag = idx + 1
        rpc.iscsi_initiator_group_remove_initiators(tag, '-n', rpc_param['initiator_name'], '-m', value)

    output = rpc.iscsi_get_initiator_groups()
    jsonvalues = json.loads(output)
    verify(
        len(jsonvalues) == tag,
        1,
        f"iscsi_get_initiator_groups returned {len(jsonvalues)} groups, expected {tag}",
    )


    for idx, value in enumerate(jsonvalues):
        verify(
            value['tag'] == idx + 1,
            1,
            f"tag value is {value['tag']}, expected {idx + 1}",
        )

        initiators = value.get('initiators')
        verify(
            len(initiators) == 0,
            1,
            f"length of initiator list is {len(initiators)}, expected 0",
        )

        netmasks = value.get('netmasks')
        verify(
            len(netmasks) == 0,
            1,
            f"length of netmask list is {len(netmasks)}, expected 0",
        )


    for idx, value in enumerate(rpc_param['netmask']):
        tag = idx + 1
        rpc.iscsi_initiator_group_add_initiators(tag, '-n', rpc_param['initiator_name'], '-m', value)
    output = rpc.iscsi_get_initiator_groups()
    jsonvalues = json.loads(output)
    verify(
        len(jsonvalues) == tag,
        1,
        f"iscsi_get_initiator_groups returned {len(jsonvalues)} groups, expected {tag}",
    )


    tag_list = []
    for idx, value in enumerate(jsonvalues):
        verify(
            value['initiators'][0] == rpc_param['initiator_name'],
            1,
            f"initiator value is {value['initiators'][0]}, expected {rpc_param['initiator_name']}",
        )

        tag_list.append(value['tag'])
        verify(
            value['tag'] == idx + 1,
            1,
            f"tag value is {value['tag']}, expected {idx + 1}",
        )

        verify(
            value['netmasks'][0] == rpc_param['netmask'][idx],
            1,
            f"netmasks value is {value['netmasks'][0]}, expected {rpc_param['netmask'][idx]}",
        )


    for idx, value in enumerate(tag_list):
        rpc.iscsi_delete_initiator_group(value)
        output = rpc.iscsi_get_initiator_groups()
        jsonvalues = json.loads(output)
        verify(
            len(jsonvalues) == (len(tag_list) - (idx + 1)),
            1,
            f"iscsi_get_initiator_groups returned {len(jsonvalues)} groups, expected {len(tag_list) - (idx + 1)}",
        )

        if not jsonvalues:
            break
        for jidx, jvalue in enumerate(jsonvalues):
            verify(
                jvalue['initiators'][0] == rpc_param['initiator_name'],
                1,
                f"initiator value is {jvalue['initiators'][0]}, expected {rpc_param['initiator_name']}",
            )

            verify(
                jvalue['tag'] != value
                or jvalue['tag'] == tag_list[idx + jidx + 1],
                1,
                f"tag value is {jvalue['tag']}, expected {tag_list[idx + jidx + 1]} and not {value}",
            )

            verify(
                jvalue['netmasks'][0] == rpc_param['netmask'][idx + jidx + 1],
                1,
                f"netmasks value is {jvalue['netmasks'][0]}, expected {rpc_param['netmask'][idx + jidx + 1]}",
            )


    print("verify_initiator_groups_rpc_method passed.")


def verify_target_nodes_rpc_methods(rpc_py, rpc_param):
    rpc = spdk_rpc(rpc_py)
    output = rpc.iscsi_get_options()
    jsonvalues = json.loads(output)
    nodebase = jsonvalues['node_base']
    output = rpc.iscsi_get_target_nodes()
    jsonvalues = json.loads(output)
    verify(
        not jsonvalues,
        1,
        f"iscsi_get_target_nodes returned {jsonvalues}, expected empty",
    )


    rpc.bdev_malloc_create(rpc_param['malloc_bdev_size'], rpc_param['malloc_block_size'])
    rpc.iscsi_create_portal_group(
        portal_tag, f"{rpc_param['target_ip']}:{str(rpc_param['port'])}"
    )

    rpc.iscsi_create_initiator_group(initiator_tag, rpc_param['initiator_name'], rpc_param['netmask'])

    lun_mapping = "Malloc" + str(rpc_param['lun_total']) + ":0"
    net_mapping = f"{portal_tag}:{initiator_tag}"
    rpc.iscsi_create_target_node(rpc_param['target_name'], rpc_param['alias_name'], lun_mapping,
                                 net_mapping, rpc_param['queue_depth'], '-d')
    output = rpc.iscsi_get_target_nodes()
    jsonvalues = json.loads(output)
    verify(
        len(jsonvalues) == 1,
        1,
        f"iscsi_get_target_nodes returned {len(jsonvalues)} nodes, expected 1",
    )

    bdev_name = jsonvalues[0]['luns'][0]['bdev_name']
    verify(
        bdev_name == "Malloc" + str(rpc_param['lun_total']),
        1,
        f"bdev_name value is {jsonvalues[0]['luns'][0]['bdev_name']}, expected Malloc{str(rpc_param['lun_total'])}",
    )

    name = jsonvalues[0]['name']
    verify(
        name == f"{nodebase}:" + rpc_param['target_name'],
        1,
        f"""target name value is {name}, expected {f"{nodebase}:" + rpc_param['target_name']}""",
    )

    verify(
        jsonvalues[0]['alias_name'] == rpc_param['alias_name'],
        1,
        f"target alias_name value is {jsonvalues[0]['alias_name']}, expected {rpc_param['alias_name']}",
    )

    verify(
        jsonvalues[0]['luns'][0]['lun_id'] == 0,
        1,
        f"lun id value is {jsonvalues[0]['luns'][0]['lun_id']}, expected 0",
    )

    verify(
        jsonvalues[0]['pg_ig_maps'][0]['ig_tag'] == int(initiator_tag),
        1,
        f"initiator group tag value is {jsonvalues[0]['pg_ig_maps'][0]['ig_tag']}, expected {initiator_tag}",
    )

    verify(
        jsonvalues[0]['queue_depth'] == rpc_param['queue_depth'],
        1,
        f"queue depth value is {jsonvalues[0]['queue_depth']}, expected {rpc_param['queue_depth']}",
    )

    verify(
        jsonvalues[0]['pg_ig_maps'][0]['pg_tag'] == int(portal_tag),
        1,
        f"portal group tag value is {jsonvalues[0]['pg_ig_maps'][0]['pg_tag']}, expected {portal_tag}",
    )

    verify(
        jsonvalues[0]['disable_chap'] == rpc_param['disable_chap'],
        1,
        f"disable chap value is {jsonvalues[0]['disable_chap']}, expected {rpc_param['disable_chap']}",
    )

    verify(
        jsonvalues[0]['mutual_chap'] == rpc_param['mutual_chap'],
        1,
        f"chap mutual value is {jsonvalues[0]['mutual_chap']}, expected {rpc_param['mutual_chap']}",
    )

    verify(
        jsonvalues[0]['require_chap'] == rpc_param['require_chap'],
        1,
        f"chap required value is {jsonvalues[0]['require_chap']}, expected {rpc_param['require_chap']}",
    )

    verify(
        jsonvalues[0]['chap_group'] == rpc_param['chap_group'],
        1,
        f"chap auth group value is {jsonvalues[0]['chap_group']}, expected {rpc_param['chap_group']}",
    )

    verify(
        jsonvalues[0]['header_digest'] == rpc_param['header_digest'],
        1,
        f"header digest value is {jsonvalues[0]['header_digest']}, expected {rpc_param['header_digest']}",
    )

    verify(
        jsonvalues[0]['data_digest'] == rpc_param['data_digest'],
        1,
        f"data digest value is {jsonvalues[0]['data_digest']}, expected {rpc_param['data_digest']}",
    )

    lun_id = '1'
    rpc.iscsi_target_node_add_lun(name, bdev_name, "-i", lun_id)
    output = rpc.iscsi_get_target_nodes()
    jsonvalues = json.loads(output)
    verify(
        jsonvalues[0]['luns'][1]['bdev_name']
        == "Malloc" + str(rpc_param['lun_total']),
        1,
        f"bdev_name value is {jsonvalues[0]['luns'][0]['bdev_name']}, expected Malloc{str(rpc_param['lun_total'])}",
    )

    verify(
        jsonvalues[0]['luns'][1]['lun_id'] == 1,
        1,
        f"lun id value is {jsonvalues[0]['luns'][1]['lun_id']}, expected 1",
    )


    rpc.iscsi_delete_target_node(name)
    output = rpc.iscsi_get_target_nodes()
    jsonvalues = json.loads(output)
    verify(
        not jsonvalues,
        1,
        f"iscsi_get_target_nodes returned {jsonvalues}, expected empty",
    )


    rpc.iscsi_create_target_node(rpc_param['target_name'], rpc_param['alias_name'], lun_mapping,
                                 net_mapping, rpc_param['queue_depth'], '-d')

    rpc.iscsi_delete_portal_group(portal_tag)
    rpc.iscsi_delete_initiator_group(initiator_tag)
    rpc.iscsi_delete_target_node(name)
    output = rpc.iscsi_get_target_nodes()
    jsonvalues = json.loads(output)
    if not jsonvalues:
        print("This issue will be fixed later.")

    print("verify_target_nodes_rpc_methods passed.")


def help_get_interface_ip_list(rpc_py, nic_name):
    rpc = spdk_rpc(rpc_py)
    nics = json.loads(rpc.net_get_interfaces())
    nic = [x for x in nics if x["name"] == nic_name]
    verify(
        len(nic) != 0,
        1,
        f'Nic name: {nic_name} is not found in {[x["name"] for x in nics]}',
    )

    return nic[0]["ip_addr"]


if __name__ == "__main__":

    rpc_py = sys.argv[1]

    try:
        verify_log_flag_rpc_methods(rpc_py, rpc_param)
        create_malloc_bdevs_rpc_methods(rpc_py, rpc_param)
        verify_portal_groups_rpc_methods(rpc_py, rpc_param)
        verify_initiator_groups_rpc_methods(rpc_py, rpc_param)
        verify_target_nodes_rpc_methods(rpc_py, rpc_param)
        verify_scsi_devices_rpc_methods(rpc_py)
        verify_iscsi_connection_rpc_methods(rpc_py)
    except RpcException as e:
        print(f"{e.message}. Exiting with status {e.retval}")
        raise e
    except Exception as e:
        raise e

    sys.exit(0)
