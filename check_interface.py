#!/usr/bin/python3
import argparse
import json
import os
import re
import time
from collections import defaultdict

from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi import ContextData, CommunityData, UdpTransportTarget, nextCmd, getCmd, ObjectType, ObjectIdentity
from pysnmp.proto.errind import ErrorIndication

from vars import eth_status, exit_status_map, CISCO_VLAN_MEMBERSHIP

default_if_name_format = "^(Gigabit|Fast)Ethernet.*|eth\d+|enp\d.*|wlan\d+|tun\d+|ppp\d+$"


def get_id_from_name(if_target_name, if_names):
    if_id = None
    for if_name in if_names:
        if re.match(if_target_name, str(if_name[0][1])):
            if_id = os.path.splitext(str(if_name[0][0]))[1][1:]
            break
    return if_id


# def if_discover(filt_by_names=None):
#     type_err_ind, type_err_stat, type_err_idx, if_types = cmdGen.nextCmd(
#         community,
#         transport,
#         ObjectIdentity('IF-MIB', 'ifType').resolveWithMib(view)
#     )
#     name_err_ind, name_err_stat, name_err_idx, if_names = cmdGen.nextCmd(
#         community,
#         transport,
#         ObjectIdentity('IF-MIB', 'ifDescr').resolveWithMib(view)
#     )
#
#     if filt_by_names is not None:
#         name_filter = re.compile(filt_by_names)
#         filt_if_names = [if_name for if_name in range(0, len(if_names)) if
#                          iana[if_types[if_name][0][1]] != "softwareLoopback" and name_filter.match(
#                              str(if_names[if_name][0][1]))]
#     else:
#         filt_if_names = [if_name for if_name in range(0, len(if_names)) if
#                          iana[if_types[if_name][0][1]] != "softwareLoopback"]
#
#     if_list = [
#         json.dumps({'name': str(if_names[ifIdx][0][1]), 'check': check_if_status}) for ifIdx in filt_if_names
#     ]
#
#     return if_list


# def if_update():
#     """
#     When creating the object get all the interfaces and set them to be monitored
#     """
#     # "^(Giga.*|Fast)Ethernet.*"
#     # "^eth\d+|enp\d.*|wlan\d+|tun\d+$"
#     new_interfaces = if_discover(new_int_name_format)
#     s = requests.Session()
#     s.verify = "/etc/pki/tls/certs/ca-bundle.crt"
#
#     url = "https://flavio.piccinelli:icinga19()@icinga.scll/icingaweb2/director/host?name={}".format(hostname)
#     headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
#     r = s.get(url, headers=headers)
#
#     old_content = json.loads(r.content.decode())
#     old_vars = old_content["vars"] if "vars" in old_content else {}
#
#     new_vars = {
#         "monitored_interfaces": new_interfaces
#     }
#     data = {
#         "vars": merge_dicts(old_vars, new_vars)
#     }
#     r = s.post(url, data=json.dumps(data), headers=headers)
#     if r.status_code != 200:
#         sys.exit(1)
#
#     r = s.post("https://flavio.piccinelli:icinga19()@icinga.scll/icingaweb2/director/config/deploy", headers=headers)
#     if r.status_code != 200:
#         sys.exit(1)
#
#     print("Added new interfaces: {}".format(json.dumps(new_interfaces, indent=2)))
#

def get_if_spec_from_cmd(cmd, ifs_search):
    ifs_spec = defaultdict(list)
    ifs_search_map = {if_search: re.compile("^" + if_search + "$") for if_search in ifs_search}

    for err_ind, err_stat, err_idx, if_snmp in cmd:
        if err_ind is not None:
            raise err_ind

        if_name = str(if_snmp[1][1])
        if_search_match = None
        for if_search, if_regex in ifs_search_map.items():
            if if_regex.match(if_name):
                if_search_match = if_search
                break
        if if_search_match is not None:
            ifs_spec[if_search_match].append({
                "index": int(if_snmp[0][1]),
                "name": if_name,
                "status": eth_status[int(if_snmp[2][1])],
                "adm_status": eth_status[int(if_snmp[3][1])],
                "speed": int(if_snmp[4][1]),
                "in": int(if_snmp[5][1]),
                "out": int(if_snmp[6][1])
            })

    return ifs_spec


def if_check(interfaces_search):
    if_status = []
    if_perf = []
    if_error = []
    exit_code = exit_status_map["OK"]

    cmd = nextCmd(
        engine, community, transport, context,
        ObjectType(ObjectIdentity('IF-MIB', 'ifIndex')),
        ObjectType(ObjectIdentity('IF-MIB', 'ifDescr')),
        ObjectType(ObjectIdentity('IF-MIB', 'ifOperStatus')),
        ObjectType(ObjectIdentity('IF-MIB', 'ifAdminStatus')),
        ObjectType(ObjectIdentity('IF-MIB', 'ifSpeed')),
        ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets')),
        ObjectType(ObjectIdentity('IF-MIB', 'ifOutOctets')),
        lexicographicMode=False)

    timestamp = round(time.time())
    try:
        ifs_spec = get_if_spec_from_cmd(cmd, interfaces_search)
    except ErrorIndication as e:
        exit_code = exit_status_map["UNKNOWN"]
        if_error.append(e)
    else:
        for if_search in interfaces_search:
            if if_search in ifs_spec:
                for if_spec in ifs_spec[if_search]:

                    if_io_min = "-"
                    if_io_max = "-"
                    if_in_warning = "-"
                    if_out_warning = "-"
                    if_in_critical = "-"
                    if_out_critical = "-"
                    if_in_mbps = "-"
                    if_out_mbps = "-"
                    if_in_util = "-"
                    if_out_util = "-"
                    if_vlan = None

                    if_name = if_spec["name"]
                    if_oper_status = if_spec["status"]
                    if_adm_status = if_spec["adm_status"]
                    if_speed = if_spec["speed"]
                    if_in_tot = if_spec["in"]
                    if_out_tot = if_spec["out"]

                    if get_vlan:
                        err_ind, err_stat, err_idx, if_snmp = next(getCmd(
                            engine, community, transport, context,
                            ObjectType(
                                ObjectIdentity('SNMPv2-SMI', 'enterprises', CISCO_VLAN_MEMBERSHIP, if_spec["index"]))
                        ))
                        try:
                            if_vlan = " - vLAN {}".format(int(if_snmp[0][1]))
                        except ValueError:
                            pass

                    if_metrics = None
                    if_file = "/tmp/_snmp-check_{}_{}".format(host, if_name.replace("/", "_"))
                    try:
                        with open(if_file, 'r') as data_file:
                            if_metrics = json.load(data_file)
                    except (OSError, ValueError):
                        pass

                    try:
                        with open(if_file, 'w') as data_file:
                            json.dump({
                                "timestamp": timestamp,
                                "if_in_octets": if_in_tot,
                                "if_out_octets": if_out_tot
                            }, data_file)
                    except OSError:
                        pass

                    if check_if_status:
                        if if_oper_status != if_adm_status:
                            exit_code = exit_status_map["WARNING"]
                            if_error.append("{}: (is {} not {})".format(if_name, if_oper_status, if_adm_status))
                            if_oper_status = "({})".format(if_oper_status)

                    if if_speed > 0:
                        if_io_min = "0"
                        if_io_max = "{:.2f}".format(if_speed / 1000000)
                        if_in_warning = "{:.2f}".format(if_speed * warning_threshold[0] / 100000000)
                        if_out_warning = "{:.2f}".format(if_speed * warning_threshold[1] / 100000000)
                        if_in_critical = "{:.2f}".format(if_speed * critical_threshold[0] / 100000000)
                        if_out_critical = "{:.2f}".format(if_speed * critical_threshold[1] / 100000000)

                    if if_metrics is not None and if_spec["status"] == "UP":
                        time_delta = timestamp - if_metrics['timestamp']
                        if not octects_only:
                            if_in_mbps = "{:.2f}".format(
                                (if_in_tot - if_metrics['if_in_octets']) * (8 / 1000000) / time_delta)
                            if_out_mbps = "{:.2f}".format(
                                (if_out_tot - if_metrics['if_out_octets']) * (8 / 1000000) / time_delta)

                        if if_speed > 0:
                            if_tot_band = time_delta * if_speed
                            if_in_util = "{:.2f}".format(
                                (if_in_tot - if_metrics['if_in_octets']) * 8 * 100 / if_tot_band)
                            if_out_util = "{:.2f}".format(
                                (if_out_tot - if_metrics['if_out_octets']) * 8 * 100 / if_tot_band)

                    if_status.append(
                        "{}: ({}%,{}%) {}{}".format(
                            if_name, if_in_util, if_out_util, if_oper_status,
                            if_vlan if if_vlan is not None else ""))

                    if octects_only:
                        if_perf.append("'{} in'={}c".format(if_name, if_in_tot))
                        if_perf.append("'{} out'={}c".format(if_name, if_out_tot))
                    else:
                        if_perf.append("'{} in'={}Mb;{};{};{};{}".format(
                            if_name, if_in_mbps, if_in_warning, if_in_critical, if_io_min, if_io_max))
                        if_perf.append("'{} out'={}Mb;{};{};{};{}".format(
                            if_name, if_out_mbps, if_out_warning, if_out_critical, if_io_min, if_io_max))

            else:
                exit_code = exit_status_map["CRITICAL"]
                if_error.append("{}: {}".format(if_search, "interface not found"))

    if len(if_error) == 0:
        print("All interfaces OK")
    else:
        print("Interfaces ERROR", *if_error, sep=" - ")

    if len(if_status) > 0:
        print(*if_status, sep="\n")
    if len(if_perf) > 0:
        print("|" + " ".join(if_perf))

    return exit_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", type=str,
                        help="SNMP host", required=True)
    parser.add_argument("-I", "--icingahostname", type=str,
                        help="Icinga hostname")
    parser.add_argument("-C", "--community", type=str,
                        help="SNMP community", required=True)
    parser.add_argument("-t", "--timeout", type=int, default=1,
                        help="SNMP timeout")
    parser.add_argument("-i", "--interfaces", action='append', type=str,
                        help="Interfaces List")
    parser.add_argument("-f", "--newintformat", type=str,
                        default=default_if_name_format,
                        help="New interfaces format")
    parser.add_argument("-v", "--vlan", action="store_true",
                        help="Get vLAN")
    parser.add_argument("-s", "--checkstatus", action="store_true",
                        help="Check interface status")
    parser.add_argument("-o", "--octectsonly", action="store_true",
                        help="I/O usage critical")
    parser.add_argument("-w", "--warning", type=list, default=[60, 60],
                        help="I/O usage warning")
    parser.add_argument("-c", "--critical", type=list, default=[95, 95],
                        help="I/O usage critical")
    args = parser.parse_args()

    host = args.host
    hostname = args.icingahostname
    community_str = args.community
    timeout = args.timeout
    interfaces = args.interfaces
    new_int_name_format = args.newintformat
    check_if_status = args.checkstatus
    get_vlan = args.vlan
    warning_threshold = args.warning
    critical_threshold = args.critical
    octects_only = args.octectsonly

    engine = SnmpEngine()
    context = ContextData()
    community = CommunityData(community_str, mpModel=1)
    transport = UdpTransportTarget((host, 161), timeout=timeout)

    if interfaces is not None:
        exit_status = if_check(interfaces)
        exit(exit_status)
    else:
        # if_update()
        print("No mount points defined")
        exit(exit_status_map["UNKNOWN"])
