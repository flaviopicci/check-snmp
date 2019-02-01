#!/usr/bin/python3

import argparse
import os
import re
from collections import defaultdict

from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, nextCmd, \
    ObjectIdentity
from pysnmp.proto.errind import ErrorIndication

from vars import exit_status_map

message_template = "{}: {:.1f}% used ({}MiB/{}MiB) - {}"
not_found_message_template = "{}: volume not found!"
volume_error_template = "{} {}: {:.1f}% used"
performance_template = "{}={}{};{};{};0;{}"

b_to_mb = pow(2, 20)


def get_id_from_name(target_name, names):
    target_name = re.compile("^{}$".format(target_name))
    res_ids = []
    for name in names:
        if target_name.match(name):
            res_ids.append({
                "id": os.path.splitext(str(name[0][0]))[1][1:],
                "name": str(name[0][1])
            })
    return res_ids


def get_volumes_spec_from_cmd(cmd, volumes_search):
    volumes_spec = defaultdict(list)
    volumes_search_map = {volume_search: re.compile("^" + volume_search + "$") for volume_search in volumes_search}

    for err_ind, err_stat, err_idx, volume_snmp in cmd:
        if err_ind is not None:
            raise err_ind

        volume_name = str(volume_snmp[0][1])
        volume_search_match = None
        for volume_search, volume_regex in volumes_search_map.items():
            if volume_regex.match(volume_name):
                volume_search_match = volume_search
                break
        if volume_search_match is not None:
            volume_au = int(volume_snmp[1][1])
            volumes_spec[volume_search_match].append({
                "name": volume_name,
                "size": int(volume_snmp[2][1]) * volume_au,
                "used": int(volume_snmp[3][1]) * volume_au
            })

    return volumes_spec


def storage_check(volumes_search):
    exit_code = exit_status_map["OK"]
    volume_errors = []
    performance_data = []

    cmd = nextCmd(
        engine, community, transport, context,
        ObjectType(ObjectIdentity('HOST-RESOURCES-MIB', 'hrStorageDescr')),
        ObjectType(ObjectIdentity('HOST-RESOURCES-MIB', 'hrStorageAllocationUnits').addMibSource('.')),
        ObjectType(ObjectIdentity('HOST-RESOURCES-MIB', 'hrStorageSize')),
        ObjectType(ObjectIdentity('HOST-RESOURCES-MIB', 'hrStorageUsed')),
        lexicographicMode=False)

    try:
        volumes_spec = get_volumes_spec_from_cmd(cmd, volumes_search)
    except ErrorIndication as e:
        exit_code = exit_status_map["UNKNOWN"]
        volume_errors.append(e)
    else:
        for volume_search in volumes_search:

            if volume_search in volumes_spec:
                volume_status = "OK"
                for volume_spec in volumes_spec[volume_search]:

                    used_perc = volume_spec["used"] / volume_spec["size"]
                    total_size = int(volume_spec["size"] / b_to_mb)  # total size in MiB
                    used_space = int(volume_spec["used"] / b_to_mb)  # total size in MiB

                    if used_perc > critical_threshold:
                        volume_status = "CRITICAL"
                    elif used_perc > warning_threshold:
                        volume_status = "WARNING"

                    if volume_status != "OK":
                        volume_errors.append(
                            volume_error_template.format(volume_status, volume_spec["name"], used_perc * 100))

                    performance_data.append(
                        performance_template.format(
                            volume_spec["name"], used_space, "MB",
                            int(total_size * warning_threshold), int(total_size * critical_threshold), total_size)
                    )
                    if exit_code < exit_status_map[volume_status]:
                        exit_code = exit_status_map[volume_status]
            else:
                volume_status = "CRITICAL"
                # performance_data.append(performance_template.format(volume_name, "-", "MB", "-", "-", "-"))
                volume_errors.append(
                    not_found_message_template.format(volume_search)
                )
                exit_code = exit_status_map[volume_status]

    if len(volume_errors) > 0:
        print("Storage ERROR", *volume_errors, sep=" - ")
    else:
        print("All volumes OK")

    if len(performance_data) > 0:
        print("|" + " ".join(performance_data))

    return exit_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", type=str,
                        help="SNMP host", required=True)
    parser.add_argument("-C", "--community", type=str,
                        help="SNMP community", required=True)
    parser.add_argument("-t", "--timeout", type=int, default=1,
                        help="SNMP timeout")
    parser.add_argument("-v", "--volumes", action='append', type=str,
                        help="Volumes List")
    parser.add_argument("-w", "--warning", type=int, default=80,
                        help="I/O usage warning")
    parser.add_argument("-c", "--critical", type=int, default=95,
                        help="I/O usage critical")
    args = parser.parse_args()

    host = args.host
    community_str = args.community
    timeout = args.timeout
    volumes = args.volumes
    warning_threshold = args.warning / 100
    critical_threshold = args.critical / 100

    engine = SnmpEngine()
    context = ContextData()
    community = CommunityData(community_str, mpModel=1)
    transport = UdpTransportTarget((host, 161), timeout=timeout)

    if volumes is not None:
        exit_status = storage_check(volumes)
        exit(exit_status)
    else:
        print("No mount points defined")
        exit(exit_status_map["UNKNOWN"])
