#!/usr/bin/env python2

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
from collections import OrderedDict
import json
import logging
import os
import re
import struct
import subprocess
import sys

import grpc
from p4 import p4runtime_pb2
from p4.config import p4info_pb2
from p4.tmp import p4config_pb2
import google.protobuf.text_format

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PTF runner")

def error(msg, *args, **kwargs):
    logger.error(msg, *args, **kwargs)

def warn(msg, *args, **kwargs):
    logger.warn(msg, *args, **kwargs)

def info(msg, *args, **kwargs):
    logger.info(msg, *args, **kwargs)


def check_ifaces(ifaces):
    '''
    Checks that required interfaces exist.
    '''
    ifconfig_out = subprocess.check_output(['ifconfig'])
    iface_list = re.findall(r'^(\S+)', ifconfig_out, re.S | re.M)
    present_ifaces = set(iface_list)
    ifaces = set(ifaces)
    return ifaces <= present_ifaces

def build_config(prog_name, bin_path, cxt_json_path):
    device_config = p4config_pb2.P4DeviceConfig()
    with open(bin_path, 'rb') as bin_f:
        with open(cxt_json_path, 'r') as cxt_json_f:
            device_config.device_data = ""
            device_config.device_data += struct.pack("<i", len(prog_name))
            device_config.device_data += prog_name
            bin = bin_f.read()
            device_config.device_data += struct.pack("<i", len(bin))
            device_config.device_data += bin
            cxt_json = cxt_json_f.read()
            device_config.device_data += struct.pack("<i", len(cxt_json))
            device_config.device_data += cxt_json
    return device_config

def update_config(p4info_path, bin_path, cxt_json_path, grpc_addr, device_id):
    '''
    Performs a SetForwardingPipelineConfig on the device
    '''
    channel = grpc.insecure_channel(grpc_addr)
    stub = p4runtime_pb2.P4RuntimeStub(channel)

    info("Sending P4 config")
    request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
    request.device_id = device_id
    config = request.config
    with open(p4info_path, 'r') as p4info_f:
        google.protobuf.text_format.Merge(p4info_f.read(), config.p4info)
    device_config = build_config("name", bin_path, cxt_json_path)
    config.p4_device_config = device_config.SerializeToString()
    request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
    try:
        response = stub.SetForwardingPipelineConfig(request)
    except Exception as e:
        error("Error during SetForwardingPipelineConfig")
        error(str(e))
        return False
    return True

def run_test(p4info_path, grpc_addr, device_id,
             ptfdir, port_map_path, platform=None, extra_args=[]):
    '''
    Runs PTF tests included in provided directory.
    Device must be running and configfured with appropriate P4 program.
    '''
    # TODO: check schema?
    # "ptf_port" is ignored for now, we assume that ports are provided by
    # increasing values of ptf_port, in the range [0, NUM_IFACES[.
    port_map = OrderedDict()
    with open(port_map_path, 'r') as port_map_f:
        port_list = json.load(port_map_f)
        for entry in port_list:
            ptf_port = entry["ptf_port"]  # ignored
            p4_port = entry["p4_port"]
            iface_name = entry["iface_name"]
            port_map[p4_port] = iface_name

    if not check_ifaces(port_map.values()):
        error("Some interfaces are missing")
        return False

    ifaces = []
    # FIXME
    # find base_test.py
    pypath = os.path.dirname(os.path.abspath(__file__))
    if 'PYTHONPATH' in os.environ:
        os.environ['PYTHONPATH'] += ":" + pypath
    else:
        os.environ['PYTHONPATH'] = pypath
    for iface_idx, iface_name in port_map.items():
        ifaces.extend(['-i', '{}@{}'.format(iface_idx, iface_name)])
    cmd = ['ptf']
    cmd.extend(['--test-dir', ptfdir])
    cmd.extend(ifaces)
    test_params = 'p4info=\'{}\''.format(p4info_path)
    test_params += ';grpcaddr=\'{}\''.format(grpc_addr)
    if platform is not None:
        test_params += ';pltfm=\'{}\''.format(platform)
    cmd.append('--test-params={}'.format(test_params))
    cmd.extend(extra_args)
    info("Executing PTF command: {}".format(' '.join(cmd)))

    try:
        # we want the ptf output to be sent to stdout
        p = subprocess.Popen(cmd)
        p.wait()
    except:
        error("Error when running PTF tests")
        return False
    return p.returncode == 0

def check_ptf():
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call(['ptf', '--version'],
                                  stdout=devnull, stderr=devnull)
        return True
    except subprocess.CalledProcessError:
        return True
    except OSError:  # PTF not found
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Compile the provided P4 program and run PTF tests on it")
    parser.add_argument('--p4c-out', type=str, required=True,
                        help='Location of p4c outout (p4info + config + context.json')
    parser.add_argument('--grpc-addr', type=str, default='localhost:50051',
                        help='Address to use to connect to P4 Runtime server')
    parser.add_argument('--device-id', type=int, default=0,
                        help='Device id for device under test')
    parser.add_argument('--ptf-dir', type=str, required=True,
                        help='Directory containing PTF tests')
    parser.add_argument('--port-map', type=str, required=True,
                        help='Path to JSON port mapping')
    parser.add_argument('--platform', type=str, required=False,
                        help='String identifying the target platform on which tests are run')
    parser.add_argument('--device', type=str,
                        choices=['tofino'], default='tofino',
                        help='Target device')
    args, unknown_args = parser.parse_known_args()

    if not check_ptf():
        error("Cannot find PTF executable")
        sys.exit(1)

    device = args.device
    p4info_path = os.path.join(args.p4c_out, 'p4info.proto.txt')
    bin_path = os.path.join(args.p4c_out, device + '.bin')
    cxt_json_path = os.path.join(args.p4c_out, 'context.json')
    if not os.path.exists(p4info_path):
        error("P4Info file {} not found".format(p4info_path))
        sys.exit(1)
    if not os.path.exists(bin_path):
        error("Binary config file {} not found".format(bin_path))
        sys.exit(1)
    if not os.path.exists(cxt_json_path):
        error("Context json file {} not found".format(cxt_json_path))
        sys.exit(1)
    if not os.path.exists(args.port_map):
        print "Port map path '{}' does not exist".format(args.port_map)
        sys.exit(1)

    success = update_config(p4info_path, bin_path, cxt_json_path,
                            args.grpc_addr, args.device_id)
    if not success:
        sys.exit(2)
    success = run_test(p4info_path, args.grpc_addr, args.device_id,
                       args.ptf_dir, args.port_map, args.platform,
                       unknown_args)
    if not success:
        sys.exit(3)

if __name__ == '__main__':
    main()
