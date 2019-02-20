#!/usr/bin/python
#
# This script will create a set of VM that meets the WDP-Installer.sh needs
# It will generate the required conf file for you to script out the entire process
#
import os
import sys
from os.path import expanduser
import paramiko
import time
import json

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# Global variables...
debug_mode = False
num_master = 3
num_compute = 3
num_storage = 3
three_node = False
deploy_data = {}

proxy_ip = ""
proxy_ip_from_database = False
balancer_ip = {}
deploy_os_name = "Redhat"
deploy_os_ver = "7.4"
platform = "x"
cluster_information_ip_pass = []
node_hostName = []
parted_ip_list = []
one_partition = False
load_balance = False
external_access = False
conf_file = "wdp.conf"

#Docker disk
docker_partition = False
docker_partition_size = 500

# Dictionaries for disk name depends on the platform, key x means x86_64, p means power, reference from fyre api
IBM_DISK = {'x': '/dev/vdb', 'p': '/dev/vda'}
DATA_DISK = {'x': '/dev/vdc', 'p': '/dev/vdb'}

# Constants
FYRE_URL = "https://api.fyre.ibm.com/rest/v1/"
PROXY_REQUEST_URL = "http://mavin1.fyre.ibm.com/requestStaticIP"
PROXY_GET_IP_URL = "http://mavin1.fyre.ibm.com/requestProxyIPbyName"

DEV_CONF_FILE = "wdp_dev.conf"
SSH_KEY_FILE = expanduser("~") + "/.ssh/id_rsa.pub"
SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"



#Disk partition script
part_disk_script_name = "dsx_part_script"
part_disk_script = """#!/bin/bash
if [[ $# -ne 2 ]]; then
    echo "Requires a disk name and mounted path name"
    echo "$(basename $0) <disk> <path>"
    exit 1
fi
set -e
parted ${1} --script mklabel gpt
parted ${1} --script mkpart primary '0%' '100%'
mkfs.xfs -f -n ftype=1 ${1}1
mkdir -p ${2}
echo "${1}1       ${2}              xfs     defaults,noatime    1 2" >> /etc/fstab
mount ${2}
exit 0
"""
def write_part_script(name):
    global part_disk_script_name
    part_disk_script_name = part_disk_script_name + "_" + name
    file = open(part_disk_script_name, "w")
    file.writelines(part_disk_script)
    file.close()

# Print this script usage and exit 1
def usage(msg):
    print("""
{}
Usage: {} --user=<fyre_user> --key=<fyre_api_key> --cluster=<cluster_name> [options]
Options:
    --num-master=n      Number of master nodes will be create, default is 3
    --num-storage=n     Number of storage nodes will be create, default is 3
    --num-compute=n     Number of compute nodes will be create, default is 3
    --os-name=os_name   Os name has to be in the list provided from https://fyre.svl.ibm.com/help#fyre-api (default is RHEL)
    --os-version=x.x    Os version, this and --os-name has to come together (default is 7.4 for RHEL) 
    --3-nodes           Only create three master nodes with additional disk 1000, --num options will not take effective
    --one-partition     Using the same partition for data storage as the install
    --external-access   Creates wdp_dev.conf file containing master-1 public ip for installer to provide external web access
    --platform=<plat>   The platform architecture; either x for x86_64 or p for ppc64le (default is x86_64)
    --debug             Show more debug information
    --docker-raw-disk       add another disk for Device Mapper
""".format(msg, sys.argv[0]))
    sys.exit(1)


# Print information if debug enabled
def log(msg):
    if debug_mode:
        print(msg)


def get_proxy_ip(url, account_info):
    data_post = {
        'username': account_info[0],
        'api_key': account_info[1],
        'cluster_name': account_info[2]
    }
    try:
        r = requests.post(url, data=json.dumps(data_post))
        if r.status_code == 200:
            data = r.json()
            log("Proxy Ip found")
            return data['message']
        else:
            data = r.json()
            print (data['message'])
            log("Proxy Ip request fail")
            return None
    except:
        log("Proxy Ip request fail")
        return None


# Send request to Fyre and get json response
def sendRequest(query, account_info, data=None):
    auth = (account_info[0], account_info[1])
    url = FYRE_URL + query
    log("Sending url: " + url)
    if (data is None):
        resp = requests.post(url, auth=auth, verify=False)
    else:
        resp = requests.post(url, data=data, auth=auth, verify=False)
    if resp.status_code != 200:
        print("Request getting non-ok code ({}): {}".format(resp.status_code, url))
        sys.exit(1)
    return resp.json()


# Validate the user arguments
def validate_args():
    account_info = ["", "", ""]
    has_set_os = 0

    if not os.path.isfile(SSH_KEY_FILE):
        print("The ssh public key file {} does not exist".format(SSH_KEY_FILE))
        sys.exit(1)

    if "--debug" in sys.argv[1:]:
        print("enabled")
        global debug_mode
        debug_mode = True

    for cur_arg in sys.argv[1:]:
        if cur_arg.startswith("--user="):
            if cur_arg == "--user=":
                usage("User name cannot be empty")
            account_info[0] = cur_arg[(cur_arg.index("=") + 1):]
            log("User name is " + account_info[0])
        elif cur_arg.startswith("--key="):
            if cur_arg == "--key=":
                usage("API key cannot be empty")
            account_info[1] = cur_arg[(cur_arg.index("=") + 1):]
            log("API key is " + account_info[1])
        elif cur_arg.startswith("--cluster="):
            if cur_arg == "--cluster=":
                usage("Cluster name cannot be empty")
            account_info[2] = cur_arg[(cur_arg.index("=") + 1):]
            log("Cluster name is " + account_info[2])
        elif cur_arg.startswith("--num-master="):
            global num_master
            num_master = validate_node_num("--num-master=", cur_arg)
            log("There will be %d master nodes" % (num_master))
        elif cur_arg.startswith("--num-storage="):
            global num_storage
            num_storage = validate_node_num("--num-storage=", cur_arg)
            log("There will be %d storage nodes" % (num_storage))
        elif cur_arg.startswith("--num-compute="):
            global num_compute
            num_compute = validate_node_num("--num-compute=", cur_arg)
            log("There will be %d compute nodes" % (num_compute))
        elif cur_arg.startswith("--os-name="):
            global deploy_os_name
            deploy_os_name = cur_arg[(cur_arg.index("=") + 1):]
            log("OS will be {}".format(deploy_os_name))
            has_set_os += 1
        elif cur_arg.startswith("--os-version="):
            global deploy_os_ver
            deploy_os_ver = cur_arg[(cur_arg.index("=") + 1):]
            log("OS version will be {}".format(deploy_os_ver))
            has_set_os += 1
        elif cur_arg == "--3-nodes":
            global three_node
            three_node = True
        elif cur_arg == "--external-access":
            global external_access
            external_access = True
        elif cur_arg == "--one-partition":
            global one_partition
            one_partition = True
        elif cur_arg == '--docker-raw-disk':
            global docker_partition
            docker_partition = True
        elif cur_arg == "--load-balancer":
            global load_balance
            load_balance = True
        elif cur_arg.startswith("--platform="):
            global platform
            platform = cur_arg[(cur_arg.index("=") + 1):]
        elif cur_arg.startswith("--debug"):
            pass
        else:
            usage("Unrecongized parameter '%s'" % (cur_arg))

    if has_set_os == 1:
        usage("--os-name= and --os-version= has to be appear both or none")

    for i in account_info:
        if i is None or i == "":
            usage("Missing required parameter")

    return account_info


# When user specify a number for nodes, make sure it is valid
def validate_node_num(param, user_input):
    if param == user_input:
        usage("Parameter {} needs to come with a number".format(param))
    num_str = user_input[(user_input.index("=") + 1):]
    try:
        my_num = int(num_str)
        if (my_num < 3):
            usage("Parameter {} must have a value greather than or equal to 3".format(param))
        return my_num
    except ValueError:
        usage("Parameter {} has the non-interger value".format(param))


# Generate a json
def get_create_json(account_info):
    f = open(SSH_KEY_FILE, 'r')
    key = f.readline()
    key = key.rstrip('\n')
    f.close()

    deploy_os = "{} {}".format(deploy_os_name, deploy_os_ver)
    data = {
        "fyre": {
            "creds": {
                "username": account_info[0],
                "api_key": account_info[1],
                "public_key": key
            }
        },
        "clusterconfig": {
            "instance_type": "virtual_server",
            "platform": platform
        },
        "cluster_prefix": account_info[2],
        account_info[2]: []
    }
    nodes = []

    proxy_node = FyreNodeJson(name="Proxy", count=1, cpu=1, memory=1, os=deploy_os, publicvlan="n", privatevlan="y",additional_disks=[])
    proxy_ip_temp = get_proxy_ip(PROXY_REQUEST_URL, account_info)
    if not proxy_ip_temp is None:
        global proxy_ip_from_database,proxy_ip
        proxy_ip_from_database = True
        proxy_ip = proxy_ip_temp
        proxy_node = None

    if not proxy_node is None:
        nodes.append(proxy_node)

    if three_node:
        disks = [{"size": 500}, {"size": 400}]
        if docker_partition:
            disks.append({"size": docker_partition_size})
        nodes.append(FyreNodeJson(name="Master-1", count=1, cpu=8, memory=24, os=deploy_os, publicvlan="y", privatevlan="y", additional_disks=disks))
        nodes.append(FyreNodeJson(name="Master-2", count=1, cpu=8, memory=24, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks))
        nodes.append(FyreNodeJson(name="Master-3", count=1, cpu=8, memory=24, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks))
    else:
        disks = {
            "master": [{ "size": 250}],
            "storage": [{"size": 400}, {"size": 400}],
            "compute": [{ "size": 250}]
        }
        if docker_partition:
            disks["master"].append({"size": docker_partition_size})
            disks["storage"].append({"size": docker_partition_size})
            disks["compute"].append({"size": docker_partition_size})

        nodes.append(FyreNodeJson(name="Master-1", count=1, cpu=4, memory=24, os=deploy_os, publicvlan="y", privatevlan="y", additional_disks=disks["master"]))
        for x in range(2, num_master + 1):
            nodes.append(FyreNodeJson(name="Master-{}".format(x), count=1, cpu=4, memory=24, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["master"]))
        nodes.append(FyreNodeJson(name="Storage", count=num_storage, cpu=8, memory=32, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["storage"]))
        nodes.append(FyreNodeJson(name="Compute", count=num_compute, cpu=8, memory=32, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["compute"]))
    global load_balance
    if load_balance:
        nodes.append(FyreNodeJson(name="balancer", count=1, cpu=2, memory=4, os=deploy_os, publicvlan="y", privatevlan="y"))
    data[account_info[2]] = nodes
    string = json.dumps(data, indent=4, separators=(',', ': '))
    log("============= Create request ==================")
    log(string)
    log("===============================================")
    return string

def FyreNodeJson(name, count, cpu, memory, os, publicvlan, privatevlan, additional_disks=[]):
    m = {
        "name": name,
        "count": count,
        "cpu": cpu,
        "memory": memory,
        "os": os,
        "publicvlan": publicvlan,
        "privatevlan": privatevlan,
        "additional_disks": additional_disks
    }
    return m


# Create the cluster
def create_cluster(account_info):
    # Check if the cluster name is exist already
    res = sendRequest("?operation=query&request=showclusters", account_info)
    cluster_list = res.get("clusters")
    if res.has_key("status"):
        print("Unexpected result for request showclusters")
        print("=====================================================")
        print("{}: {}".format(res.get("status"), res.get("details")))
        print("=====================================================")
        sys.exit(1)
    for c_info in cluster_list:
        if (c_info.get("name") == account_info[2]):
            print("The cluster name is already exist in your account")
            sys.exit(1)
    log("The cluster name {} is valid for create".format(account_info[2]))

    # Create now
    print("Submit create VM request to fyre and wait for completion")
    res = sendRequest("?operation=build", account_info, data=get_create_json(account_info))
    req_id = res.get("request_id")
    print("Create request id is {}".format(req_id))

    # Loop to check the building is done
    while True:
        res = sendRequest("?operation=query&request=showrequests&request_id=" + req_id, account_info)
        req_list = res.get("request")
        req_info = req_list[0]
        req_status = req_info.get("status")
        if req_status == "error":
            print("Failed to create cluster due to: {}".format(req_info.get("error_details")))
            sys.exit(1)
        elif req_status == "building":
            log("Still in building state")
        elif req_status == "completed":
            log("Completed state right now!")
            if req_info.get("error_details") != "0":
                print("Create completed with error: {}".format(req_info.get("error_details")))
                sys.exit(1)
            break
        else:
            print("Unrecognized create status: {}".format(req_status))
            sys.exit(1)

        time.sleep(5)

    # Return the cluster info
    res = sendRequest("?operation=query&request=showclusterdetails&cluster_name=" + account_info[2], account_info)
    if not res.has_key(account_info[2]):
        print("Invalid response when getting information for cluster {}".format(account_info[2]))
        print("=====================================================")
        print(str(res))
        print("=====================================================")
        sys.exit(1)
    return res


# Creating the configuration file according to the fyre api response
def create_file(cluster_info):
    global cluster_information_ip_pass, parted_ip_list, deploy_data, proxy_ip, node_hostName
    field, clus_info = cluster_info.items()[0]
    node_hostName = []
    for l in clus_info:
        node_hostName.append(l["node"])

    global conf_file
    conf_file = "wdp." + field + ".conf"
    if os.path.exists(os.getcwd() + "/" + conf_file):
        os.remove(os.getcwd() + "/" + conf_file)
    f = open(os.getcwd() + "/" + conf_file, 'w')
    f.write("# Warning: This file generated by a script, do NOT share\n")
    f.write("user=root\n")
    proxy_ip = get_proxy_ip(PROXY_GET_IP_URL, ["", "", field])
    if not proxy_ip is None:
        f.write("virtual_ip_address={}\n".format(proxy_ip))
    for line in clus_info:
        node_info = line.get("node").split("-")
        if node_info[-1] == "proxy":
            proxy_ip = line.get("privateip")
            f.write("virtual_ip_address=%s\n" % (line.get("privateip")))
        elif node_info[-2] == "master":
            if three_node:
                f.write("node_%s=%s\n" % (node_info[-1], line.get("privateip")))
                if one_partition:
                    f.write("node_data_%s=/ibm\n" % (node_info[-1]))
                else:
                    f.write("node_data_%s=/data\n" % (node_info[-1]))
                f.write("node_path_%s=/ibm\n" % (node_info[-1]))
                parted_ip_list.append(line.get("privateip"))
            else:
                f.write("master_node_%s=%s\n" % (node_info[-1], line.get("privateip")))
                f.write("master_node_path_%s=/ibm\n" % (node_info[-1]))

            if node_info[-1] == "1":
                deploy_data = {"ip": line.get("publicip"), "password": line.get("root_password")}
                if external_access:
                    f_dev = open(os.getcwd() + "/" + DEV_CONF_FILE, 'w')
                    f_dev.write("EXTERNAL_IP=%s\n" % (deploy_data["ip"]))
                    f_dev.close()
            cluster_information_ip_pass.append({"ip": line.get("privateip"), "password": line.get("root_password")})
        elif node_info[-2] == "storage":
            f.write("storage_node_%s=%s\n" % (node_info[-1], line.get("privateip")))
            if one_partition:
                f.write("storage_node_data_%s=/ibm\n" % (node_info[-1]))
            else:
                f.write("storage_node_data_%s=/data\n" % (node_info[-1]))
            f.write("storage_node_path_%s=/ibm\n" % (node_info[-1]))
            parted_ip_list.append(line.get("privateip"))
            cluster_information_ip_pass.append({"ip": line.get("privateip"), "password": line.get("root_password")})
        elif node_info[-2] == "compute":
            f.write("compute_node_%s=%s\n" % (node_info[-1], line.get("privateip")))
            f.write("compute_node_path_%s=/ibm\n" % (node_info[-1]))
            cluster_information_ip_pass.append({"ip": line.get("privateip"), "password": line.get("root_password")})
        elif node_info[-1] == "balancer":
            f.write("load_balancer_ip_address=%s\n" % (line.get("privateip")))
            global balancer_ip
            balancer_ip = {"ip": line.get("privateip"), "password": line.get("root_password")}
    f.write("ssh_port=22\n")
    f.write("overlay_network=9.242.0.0/16\n")
    f.write("suppress_warning=true\n")
    f.close()


# Wait for all nodes are running
def wait_all_running(account_info):
    for x in range(60):
        res = sendRequest("?operation=query&request=showclusterdetails&cluster_name=" + account_info[2], account_info)
        if not res.has_key(account_info[2]):
            print("Invalid response when getting information for cluster {}".format(account_info[2]))
            print("=====================================================")
            print(str(res))
            print("=====================================================")
            sys.exit(1)
        cluster_info = res.get(account_info[2])

        is_all_running = True
        for line in cluster_info:
            if line.get("state") != "running":
                is_all_running = False
                break
        if is_all_running:
            print("All nodes are on running state")
            return
        time.sleep(5)
    print("Timeout to wait for all nodes to become running state")


# Set selinux, mount directory etc
def configure_nodes(account_info):
    write_part_script(account_info[2])
    fnull = open(os.devnull, 'w')
    if debug_mode:
        out_target = None
    else:
        out_target = fnull

    # Copy the partition scripts to all nodes
    print("Updating each node")
    for node_info in cluster_information_ip_pass:
        cur_ip = node_info['ip']
        client = None
        client, jhost = nested_ssh(deploy_data['ip'], cur_ip, deploy_data['password'], node_info['password'])

        log("Making SELinux to permissive on " + cur_ip)
        stdin, stdout, stderr = jhost.exec_command("sed -i 's/^SELINUX=.*$/SELINUX=permissive/g' /etc/selinux/config >& /dev/null")
        log("Exit status:" + str(stdout.channel.recv_exit_status()))
        log("Command output: " + str(stdout.readlines()))
        if stdout.channel.recv_exit_status() != 0:
            log("Unable to set config selinux")
            exit(1)
  
        log("Copying partition script to " + cur_ip)
        ftp = jhost.open_sftp()
        f = ftp.put(part_disk_script_name, "part_disk.sh")
        if f is None:
            log("Unable to copy partition script  ")
            exit (1)
        log("Executing partition script on {} for /ibm".format(cur_ip))
        stdin, stdout, stderr = jhost.exec_command("chmod +x ~/part_disk.sh; ~/part_disk.sh " + IBM_DISK[platform] + " /ibm >& /dev/null")
        log("Exit status:" + str(stdout.channel.recv_exit_status()))
        log("Command output: " + str(stdout.readlines()))
        if stdout.channel.recv_exit_status() != 0:
            log("Unable to execute partition script on {}".format(cur_ip))
            exit(1)
        if cur_ip in parted_ip_list:
            log("Executing partition script on {} for /data".format(cur_ip))
            stdin, stdout, stderr = jhost.exec_command("chmod +x ~/part_disk.sh; ~/part_disk.sh " + DATA_DISK[platform] + " /data >& /dev/null")
            log("Exit status:" + str(stdout.channel.recv_exit_status()))
            log("Command output: " + str(stdout.readlines()))
            if stdout.channel.recv_exit_status() != 0:
                log("Unable to execute partition script on {}".format(cur_ip))
                exit(1)

        if cur_ip == cluster_information_ip_pass[0]['ip']:
            log("Scp the wdp.conf file")
            f = ftp.put(conf_file, "/ibm/wdp.conf")
            if f is None:
                print("Failed to scp the conf file, please try again by yourself")
                sys.exit(1)
            if external_access:
                f = ftp.put(DEV_CONF_FILE, "/ibm/wdp_dev.conf")
                if f is None:
                    print("Failed to scp the external access conf file, please try again by yourself")
                    sys.exit(1)
        ftp.close()
        client.close()
        jhost.close()
        global load_balance 
        if load_balance:
            load_balancer(deploy_data, balancer_ip, cluster_information_ip_pass) 
 
    if os.path.exists(os.getcwd() + "/part_disk.sh"):
        os.remove(os.getcwd() + "/part_disk.sh")

    log("rebooting all nodes")
    for hostname in node_hostName:
        if not hostname.endswith("-proxy"):
            sendRequest("?operation=reboot&node_name={}".format(hostname), account_info)
    # Reboot all the nodes
    print("Intended sleep 60 seconds")
    time.sleep(60)
    wait_all_running(account_info)
    os.remove(part_disk_script_name)
    for hostname in node_hostName:
        if hostname.endswith("-proxy"):
            sendRequest("?operation=shutdown&node_name={}".format(hostname), account_info)
    time.sleep(1)
    fnull.close()

def load_balancer(deploy_data, balancer_ip, cluster_information_ip_pass):
    client, jhost = nested_ssh(deploy_data['ip'], balancer_ip['ip'], deploy_data['password'], balancer_ip['password'])
    log("Creating load balancer " + balancer_ip['ip'])
    wget_cmd = "wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm; yum install -y epel-release-latest-7.noarch.rpm; yum install -y nginx;"
    stdin, stdout, stderr = jhost.exec_command(wget_cmd)
    log("Exit status:" + str(stdout.channel.recv_exit_status()))
    if stdout.channel.recv_exit_status() != 0:
        log("Error in getting epel-release and installing nginx")
        log("Command output: " + str(stdout.readlines()))
        exit(1)
    setup_conf_cmd = """mkdir -p /etc/nginx/tcpconf.d; 
                       echo \"stream { 
                                  upstream kubeapi { 
                                      server %s:6443; 
                                      server %s:6443; 
                                      server %s:6443;
                                  } 
                                  upstream dsxportal { 
                                      server %s:443; 
                                      server %s:443; 
                                      server %s:443;
                                  } 
                                  server { 
                                      listen     6443; 
                                      proxy_pass kubeapi;
                                  } 
                                  server {  
                                      listen     443; 
                                      proxy_pass dsxportal;
                                  }
                              }\" > /etc/nginx/tcpconf.d/load-balancer.conf;""" % (cluster_information_ip_pass[0]['ip'], cluster_information_ip_pass[1]['ip'], cluster_information_ip_pass[2]['ip'], cluster_information_ip_pass[0]['ip'], cluster_information_ip_pass[1]['ip'],cluster_information_ip_pass[2]['ip'])
    stdin, stdout, stderr = jhost.exec_command(setup_conf_cmd)
    log("Exit status:" + str(stdout.channel.recv_exit_status()))
    if stdout.channel.recv_exit_status() != 0:
        log("Error in setup of load-balancer.conf")
        log("Command output: " + str(stdout.readlines()))
        exit(1)
    include_conf_cmd = "sed -i '/include\ \/usr\/share\/nginx\/modules\/\*.conf/a include\ \/etc\/nginx\/tcpconf.d\/\*;' /etc/nginx/nginx.conf;" 
    stdin, stdout, stderr = jhost.exec_command(include_conf_cmd)
    log("Exit status:" + str(stdout.channel.recv_exit_status()))
    if stdout.channel.recv_exit_status() != 0:
        log("Unable to copy the include command into nginx conf")
        log("Command output: " + str(stdout.readlines()))
        exit(1)
    start_nginx_cmd = "systemctl enable nginx; systemctl start nginx"
    stdin, stdout, stderr = jhost.exec_command(start_nginx_cmd)
    log("Exit status:" + str(stdout.channel.recv_exit_status()))
    if stdout.channel.recv_exit_status() != 0:
        log("Error cannot enable or start nginx")
        log("Command output: " + str(stdout.readlines()))
        exit(1)
    jhost.close()
    client.close()       

def nested_ssh(levelOneIP, levelTwoIP, passwordIP1, passwordIP2):
     count = 0
     while count < 10:
         log('trying to make ssh tunnel on {} number of try {}'.format(levelTwoIP, count))
         client = paramiko.client.SSHClient()
         client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
         client.connect(levelOneIP, username='root', password=passwordIP1)
         vmtransport = client.get_transport()
         count += 1
         if vmtransport.is_active():
             dest_addr = (levelTwoIP, 22)  # edited#
             local_addr = (levelOneIP, 22)  # edited#
             vmchannel = vmtransport.open_channel("direct-tcpip", dest_addr, local_addr)
             jhost = paramiko.SSHClient()
             jhost.load_system_host_keys()
             jhost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
             jhost.connect(levelTwoIP, username='root',password=passwordIP2, sock=vmchannel)
             if jhost.get_transport().is_active():
                 count = 1
                 break
             else:
                 log('Unable to connect to ' + levelTwoIP + ' through ' + levelOneIp + ' trying again')
                 time.sleep(10)
                 if count == 10:
                     exit(1)
         elif count == 10:
             log('Unable to connect to ' + levelOneIP + ' through ssh with paramiko')
             exit(1)
     return client, jhost

# The script starts here
def run():
    print("Validating the the arguments")
    account_info = validate_args()

    if external_access:
        if os.path.isfile(os.getcwd() + "/" + DEV_CONF_FILE):
            print(
                "There is an external access configuration file with the same name {} in the directory already, please move them away and try again...".format(DEV_CONF_FILE))
            sys.exit(1)

    # Suppress warning message when sending insecure request
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    cluster_info = create_cluster(account_info)
    print("Request completed and generating the conf file")
    time.sleep(2)
    create_file(cluster_info)
    print("File generated")
    configure_nodes(account_info)
    print("Script finished successfully")

    sys.exit(0)


if __name__ == '__main__':
  run()
