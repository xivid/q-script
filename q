#!/usr/bin/env python3
"""
Copyright 2012-2021 Fam Zheng <fam@euphon.net>
Copyright 2021-2022 Bytedance Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""
import logging
import os
import sys
import argparse
import shutil
import tempfile
import json
import multiprocessing
import subprocess
import random
import time
import datetime
import hashlib
import re
import atexit
import signal

####### QMP module #######
import errno
import socket

class QMPError(Exception):
    pass

class QMPConnectError(QMPError):
    pass

class QMPCapabilitiesError(QMPError):
    pass

class QEMUMonitorProtocol:
    def __init__(self, address, server=False):
        """
        Create a QEMUMonitorProtocol class.

        @param address: QEMU address, can be either a unix socket path (string)
                        or a tuple in the form ( address, port ) for a TCP
                        connection
        @param server: server mode listens on the socket (bool)
        @raise socket.error on socket connection errors
        @note No connection is established, this is done by the connect() or
              accept() methods
        """
        self.__events = []
        self.__address = address
        self.__sock = self.__get_sock()
        if server:
            self.__sock.bind(self.__address)
            self.__sock.listen(1)

    def __get_sock(self):
        if isinstance(self.__address, tuple):
            family = socket.AF_INET
        else:
            family = socket.AF_UNIX
        return socket.socket(family, socket.SOCK_STREAM)

    def __negotiate_capabilities(self):
        greeting = self.__json_read()
        if greeting is None or 'QMP' not in greeting:
            raise QMPConnectError
        # Greeting seems ok, negotiate capabilities
        resp = self.cmd('qmp_capabilities')
        if "return" in resp:
            return greeting
        raise QMPCapabilitiesError

    def __json_read(self, only_event=False):
        while True:
            data = self.__sockfile.readline()
            if not data:
                return
            resp = json.loads(data)
            if 'event' in resp:
                self.__events.append(resp)
                if not only_event:
                    continue
            return resp

    error = socket.error

    def connect(self, negotiate=True):
        """
        Connect to the QMP Monitor and perform capabilities negotiation.

        @return QMP greeting dict
        @raise socket.error on socket connection errors
        @raise QMPConnectError if the greeting is not received
        @raise QMPCapabilitiesError if fails to negotiate capabilities
        """
        self.__sock.connect(self.__address)
        self.__sockfile = self.__sock.makefile()
        if negotiate:
            return self.__negotiate_capabilities()

    def accept(self):
        """
        Await connection from QMP Monitor and perform capabilities negotiation.

        @return QMP greeting dict
        @raise socket.error on socket connection errors
        @raise QMPConnectError if the greeting is not received
        @raise QMPCapabilitiesError if fails to negotiate capabilities
        """
        self.__sock, _ = self.__sock.accept()
        self.__sockfile = self.__sock.makefile()
        return self.__negotiate_capabilities()

    def cmd_obj(self, qmp_cmd):
        """
        Send a QMP command to the QMP Monitor.

        @param qmp_cmd: QMP command to be sent as a Python dict
        @return QMP response as a Python dict or None if the connection has
                been closed
        """
        try:
            self.__sock.sendall(json.dumps(qmp_cmd).encode("utf-8"))
        except socket.error as err:
            if err[0] == errno.EPIPE:
                return
            raise socket.error(err)
        return self.__json_read()

    def cmd(self, name, args=None, id=None):
        """
        Build a QMP command and send it to the QMP Monitor.

        @param name: command name (string)
        @param args: command arguments (dict)
        @param id: command id (dict, list, string or int)
        """
        qmp_cmd = { 'execute': name }
        if args:
            qmp_cmd['arguments'] = args
        if id:
            qmp_cmd['id'] = id
        return self.cmd_obj(qmp_cmd)

    def command(self, cmd, **kwds):
        ret = self.cmd(cmd, kwds)
        if 'error' in ret:
            raise Exception(ret['error']['desc'])
        return ret['return']

    def pull_event(self, wait=False):
        """
        Get and delete the first available QMP event.

        @param wait: block until an event is available (bool)
        """
        self.__sock.setblocking(0)
        try:
            self.__json_read()
        except socket.error as err:
            if err[0] == errno.EAGAIN:
                # No data available
                pass
        self.__sock.setblocking(1)
        if not self.__events and wait:
            self.__json_read(only_event=True)
        event = self.__events[0]
        del self.__events[0]
        return event

    def get_events(self, wait=False):
        """
        Get a list of available QMP events.

        @param wait: block until an event is available (bool)
        """
        self.__sock.setblocking(0)
        try:
            self.__json_read()
        except socket.error as err:
            if err[0] == errno.EAGAIN:
                # No data available
                pass
        self.__sock.setblocking(1)
        if not self.__events and wait:
            self.__json_read(only_event=True)
        return self.__events

    def clear_events(self):
        """
        Clear current list of pending events.
        """
        self.__events = []

    def close(self):
        self.__sock.close()
        self.__sockfile.close()

    timeout = socket.timeout

    def settimeout(self, timeout):
        self.__sock.settimeout(timeout)

####### End of QMP module ########

devnull = open("/dev/null")

def get_nr_cores():
    return multiprocessing.cpu_count()

Q_RUNDIR = os.path.expanduser("~/.cache/q-script")

def check_output(cmd, *args, **kwargs):
    kwargs["shell"] = not isinstance(cmd, list)
    return subprocess.check_output(cmd, *args, **kwargs).decode("utf-8")

def check_call(cmd, *args, **kwargs):
    kwargs["shell"] = not isinstance(cmd, list)
    return subprocess.check_call(cmd, *args, **kwargs)

def print_cmd(cmd):
    def escape(x):
        quote = False
        if '"' in x:
            x = x.replace('"', '\\"')
            quote = True
        if " " in x:
            quote = True
        if quote:
            x = '"' + x + '"'
        return x
    print(" ".join([escape(x) for x in cmd]))


def git_clone_maybe(repo, target):
    if not os.path.exists(target):
        check_call(["mkdir", "-p", os.path.dirname(target)])
        check_output(['git', 'clone', '--depth=1', repo,
                      target])

class SubCommand(object):
    """ Base class of subcommand"""
    help = ""
    aliases = []
    want_argv = False # Whether the command accepts extra arguments

    def setup_args(self, parser):
        pass

    def do(self, args, argv):
        """Do command"""
        print("Not implemented")

    def minio_upload(self, host, s3_key, s3_secret, bucket, folder, fname, secure=False):
        import minio
        client = minio.Minio(host, access_key=s3_key, secret_key=s3_secret, secure=secure)

        basename = os.path.basename(fname)
        u = f"{folder}/{basename}"
        print(f"uploading {fname} to {u}")
        client.fput_object(bucket, u, fname)
        return bucket + "/" + u

    def mkdtemp(self, autoremove=True):
        tmpd = tempfile.mkdtemp(dir="/var/tmp", prefix="q-%s-" % self.name)
        if autoremove:
            atexit.register(lambda: shutil.rmtree(tmpd))
        return tmpd


def get_total_cpus():
    return multiprocessing.cpu_count()

def get_numa_cpus(node):
    ret = []
    for x in os.listdir("/sys/devices/system/node/node%d/" % node):
        if not x.startswith("cpu"):
            continue
        try:
            ret.append(int(x[3:]))
        except:
            pass
    return sorted(ret)

def gen_name():
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d.%s-") + os.uname()[1]

class DockerContainer(object):
    def __init__(self, image, env={}, volumes=[], cpus=0, args=[]):
        self.image = image
        self.name = 'q-' + gen_name()
        self.env = env
        self.volumes = volumes
        self.cpus = cpus
        self.args = args
        self.start()

    def env_args(self):
        ret = []
        for x in self.volumes:
            ret += ['-v', "%s:%s" % (x[0], x[1])]
        return ret

    def volume_args(self):
        ret = []
        for k, v in self.env.items():
            ret += ['-e', "%s=%s" % (k, v)]
        return ret

    def cpuset_args(self):
        node = 0
        cpus = ','.join([str(x) for x in get_numa_cpus(node)])
        mems = str(node)
        return [
            '--cpuset-cpus', cpus,
            '--cpuset-mems', mems]

    def cpus_args(self):
        cpus = min(get_total_cpus(), self.cpus)
        return ['--cpus=%f' % cpus]

    def start(self):
        cmd = ['docker', 'run', '--rm', '-d',
               '--network=host', '--name', self.name]
        cmd += self.env_args()
        cmd += self.volume_args()
        cmd += self.cpuset_args()
        cmd += self.cpus_args()
        cmd.append(self.image)
        cmd += self.args
        subprocess.check_output(cmd)
        atexit.register(self.stop)
        for _ in range(10000):
            cmd = ['docker', 'ps']
            try:
                if self.name in subprocess.check_output(cmd).decode():
                    break
            except:
                pass
            time.sleep(0.2)

    def stop(self):
        cmd = ['docker', 'kill', self.name]
        dn = subprocess.DEVNULL
        subprocess.Popen(cmd, stdout=dn, stderr=dn)

    def do_exec(self, cmd):
        cmd = ['docker', 'exec', self.name, '/bin/sh', '-c', cmd]
        return subprocess.check_output(cmd).decode()

class QEMUInstance(object):
    def __init__(self, rundir):
        self._rundir = rundir
        self.name = rundir[rundir.rfind("/qemu-") + len("/qemu-"):]
        self.qmp_path = os.path.join(rundir, "qmp")
        sshportpath = os.path.join(rundir, "sshport")
        if os.path.exists(sshportpath):
            self.sshport = int(open(sshportpath, "r").read().strip())
        else:
            self.sshport = None
        pidpath = os.path.join(rundir, "pid")
        if os.path.exists(pidpath):
            self.pid = int(open(pidpath, "r").read().strip())
        else:
            self.pid = None
        self.do_qmp("query-block")

    def do_qmp(self, cmd, **args):
        qmp = QEMUMonitorProtocol(self.qmp_path)
        qmp.connect()
        try:
            logging.info(cmd, args)
            return qmp.command(cmd, **args)
        finally:
            qmp.close()

class InstanceLookupError(Exception):
    pass

def get_all_qemu_instances():
    ret = []
    a = [x for x in os.listdir(Q_RUNDIR) if x.startswith("qemu-")]
    for x in a:
        try:
            i = QEMUInstance(os.path.join(Q_RUNDIR, x))
            ret.append(i)
        except:
            pass
    return ret

def get_qemu_instance(name=None):
    """ Find and initialize QEMU instance by name. Or return the instance if
    there is only one.
    Otherwise, raise exception"""
    a = get_all_qemu_instances()
    if not a:
        raise InstanceLookupError("No instance is running")
    if name == None:
        if len(a) == 1:
            return a[0]
        else:
            raise InstanceLookupError("Multiple instances running")
    for x in a:
        if x.name == name:
            return x
    raise InstanceLookupError("Instance not found")

class UnknownTemplateName(Exception):
    pass

def find_port(start):
    ret = start
    while subprocess.call("ss -lt | grep -q ':%d'" % ret, shell=True) == 0:
        ret += 1
    return ret

ssh_opts = [
    "-o", "ConnectTimeout=1",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "StrictHostKeyChecking=no",
    ]
def ssh_call(port, user, *argv, **kwargs):
    return subprocess.call(["ssh"] + ssh_opts + [
                            "-q",
                            "-p", str(port),
                            "%s@127.0.0.1" % user] + list(argv),
                            **kwargs)

def scp_call(port, user, *argv, **kwargs):
    scp_args = []
    for a in argv:
        if a.startswith("vm:"):
            a = "%s@127.0.0.1" % user + a[2:]
        scp_args.append(a)

    cmd = ["scp"] + ssh_opts + [
            "-q", "-P", str(port)] + scp_args
    return subprocess.call(cmd, **kwargs)

def get_default_mem():
    try:
        avail = subprocess.check_output("free -m", shell=True, encoding='utf-8').splitlines()[1].split()[6]
        avail = int(avail) / 1000
        if avail > 16:
            return '10G'
        if avail > 10:
            return '8G'
        if avail > 6:
            return '4G'
        if avail > 3:
            return '2G'
        else:
            return '1G'
    except:
        return '1G'

def get_default_qemu():
    return "qemu-system-" + os.uname().machine

class QemuCommand(SubCommand):
    name = "qemu"
    aliases = ["q"]
    want_argv = True
    help = "Start QEMU"
    def __init__(self):
        self._ids = {}
        self.serial = None

    def setup_args(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Only print the command line")
        parser.add_argument("--memory", type=str, default=get_default_mem(),
                            help="memory size")
        parser.add_argument("--name", type=str,
                            help="name of the QEMU instance")
        parser.add_argument("-f", "--foreground", action="store_true",
                            help="Don't detach after QEMU started")
        parser.add_argument("-p", "--program", default=get_default_qemu(),
                            help="Which qemu executable to use")
        parser.add_argument("--no-net", action="store_true",
                            help="Don't add network")
        parser.add_argument("--nic", default="virtio-net-pci",
                            help="NIC type")
        parser.add_argument("--wait-ssh", "-w", action="store_true",
                            help="Wait for guest SSH service to start")
        parser.add_argument("--run-cmd", "-c",
                            help="Run command in guest and exit")
        parser.add_argument("--net", default="10.0.2.0/24",
                            help="CIDR for the user net")
        parser.add_argument("--host", default="10.0.2.2",
                            help="host addr for the user net")

    def _rundir_filename(self, fn):
        return os.path.join(self._rundir, fn)

    def get_machine_type(self):
        m = os.uname()[4]
        if m == 'aarch64':
            return 'virt'
        return 'q35'

    def _def_args(self, args, argv):
        self._sshport = find_port(10022)
        self._rdpport = find_port(13389)
        ret = ["-enable-kvm"]
        if '+sev' not in argv:
            ret += ['-cpu', 'max', '-machine', self.get_machine_type()]
        if '-m' not in argv:
            ret += ["-m", args.memory]
        if '-smp' not in argv:
            ret += ["-smp", "cores=4"]
        ret += ["-qmp", "unix:%s,server,nowait" % self._rundir_filename("qmp")]
        ret += ["-name", self.name]
        if not os.environ.get("DISPLAY"):
            ret += ["-display", "none", "-vnc", ":0,to=100"]
        # TODO: fix 10022 to a dynamic port
        if not args.no_net:
            ret += ["-netdev", "user,id=vnet,net=%s,host=%s,hostfwd=:0.0.0.0:%d-:22,hostfwd=:0.0.0.0:%d-:3389" % (args.net, args.host, self._sshport, self._rdpport),
                    "-device", args.nic + ",netdev=vnet,mac=00:8c:fa:e4:a3:53"]

        return ret;

    def _gen_id(self, prefix=""):
        r = self._ids[prefix] = self._ids.get(prefix, 0) + 1
        return prefix + str(r)

    def _gen_drive(self, s):
        drive = self._gen_id("drive-")
        optstr = "file=%s,if=none,id=%s" % (s, drive)
        if ".raw" in s:
            optstr += ",format=raw"
        if "cache=" not in optstr:
            try:
                fpath = os.path.realpath(s)
                if not fpath.startswith("/tmp"):
                    optstr += ",cache=none,aio=native"
            except Exception as e:
                logging.warning(str(e))
        return drive, ["-drive", optstr]

    def _devtmpl_ide(self, s):
        drive, r = self._gen_drive(s)
        return r + ["-device", "ide-hd,drive=%s" % drive]

    def _devtmpl_sev(self, s):
        return [
                "-cpu", "EPYC-v4",
                "-machine", "pc-q35-7.1",
                "-no-reboot",
                "-drive", "if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on",
                "-drive", "if=pflash,format=raw,unit=1,file=OVMF_VARS.fd",
                "-machine", "memory-encryption=sev0,vmport=off",
                "-object", "sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1",
        ]

    def _devtmpl_vblk(self, s):
        drive, r = self._gen_drive(s)
        return r + ["-device", "virtio-blk-pci,drive=%s" % drive]

    def _devtmpl_vblk_dp(self, s):
        opts = []
        if not hasattr(self, "_has_iothread"):
            opts += ["-object", "iothread,id=iot0"]
            self._has_iothread = True
        drive, r = self._gen_drive(s)
        opts += r
        return opts + ["-device", "virtio-blk-pci,iothread=iot0,drive=%s" % drive]

    def _devtmpl_scsi_block(self, s):
        opts = []
        if not hasattr(self, "_has_scsi_bus"):
            opts += ["-device", "virtio-scsi-pci,id=scsi0"]
            self._has_scsi_bus = True
        drive, r = self._gen_drive(s)
        return opts + r + ["-device", "scsi-block,bus=scsi0.0,drive=%s" % drive]

    def _devtmpl_sd_boot(self, s):
        opts = []
        if not hasattr(self, "_has_scsi_bus"):
            opts += ["-device", "virtio-scsi-pci,id=scsi0"]
            self._has_scsi_bus = True
        drive, r = self._gen_drive(s)
        return opts + r + ["-device", "scsi-hd,bus=scsi0.0,drive=%s,bootindex=1" % drive]

    def _devtmpl_sd(self, s):
        opts = []
        if not hasattr(self, "_has_scsi_bus"):
            opts += ["-device", "virtio-scsi-pci,id=scsi0"]
            self._has_scsi_bus = True
        drive, r = self._gen_drive(s)
        return opts + r + ["-device", "scsi-hd,bus=scsi0.0,id={drive},serial=drive_{drive},drive={drive}".format(drive=drive)]

    def _devtmpl_sg(self, s):
        opts = []
        if not hasattr(self, "_has_scsi_bus"):
            opts += ["-device", "virtio-scsi-pci,id=scsi0"]
            self._has_scsi_bus = True
        drive, r = self._gen_drive(s)
        return opts + r + ["-device", "scsi-generic,bus=scsi0.0,drive=%s" % drive]

    def _devtmpl_sb(self, s):
        opts = []
        if not hasattr(self, "_has_scsi_bus"):
            opts += ["-device", "virtio-scsi-pci,id=scsi0"]
            self._has_scsi_bus = True
        drive, r = self._gen_drive(s)
        return opts + r + ["-device", "scsi-block,bus=scsi0.0,drive=%s" % drive]

    def _devtmpl_sd_dp(self, s):
        opts = []
        if not hasattr(self, "_has_scsi_dataplane_bus"):
            if not hasattr(self, "_has_iothread"):
                opts += ["-object", "iothread,id=iot0"]
                self._has_iothread = True
            opts += ["-device", "virtio-scsi-pci,iothread=iot0,id=scsi-dp0"]
            self._has_scsi_dataplane_bus = True
        drive, r = self._gen_drive(s)
        return opts + r + ["-device", "scsi-disk,bus=scsi-dp0.0,id=%s,drive=%s" % (drive + "-sd", drive)]

    def _devtmpl_scsi_cd_dataplane(self, s):
        opts = []
        if not hasattr(self, "_has_scsi_dataplane_bus"):
            if not hasattr(self, "_has_iothread"):
                opts += ["-object", "iothread,id=iot0"]
                self._has_iothread = True
            opts += ["-device", "virtio-scsi-pci,iothread=iot0,id=scsi-dp0"]
            self._has_scsi_dataplane_bus = True
        drive, r = self._gen_drive(s + ",media=cdrom")
        return opts + r + ["-device", "scsi-cd,bus=scsi-dp0.0,drive=%s" % drive]

    def _devtmpl_nvme(self, s):
        drive, r = self._gen_drive(s)
        return r + ["-device", "nvme,serial=nvmedisk%s,drive=%s" % (drive, drive)]

    def _devtmpl_seabios_debug(self, s):
        i = self._gen_id("c")
        return ["-chardev", "stdio,id=" + i,
                "-device", "isa-debugcon,iobase=0x402,chardev=" + i]

    def _parse_one(self, v):
        if v and v[0] not in "@+":
            return [v]
        if v.startswith("+"):
            prefix = "_devtmpl_"
        tn = v[1:]
        ts = ""
        if ":" in v:
            tn = v[1:v.find(":")]
            ts = v[v.find(":") + 1:]
        tn = tn.replace("-", "_")
        if not hasattr(self, prefix + tn):
            raise UnknownTemplateName(tn)
        return getattr(self, prefix + tn)(ts)

    def _parse_argv(self, argv):
        r = []
        for v in argv:
            r = r + self._parse_one(v)
        if '-serial' not in r:
            self.serial = "file:" + os.path.join(self._rundir, 'serial.out')
            r += ["-serial", self.serial]
        return r

    def _quote_cmd(self, cmd):
        r = ""
        for p in cmd:
            if " " in p:
                r += '"' + p + '"'
            else:
                r += p
            r += " "
        return r

    def do(self, args, argv):
        if "--" in argv:
            argv.remove("--")

        check_call(["mkdir", "-p", Q_RUNDIR])
        self.name = args.name or tempfile.mktemp(prefix="", dir="").upper()
        self._rundir = os.path.join(Q_RUNDIR, "qemu-" + self.name)
        check_call(["mkdir", "-p", self._rundir])

        cmd = args.program.split() + self._def_args(args, argv) + self._parse_argv(argv)
        cmd += ["-pidfile", os.path.join(self._rundir, "pid")]
        print_cmd(cmd)
        if args.dry_run:
            return 0
        assert self._rundir
        open(os.path.join(self._rundir, "sshport"), "w").write(str(self._sshport))
        qemup = subprocess.Popen("%s; rm %s/*; rm -fr %s" % \
                                 (self._quote_cmd(cmd), self._rundir, self._rundir),
                                 shell=True)
        if args.foreground:
            qemup.wait()
            return 0
        connected = False
        if args.wait_ssh or args.run_cmd:
            starttime = datetime.datetime.now()
            timeout = 60
            while (datetime.datetime.now() - starttime).total_seconds() < timeout:
                if qemup.poll() != None:
                    return 1
                if ssh_call(self._sshport, "root", "true",
                            stderr=subprocess.PIPE) == 0:
                    connected = True
                    break
                time.sleep(0.5)
            if not connected:
                if self.serial and self.serial.startswith(self._rundir):
                    subprocess.call(['cat', self.serial])
                logging.error("Timeout while waiting for SSH server")
                return 1
        else:
            # TODO: Wait for QMP or pidfile?
            time.sleep(0.5)
        if args.run_cmd:
            r = ssh_call(self._sshport, "root", args.run_cmd)
            ssh_call(self._sshport, "root", 'poweroff')
            qemup.wait()
            return r
        return 0

class QMPCommand(SubCommand):
    name = "qmp"
    want_argv = True
    help = "Execute QMP command"

    def setup_args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")
        parser.add_argument("--raw", action='store_true',
                            help="Argument is raw JSON")

    def do(self, args, argv):
        vm = get_qemu_instance(args.name)
        if len(argv) == 0:
            print("No command specified")
            return 1
        if args.raw:
            allargs = json.loads(argv[1])
        else:
            allargs = {}
            for i in argv[1:]:
                if "=" not in i:
                    raise Exception("Error while parsing argument (no '=') " + i)
                key, value = i[:i.find("=")], i[i.find("=") + 1:]
                optpath = key.split('.')
                parent = allargs
                curpath = []
                for p in optpath[:-1]:
                    curpath.append(p)
                    d = parent.get(p, {})
                    if type(d) is not dict:
                        raise Exception('Cannot use "%s" as both leaf and non-leaf key' % '.'.join(curpath))
                    parent[p] = d
                    parent = d
                if optpath[-1] in parent:
                    if type(parent[optpath[-1]]) is dict:
                        raise Exception('Cannot use "%s" as both leaf and non-leaf key' % '.'.join(curpath))
                    else:
                        raise Exception('Cannot set "%s" multiple times' % '.'.join(curpath))
                if value.lower() in ["true", "false"]:
                    value = value.lower() == "true"
                try:
                    if str(int(value)) == value:
                        value = int(value)
                except:
                    pass
                parent[optpath[-1]] = value
        r = vm.do_qmp(argv[0], **allargs)
        json.dump(r, sys.stdout, indent=2, separators=(",", ": "))

class SSHCommand(SubCommand):
    name = "ssh"
    want_argv = True
    help = "Execute SSH command"

    def setup_args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        return ssh_call(i.sshport, "root", *argv)

class SCPCommand(SubCommand):
    name = "scp"
    want_argv = True
    help = "Execute SSH command"

    def setup_args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        return scp_call(i.sshport, "root", *argv)

class ListCommand(SubCommand):
    name = "list"
    want_argv = True
    help = "List managed QEMU instances"

    def setup_args(self, parser):
        pass

    def do(self, args, argv):
        for i in get_all_qemu_instances():
            print(i.name)

class SSHCopyIdCommand(SubCommand):
    name = "ssh-copy-id"
    want_argv = False
    help = "Execute ssh-copy-id command"

    def setup_args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        return subprocess.call(["ssh-copy-id", "-p", str(i.sshport), "root@127.0.0.1"])

def do_hmp(name, argv):
    i = get_qemu_instance(name)
    print(argv)
    r = i.do_qmp('human-monitor-command',
                 **{'command-line': " ".join(argv)})
    print(r)

class HMPCommand(SubCommand):
    name = "hmp"
    want_argv = True

    def setup_args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        do_hmp(args.name, argv)
        return 0

class GDBCommand(SubCommand):
    name = "gdb"
    want_argv = True

    def setup_args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        return subprocess.call(["gdb", "-p", str(i.pid)])

class PidCommand(SubCommand):
    name = "pid"
    help = "Get PID of QEMU process"

    def setup_args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        print(i.pid)
        return 0

class MakeCommand(SubCommand):
    name = "make"
    aliases = ["m"]
    want_argv = True
    help = "Invoke make in QEMU build dir"

    def do(self, args, argv):
        build_dir = os.path.join(Q_RUNDIR, "build")
        nr_cores = get_nr_cores()
        check_call(["make", "-C", build_dir, "-j", str(nr_cores)] + argv)

class MinioUploadCommand(SubCommand):
    name = "minio-upload"
    help = "Upload file to a minio server"
    want_argv = True

    def setup_args(self, parser):
        parser.add_argument("--server", '-s', type=str, required=True, help="server")
        parser.add_argument("--user", '-u', type=str, required=True, help="username")
        parser.add_argument("--password", '-p', type=str, required=True, help="password")
        parser.add_argument("--bucket", '-b', type=str, required=True, help="bucket name")
        parser.add_argument("--folder", '-f', type=str, default='q-script', help="folder name")
        parser.add_argument("--insecure", action="store_true")

    def do(self, args, argv):
        for f in argv:
            self.minio_upload(args.server, args.user, args.password, args.bucket, args.folder, f, not args.insecure)

class PgbenchCommand(SubCommand):
    name = "pgbench"
    help = "Run pgbench"
    want_argv = True

    def setup_args(self, parser):
        parser.add_argument("--scale-factor", "-s", type=int, default=1,
                help="pgbench scale factor")
        parser.add_argument("--test-time", "-t", type=int, default=5,
                help="pgbench test time")
        parser.add_argument("--concurrency", "-c", type=int, default=32,
                help="pgbench test concurrency (both threads and clients)")
        parser.add_argument("--metrics", "-m", action="store_true",
                help="Collect telegraf metrics")

    def do(self, args, argv):
        env = {
            'POSTGRES_PASSWORD': 'benchpass',
            'POSTGRES_USER': 'bench',
            'PGHOST': 'localhost',
            'PGPORT': '5432',
            'PGUSER': 'bench',
            'PGDATABASE': 'bench',
            'PGPASSWORD': 'benchpass'
        }
        tmpd = self.mkdtemp(False)
        vols = [(tmpd, '/var/lib/postgresql/data')]
        d = DockerContainer('postgres:12.13', env=env, volumes=vols, cpus=args.concurrency)
        time.sleep(5)
        print("preparing data...")
        d.do_exec("pgbench -i -s %d" % args.scale_factor)
        print("benchmarking read only...")
        self.container = d
        if args.metrics:
            self.start_telegraf()
        ro = self.bench_ro()
        print("benchmarking read write...")
        rw = self.bench_rw()
        print("== Test completed ==")
        print()
        print("=== RO result ===")
        print(ro)
        print()
        print("=== RW result ===")
        print(rw)

    def bench_do(self, sql):
        cmd = """
        cat >bench.sql <<EOF
        """ + sql + """
EOF
        pgbench -M prepared -v -r -P 1 --progress-timestamp \
                -f ./bench.sql \
                -c {concurrency} -j {concurrency} -T {test_time} -D scale=10000 -D range=100000000
        """.format(
                test_time=self.args.test_time,
                concurrency=self.args.concurrency,
                )
        r = self.container.do_exec(cmd)
        ret = []
        for l in r.splitlines():
            if 'latency' in l or 'tps' in l:
                ret.append(l)
        return "\n".join(ret)

    def bench_ro(self):
        sql = """
\set aid random_gaussian(1, :range, 10.0)
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
"""
        return self.bench_do(sql)

    def bench_rw(self):
        sql = """
\set aid random_gaussian(1, :range, 10.0)
\set bid random(1, 1 * :scale)
\set tid random(1, 10 * :scale)
\set delta random(-5000, 5000)
BEGIN;
UPDATE pgbench_accounts SET abalance = abalance + :delta WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
UPDATE pgbench_tellers SET tbalance = tbalance + :delta WHERE tid = :tid;
UPDATE pgbench_branches SET bbalance = bbalance + :delta WHERE bid = :bid;
INSERT INTO pgbench_history (tid, bid, aid, delta, mtime) VALUES (:tid, :bid, :aid, :delta, CURRENT_TIMESTAMP);
END;
"""
        return self.bench_do(sql)

class IpcBenchCommand(SubCommand):
    name = "ipc-bench"
    want_argv = True
    help = "Run ipc-bench"

    def setup_args(self, parser):
        parser.add_argument("-t", "--test", default="domain")

    def do(self, args, argv):
        signal.signal(signal.SIGUSR2, lambda sig, stack: print("SIGUSR2 received"))
        repo = 'https://github.com/famz/ipc-bench'
        workdir = os.path.join(Q_RUNDIR, "ipc-bench")
        test_exe = os.path.join(workdir, f"./build/source/{args.test}/{args.test}")
        if not os.path.exists(test_exe):
            git_clone_maybe(repo, workdir)
            nr_cores = get_nr_cores()
            check_call(f"""
                set -e
                mkdir -p {workdir}/build
                cd "{workdir}/build"
                cmake ..
                make -j{nr_cores - 1}
                """
            )
        test_args = ""
        if args.test == "domain":
            test_args = " -c 2000000 -s 1024"
        cmd = test_exe + test_args
        subprocess.check_call(["bash", "-c", cmd], cwd=workdir)

class FioCommand(SubCommand):
    name = "fio"
    want_argv = True
    help = "Benchmark SSD/NVMe performance using fio"

    cfg_template = """
    [global]
    bs={bs}
    ioengine=libaio
    iodepth={iodepth}
    size={size}
    direct=1
    ramp_time=30
    runtime={runtime}
    filename={testfile}
    time_based=1

    [seq-write]
    rw=write
    stonewall

    [rand-write]
    rw=randwrite
    stonewall

    [rand-rw]
    rw=randrw
    stonewall

    [seq-read]
    rw=read
    stonewall

    [rand-read]
    rw=randread
    stonewall
    """

    def setup_args(self, parser):
        parser.add_argument("-t", "--runtime", type=int, default=30)
        parser.add_argument("-s", "--size", default='10g')
        parser.add_argument("-b", "--bs", default='4k')
        parser.add_argument("-q", "--iodepth", default='1')
        parser.add_argument("-f", "--testfile")

    def do(self, args, argv):
        configs = []
        for bs in args.bs.split(','):
            for iodepth in args.iodepth.split(','):
                configs.append(
                    {
                        'bs': bs,
                        'iodepth': int(iodepth),
                    }
                )
        tmpd = self.mkdtemp()
        # atexit.register(lambda: shutil.rmtree(tmpd))
        tf = args.testfile or os.path.join(tmpd, 'testfile')
        for c in configs:
            self.show_cfg(c)
            cfg = self.cfg_template.format(
                    size=args.size,
                    runtime=args.runtime,
                    testfile=tf,
                    **c)
            r = self.do_fio(cfg)
            self.show_result(r)

    def show_result(self, r):
        for job in r['jobs']:
            bw = job['read']['bw_bytes'] + job['write']['bw_bytes']
            iops = job['read']['iops'] + job['write']['iops']
            x = "{name: <18} {bw_mb: >10} MB/s, {iops: >10} iops, {rlat: >10}us r-lat, {wlat: >10}us w-lat".format(
                    name=job['jobname'] + ":",
                    bw_mb=bw >> 20,
                    rlat=int(job['read']['lat_ns']['mean'] / 1000),
                    wlat=int(job['write']['lat_ns']['mean'] / 1000),
                    iops=int(iops))
            print(x)

    def show_cfg(self, cfg):
        print("\n=== Testing bs={bs} iodepth={iodepth}===".format(
            bs=cfg['bs'],
            iodepth=cfg['iodepth']
            ))
    def do_fio(self, cfg):
        cf = tempfile.NamedTemporaryFile(prefix="q-fio-", suffix=".fio", mode="w", delete=False)
        cf.write(cfg)
        cf.flush()
        cmd = ['fio', '--output-format=json', cf.name]
        print(' '.join(cmd))
        r = subprocess.check_output(cmd, encoding='utf-8')
        return json.loads(r)

class BuildCommand(SubCommand):
    name = "build"
    aliases = ["b"]
    want_argv = True
    help = "Build QEMU"
    def setup_args(self, parser):
        parser.add_argument("-r", "--rebuild", action="store_true",
                            help="Force rebuild")
        parser.add_argument("-i", "--install", action="store_true",
                            help="Install after build")
        parser.add_argument("-t", "--target-list", default="x86_64-softmmu",
                            help="Target list")
        parser.add_argument("-D", "--no-debug", action="store_true",
                            help="Don't use --enable-debug")

    def do(self, args, argv):
        build_dir = os.path.join(Q_RUNDIR, "build")
        cwd = os.path.realpath(os.getcwd())
        if not os.path.isfile("vl.c"):
            raise Exception("Not in QEMU source directory")
        try:
            bn = check_output(["git-branch-name"]).strip()
        except:
            bn = "[detached]"
        prefix = os.path.join(Q_RUNDIR, "install", bn)
        configure_opts = []
        if not args.no_debug:
            configure_opts.append("--enable-debug")
        try:
            source_path = os.path.dirname(
                              os.path.realpath(
                                  os.path.join(build_dir, "Makefile")))
        except:
            source_path = None
        if args.rebuild or not source_path or cwd.strip() != source_path.strip():
            if args.rebuild:
                print("Rebuild forced")
            if os.path.isdir(build_dir):
                shutil.rmtree(build_dir)
            check_call(["mkdir", "-p", build_dir])
            logging.debug("Configuring...")
            cfg_cmd = [os.path.join(cwd, "configure"),
                       "--prefix=" + prefix] + \
                      configure_opts + argv
            if args.target_list:
                cfg_cmd += ["--target-list=" + args.target_list]
            print_cmd(cfg_cmd)
            check_call(cfg_cmd, cwd=build_dir)
        logging.debug("Compiling...")
        nr_cores = get_nr_cores()
        check_call(["make", "-j", str(nr_cores), "-C", build_dir])
        if args.install:
            logging.debug("Installing...")
            check_call(["make", "-j", str(nr_cores), "-C", build_dir,
                        "install"])

class IotestsCommand(SubCommand):
    name = "iotests"
    want_argv = True
    help = "Run iotests in QEMU build dir"

    def setup_args(self, parser):
        parser.add_argument("-A", "--all", action="store_true",
                            help="Run formats raw qcow2 and vmdk")
        parser.add_argument("-i", "--ignore-error", action="store_true",
                            help="Continue even on error")
    def do(self, args, argv):
        build_dir = os.path.join(Q_RUNDIR, "build")
        if args.all:
            for i in ['-raw', '-qcow2', '-vmdk']:
                try:
                    check_call(["./check", i] + argv,
                               cwd=os.path.join(build_dir, "tests", "qemu-iotests"))
                except:
                    if not args.ignore_error:
                        raise
        else:
            check_call(["./check"] + argv,
                       cwd=os.path.join(build_dir, "tests", "qemu-iotests"))

class VMGrowCommand(SubCommand):
    name = "vmgrow"
    want_argv = False
    help = "Grow guest image"

    growcmds = [
        '--run-command', '/bin/bash /bin/growpart /dev/vda 1',
        '--run-command', 'resize2fs /dev/vda1 || xfs_growfs /dev/vda1',
        '--run-command', 'sync',
    ]

    def setup_args(self, parser):
        parser.add_argument("image", help="Image file")
        parser.add_argument("size", help="new size")

    def do(self, args, argv):
        subprocess.check_call(["qemu-img", 'resize', args.image, args.size])
        subprocess.check_call([sys.argv[0], 'customize'] + self.growcmds + [
            '-a', args.image])

ubuntu_user_data = """
#cloud-config
autoinstall:
  version: 1
  identity:
    hostname: ubuntu-server
    password: "$6$exDY1mhS4KUYCE/2$zmn9ToZwTKLhCw.b4/b.ZRTIZM30JZ4QrOQ2aOXJ8yk96xpcCof0kxKwuX1kqLG/ygbJ1f8wxED22bTL4F46P0"
    username: ubuntu
"""

grub_cfg = """
set timeout=3

loadfont unicode

set menu_color_normal=white/black
set menu_color_highlight=black/light-gray

menuentry "Try or Install Ubuntu Server" {
    linux   /casper/vmlinuz autoinstall ds=nocloud;s=/cdrom/
    initrd  /casper/initrd
}
"""

isolinux_cfg = """
default autoinstall-server
label autoinstall-server
  menu label ^Autoinstall Server (HWE Kernel, NVIDIA, NetworkManager)
  kernel /casper/hwe-vmlinuz
  append   initrd=/casper/hwe-initrd quiet autoinstall ds=nocloud;s=/cdrom/ ---
"""

class VMCreateCommand(SubCommand):
    name = "vmcreate"
    want_argv = False
    help = "Create VM guests"

    flavors = {
        'ubuntu-22.04': {
            'url': "https://cloud-images.ubuntu.com/releases/jammy/release/ubuntu-22.04-server-cloudimg-amd64.img",
            'customize_args': [
                "--run-command", "touch .hushlogin",
                "--run-command", "echo PermitRootLogin yes >> /etc/ssh/sshd_config",
                "--run-command", "echo PubkeyAcceptedKeyTypes +ssh-rsa >> /etc/ssh/sshd_config",
                "--uninstall", "snap,snapd,cloud-init",
            ],
        },
        'ubuntu-arm64': {
            'url': "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img",
            'customize_args': [
                "--run-command", "touch .hushlogin",
                "--uninstall", "snap,snapd,cloud-init",
            ],
        },
        'ubuntu-iso': {
            'url': "https://cdimage.ubuntu.com/ubuntu-server/focal/daily-live/current/focal-live-server-amd64.iso",
            'customize_args': [
                "--run-command", "touch .hushlogin",
                "--uninstall", "snap,snapd,cloud-init",
            ],
        },
        'buster': {
            'url': 'https://cloud.debian.org/images/cloud/buster/20210329-591/debian-10-generic-amd64-20210329-591.qcow2',
        },
        'centos7': {
            'url': 'https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud-2111.qcow2',
        },
        'centos8': {
            'url': 'https://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2',
        },
        'fedora': {
            'url': 'https://download.fedoraproject.org/pub/fedora/linux/releases/36/Cloud/x86_64/images/Fedora-Cloud-Base-36-1.5.x86_64.raw.xz',
            'customize_args': [
                "--install", "cloud-utils-growpart",
            ],
        },
        'phoronix-test-suite': {
            'url': "https://cloud-images.ubuntu.com/releases/jammy/release/ubuntu-22.04-server-cloudimg-amd64.img",
            'customize_args': [
                "--run-command", "touch .hushlogin",
                "--uninstall", "snap,snapd,cloud-init",
                "--install", "unzip",
                "--run-command", """
                set -e
                wget https://phoronix-test-suite.com/releases/repo/pts.debian/files/phoronix-test-suite_10.8.4_all.deb -O pts.deb
                DEBIAN_FRONTEND=noninteractive apt install -y ./pts.deb
                rm pts.deb
                """
            ],
        },
        'k3s': {
            'url': "https://cloud-images.ubuntu.com/releases/jammy/release/ubuntu-22.04-server-cloudimg-amd64.img",
            'customize_args': [
                "--run-command", "touch .hushlogin",
                "--run-command", "echo PermitRootLogin yes >> /etc/ssh/sshd_config",
                "--run-command", "echo PubkeyAcceptedKeyTypes +ssh-rsa >> /etc/ssh/sshd_config",
                "--uninstall", "snap,snapd,cloud-init",
                "--hostname", "k3s",
                "--run-command", """systemctl disable systemd-resolved
                                    systemctl stop systemd-resolved
                                    rm /etc/resolv.conf
                                    echo nameserver 8.8.8.8 > /etc/resolv.conf
                                    curl -sfL https://get.k3s.io | sh -
                                    sync
                """
            ],
        },
    }

    def setup_args(self, parser):
        parser.add_argument("-f", "--flavor", default="ubuntu-22.04",
                            help="Guest VM flavor to create. supported: %s" % (', '.join(self.flavors)))
        parser.add_argument("--force", "-F", action="store_true",
                            help="Force overwrite the image")
        parser.add_argument("--install", "-i", default="",
                            help="Install extra packages")
        parser.add_argument("--size", "-s", default="10G",
                            help="virtual size of the image. Specifying as 0 disables resize")
        parser.add_argument("image", help="Image file")
        parser.add_argument("--root-password", default="testpass")
        parser.add_argument("--hostname")
        parser.add_argument("--run-command")
        parser.add_argument("--verbose", "-v", action="store_true")

    def create_image_via_cloud_image(self, flavor, url, args, customize_args=[]):
        cloudimg = os.path.join(self._cache_dir, flavor + ".img")
        if not os.path.exists(cloudimg):
            cloudimg_tmp = cloudimg + ".tmp"
            subprocess.check_call(["wget", "-O", cloudimg_tmp, url])
            if url.endswith(".xz"):
                subprocess.check_call(["mv", cloudimg_tmp, cloudimg_tmp + ".xz"])
                subprocess.check_call(["unxz", cloudimg_tmp + ".xz"])
            subprocess.check_call(["mv", cloudimg_tmp, cloudimg])
        subprocess.check_call(["cp", cloudimg, args.image])
        if args.size != "0":
            subprocess.check_call(["qemu-img", 'resize', args.image, args.size])
            growcmds = VMGrowCommand.growcmds
        else:
            growcmds = []
        install_pkgs = []
        if args.install:
            install_pkgs = [x.strip() for x in args.install.split(',')]
        if install_pkgs:
            customize_args += ['--install', ','.join(install_pkgs)]
        if args.verbose:
            customize_args += ['--verbose']
        if args.hostname:
            customize_args += ['--hostname', args.hostname]
        if args.run_command:
            customize_args += ['--run-command', args.run_command]
        cmd = [sys.argv[0], 'customize'] + growcmds + [
            '--run-command', 'ssh-keygen -A',
            '--run-command', 'echo SELINUX=disabled > /etc/selinux/config || true',
            '--copy-in', os.path.realpath(sys.argv[0]) + ':/usr/local/bin',
            '--run-command', """
                set -x
                for tty in tty0 ttyS0; do
                    mkdir -p /etc/systemd/system/serial-getty@$tty.service.d/ &&
                    cd /etc/systemd/system/serial-getty@$tty.service.d/ &&
                    (
                        echo [Service] &&
                        echo ExecStart= &&
                        echo 'ExecStart=-/sbin/agetty --autologin root %I $TERM'
                    ) > override.conf
                done
            """] + customize_args + [
            '--root-password', args.root_password,
            '--ssh-inject', os.path.expanduser("~/.ssh/id_rsa.pub"),
            '-a', args.image]
        print("\n".join(cmd))
        subprocess.check_call(cmd)

    def create_image_via_ubuntu_iso(self, flavor, url, args, customize_args=[]):
        iso = os.path.join(self._cache_dir, flavor + ".iso")
        uiso = os.path.join(self._cache_dir, flavor + "-unattended.iso")
        if not os.path.exists(iso):
            iso_tmp = iso + ".tmp"
            subprocess.check_call(["wget", "-O", iso_tmp, url])
            subprocess.check_call(["mv", iso_tmp, iso])
        tmpd = self.mkdtemp()
        atexit.register(lambda: shutil.rmtree(tmpd))
        print(tmpd)
        subprocess.check_output(['7z', 'x', iso], cwd=tmpd)
        if False:
            with open(os.path.join(tmpd, 'meta-data'), 'w') as f:
                f.write(ubuntu_user_data)
            with open(os.path.join(tmpd, 'boot/grub/grub.cfg'), 'w') as f:
                f.write(grub_cfg)
            with open(os.path.join(tmpd, 'isolinux/txt.cfg'), 'w') as f:
                f.write(isolinux_cfg)
        cmd = f"""
        # echo > md5sum.txt;
        genisoimage -quiet -D -r -V "ubuntu-autoinstall" \
                -cache-inodes -J -l -joliet-long \
                -b isolinux/isolinux.bin -c isolinux/boot.cat \
                -no-emul-boot -boot-load-size 4 \
                -boot-info-table -eltorito-alt-boot -e boot/grub/efi.img \
                -no-emul-boot -o {uiso} .
                """
        subprocess.check_call(cmd, cwd=tmpd, shell=True)
        print(uiso)
        subprocess.check_output(f"q q +vblk:test.img -cdrom {uiso}", shell=True)

    def create_image(self, flavor, url, args, customize_args=[]):
        if url.endswith(".iso"):
            return self.create_image_via_ubuntu_iso(flavor, url, args, customize_args)
        else:
            return self.create_image_via_cloud_image(flavor, url, args, customize_args)

    def do(self, args, argv):
        self._cache_dir = os.path.join(Q_RUNDIR, ".vmcreate")
        if os.path.exists(args.image) and not args.force:
            logging.error("File %s exists but --force is not specified" % args.image)
            return 1
        if not os.path.exists(self._cache_dir):
            os.makedirs(self._cache_dir)
        flavor = self.flavors[args.flavor]
        self.create_image(args.flavor, flavor['url'], args, flavor.get("customize_args", []))

class MkinitrdCommand(SubCommand):
    name = "mkinitrd"
    want_argv = False
    help = "Make initrd"

    def setup_args(self, parser):
        parser.add_argument("--cmd", "-c", default="true")
        parser.add_argument("--script", "-s", default="")
        parser.add_argument("--output", "-o", required=True)

    def do(self, args, argv):
        tmpd = tempfile.mkdtemp()
        atexit.register(lambda: shutil.rmtree(tmpd))
        cmd = f"""
        set -e
        set -x
        cd '{tmpd}';
        mkdir -p bin dev sys proc sysroot
        which busybox
        ldd $(which busybox) 2>&1 | grep -q 'not a dynamic executable'
        cp $(which busybox) busybox
        ./busybox --list | while read x; do ln -s ../busybox bin/$x; done
        if test -n "{args.script}"; then
            cp "{args.script}" init-script
        fi
        cat >init <<EOF
#!/bin/sh
set -e
set -x
mount -t devtmpfs dev /dev
mount -t sysfs sysfs /sys
mount -t proc proc /proc
for x in /dev/vda*; do
    if mount \$x /sysroot; then
        if test -d /sysroot/etc; then
            break
        fi
        umount /sysroot
    fi
done
if test -d /sysroot/etc; then
    mount -o bind /sys /sysroot/sys
    mount -o bind /dev /sysroot/dev
    mount -o bind /proc /sysroot/proc
    if test -n "{args.cmd}"; then
        chroot /sysroot {args.cmd}
    fi
    if test -f /init-script; then
        cp /init-script /sysroot/tmp/init-script
        chroot /sysroot /bin/sh /tmp/init-script
    fi
    while ! umount -l /sysroot; do sleep 0.1; done
    sync
    echo o > /proc/sysrq-trigger
else
    echo Cannot find sysroot
    echo o > /proc/sysrq-trigger
fi
/bin/sh -i
EOF
        chmod +x init
        find . -print0 | cpio --null -o --format=newc > '{args.output}.cpio'
        gzip --fast -f '{args.output}.cpio'
        mv '{args.output}.cpio.gz' '{args.output}'
        """
        check_output(cmd)

class CustomizeCommand(SubCommand):
    name = "customize"
    aliases = ['c']
    want_argv = False
    help = "Customize image"

    def setup_args(self, parser):
        parser.add_argument("--image", "-a")
        parser.add_argument("--ssh-inject")
        parser.add_argument("--install", default="")
        parser.add_argument("--uninstall", default="")
        parser.add_argument("--run-command", action="append", default=[])
        parser.add_argument("--hostname")
        parser.add_argument("--root-password")
        parser.add_argument("--copy-in", action="append")
        parser.add_argument("--verbose", action="store_true")

    def do(self, args, argv):
        img = args.image
        if args.ssh_inject or args.root_password:
            if 'qcow2' in check_output(['qemu-img', 'info', img]):
                rawimg = img + ".raw"
                check_output(['qemu-img', 'convert', img, rawimg])
                self.ssh_inject(rawimg, args.ssh_inject)
                check_output(['qemu-img', 'convert', rawimg, img, '-O', 'qcow2'])
                os.unlink(rawimg)
            else:
                self.ssh_inject(img, args.ssh_inject)
        cmd = []
        if args.install:
            cmd.append(self.make_install_cmd(args.install.split(',')))
        if args.uninstall:
            cmd.append(self.make_uninstall_cmd(args.uninstall.split(',')))
        if args.hostname:
            cmd.append(f"echo {args.hostname} > /etc/hostname && hostname {args.hostname}")
        if args.run_command:
            cmd += args.run_command
        if cmd:
            cmd.append('sync')
            q_cmd = [sys.argv[0], 'q', '+vblk:' + img, '-c', '\n'.join(cmd)]
            if args.verbose:
                q_cmd += ['-serial', 'stdio']
            print(q_cmd)
            check_call(q_cmd)

    def make_install_cmd(self, pkgs):
        if not pkgs:
            return "true"
        return 'export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y ' + ' '.join(pkgs)

    def make_uninstall_cmd(self, pkgs):
        if not pkgs:
            return "true"
        return 'export DEBIAN_FRONTEND=noninteractive; apt-get remove -y ' + ' '.join(pkgs)

    def ssh_inject(self, img, pubkey):
        if not pubkey.startswith("ssh-rsa ") and os.path.exists(pubkey):
            with open(pubkey, 'r') as f:
                pubkey = f.read()
        script = f"""
#!/bin/sh
set -e
mkdir -p /root/.ssh
echo '{pubkey}' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
ssh-keygen -A
if test -n "{self.args.root_password}"; then
    echo root:{self.args.root_password} | chpasswd
fi
cat >/etc/systemd/system/dhclient.service <<EOF
    [Unit]
    Description=dhclient service generated by q-script

    [Service]
    ExecStart=/usr/sbin/dhclient
    Type=oneshot

    [Install]
    WantedBy=multi-user.target
EOF
systemctl enable dhclient
        """
        with tempfile.NamedTemporaryFile() as tf:
            tf.write(script.encode())
            tf.flush()
            initrd = tf.name + '.initfd'
            cmd = [sys.argv[0], 'mkinitrd', '-s', tf.name, '-o', initrd]
            check_call(cmd)
            cache_dir = os.path.join(Q_RUNDIR, ".vmcreate")
            kernel = os.path.join(cache_dir, "kernel")
            if not os.path.exists(kernel):
                kernel_xz = kernel + ".xz"
                url = 'https://gitlab.com/famzheng/q-script/-/jobs/4356281461/artifacts/raw/build/bzImage.x86_64.xz'
                subprocess.check_call(["wget", "-O", kernel_xz, url])
                subprocess.check_call(["unxz", kernel_xz])
            append = 'console=ttyS0'
            cmd = [sys.argv[0], 'q', '+vblk:' + img, '-f', '--',
                  '-serial', 'stdio',
                  '-kernel', kernel, '-append', append, '-initrd', initrd]
            check_call(cmd)

class PatchFilter(object):
    def __init__(self):
        self.prev_line = ""

    def filter(self, line):
        orig_line = line
        if self.prev_line == "--" and re.match("[0-9]*\.[0-9]*\.[0-9]*$", line):
            line = ""
        elif line.startswith("Subject: [PATCH"):
            line = "Subject: [PATCH XXX/XXX] " + line.split(" ", maxsplit=3)[3]
        elif re.match("From [0-9a-f]* .*:", line):
            line = "From XXXXXXXXXXXXXXXXXXXX"
        elif re.match("index [0-9a-f]*\.\.[0-9a-f]* [0-7]*", line):
            line = "index XXXXXXXXXXXX..XXXXXXXXXXXX XXXXXX"
        elif re.match("@@ -[0-9]*,[0-9]* \+[0-9]*,[0-9]* @@", line):
            line = "@@ -XXXX,XX +XXXX,XX @@ " + line.split("@@", maxsplit=2)[2]
        self.prev_line = orig_line
        return line

class PatchFilterCommand(SubCommand):
    name = "patch-filter"
    want_argv = False
    help = "Filter git patch and make it easier for branch comparison"

    def setup_args(self, parser):
        pass

    def do(self, args, argv):
        f = PatchFilter()
        for line in sys.stdin:
            print(f.filter(line.strip()))

class CompareBranchesCommand(SubCommand):
    name = "cmp-branches"
    want_argv = False
    help = "Compare two branches"

    def setup_args(self, parser):
        parser.add_argument("left", type=str, help="Left branch")
        parser.add_argument("right", type=str, help="Right branch")
        parser.add_argument("--num-commits", "-n", type=int, help="Number of commits to compare")

    def do(self, args, argv):
        left = self.get_filterd_git_log(args.left, args.num_commits)
        right = self.get_filterd_git_log(args.right, args.num_commits)
        self.do_compare(left.name, right.name)

    def get_filterd_git_log(self, ref, n):
        f = tempfile.NamedTemporaryFile(suffix="-%s.patch" % ref, dir="/var/tmp", mode='w')
        pf = PatchFilter()
        for line in subprocess.check_output(['git', 'format-patch', 'HEAD~%d..' % n,
            '--stdout', ref], encoding='utf-8').splitlines():
            f.write(pf.filter(line) + "\n")
        f.flush()
        return f

    def do_compare(self, left, right):
        subprocess.call(['vimdiff', left, right])

class FlamegraphCommand(SubCommand):
    name = "flamegraph"
    want_argv = True
    help = "Collect a flamegraph"

    flamegraph_dir = os.path.join(Q_RUNDIR, ".flamegraph")

    def setup_args(self, parser):
        parser.add_argument("--output", "-o", required=True)
        parser.add_argument("--data", "-d", type=str, help="perf data path")

    def perf_record(self, argv, output):
        # td = self.mkdtemp()
        # fn = td + "/perf.data"
        fn = output + ".perf.data"
        check_call(['sudo', '-n', 'perf', 'record', '-a', '-g', '-o', fn] + argv)
        return fn

    def gen_flame_graph(self, perf_data, output):
        cmd = "sudo -n perf script -i '%s' | %s/stackcollapse-perf.pl - > %s.stacks" % (
                perf_data, self.flamegraph_dir, output)
        check_output(cmd)

        cmd = "%s/flamegraph.pl %s.stacks > %s" % (self.flamegraph_dir, output, output)

        check_output(cmd)

    def do(self, args, argv):
        repo = 'https://github.com/brendangregg/FlameGraph'
        git_clone_maybe(repo, self.flamegraph_dir)
        if args.data:
            fn = args.data
        else:
            fn = self.perf_record(argv, args.output)
        self.gen_flame_graph(fn, args.output)

def global_args(parser):
    parser.add_argument("-D", "--debug", action="store_true",
                        help="Enable debug output")

def main():
    parser = argparse.ArgumentParser()
    global_args(parser)
    subparsers = parser.add_subparsers(title="subcommands")
    for c in SubCommand.__subclasses__():
        cmd = c()
        p = subparsers.add_parser(cmd.name, aliases=cmd.aliases,
                                  help=cmd.help)
        cmd.setup_args(p)
        p.set_defaults(func=cmd.do, cmdobj=cmd, all=False)
    args, argv = parser.parse_known_args()
    if not hasattr(args, "cmdobj"):
        parser.print_usage()
        return 1
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    if argv and not args.cmdobj.want_argv:
        raise Exception("Unrecognized arguments:\n" + argv[0])
    args.cmdobj.args = args
    r = args.func(args, argv)
    return r

if __name__ == '__main__':
    sys.exit(main())

