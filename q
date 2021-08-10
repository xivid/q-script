#!/usr/bin/env python3
"""
Copyright 2012-2021 Fam Zheng <fam@euphon.net>
Copyright 2021 Bytedance Inc.

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

Q_RUNDIR = os.path.expanduser("/var/tmp/q")

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

class SubCommand(object):
    """ Base class of subcommand"""
    help = ""
    aliases = []
    want_argv = False # Whether the command accepts extra arguments

    def do(self, args, argv):
        """Do command"""
        print("Not implemented")

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

def ssh_call(port, user, *argv, **kwargs):
    return subprocess.call(["ssh",
                            "-o", "ConnectTimeout=1",
                            "-o", "UserKnownHostsFile=/dev/null",
                            "-o", "StrictHostKeyChecking=no",
                            "-q",
                            "-p", str(port),
                            "%s@127.0.0.1" % user] + list(argv),
                            **kwargs)

class QemuCommand(SubCommand):
    name = "qemu"
    aliases = ["q"]
    want_argv = True
    help = "Start QEMU"
    def __init__(self):
        self._ids = {}

    def args(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Only print the command line")
        parser.add_argument("--memory", type=str, default="1G",
                            help="memory size")
        parser.add_argument("--name", type=str,
                            help="name of the QEMU instance")
        parser.add_argument("-f", "--foreground", action="store_true",
                            help="Don't detach after QEMU started")
        parser.add_argument("-p", "--program", default="qemu-system-x86_64",
                            help="Which qemu executable to use")
        parser.add_argument("--no-net", action="store_true",
                            help="Don't add network")
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

    def _def_args(self, args):
        self._sshport = find_port(10022)
        ret = ["-enable-kvm",]
        ret += ["-m", args.memory]
        ret += ["-qmp", "unix:%s,server,nowait" % self._rundir_filename("qmp")]
        ret += ["-name", self.name]
        if not os.environ.get("DISPLAY"):
            ret += ["-display", "none", "-vnc", ":0,to=20"]
        # TODO: fix 10022 to a dynamic port
        if not args.no_net:
            ret += ["-netdev", "user,id=vnet,net=%s,host=%s,hostfwd=:0.0.0.0:%d-:22" % (args.net, args.host, self._sshport),
                    "-device", "virtio-net-pci,netdev=vnet,mac=00:8c:fa:e4:a3:53"]

        return ret;

    def _gen_id(self, prefix=""):
        r = self._ids[prefix] = self._ids.get(prefix, 0) + 1
        return prefix + str(r)

    def _gen_drive(self, s):
        drive = self._gen_id("drive-")
        optstr = "file=%s,if=none,id=%s" % (s, drive)
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
        return opts + r + ["-device", "scsi-disk,bus=scsi0.0,drive=%s,bootindex=1" % drive]

    def _devtmpl_sd(self, s):
        opts = []
        if not hasattr(self, "_has_scsi_bus"):
            opts += ["-device", "virtio-scsi-pci,id=scsi0"]
            self._has_scsi_bus = True
        drive, r = self._gen_drive(s)
        return opts + r + ["-device", "scsi-disk,bus=scsi0.0,id=%s,drive=%s" % (drive + "-sd", drive)]

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

        cmd = args.program.split() + self._def_args(args) + self._parse_argv(argv)
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
                sf = getattr(self, 'serial')
                if sf and sf.startswith(self._rundir):
                    subprocess.call(['cat', sf])
                logging.error("Timeout while waiting for SSH server")
                return 1
        else:
            # TODO: Wait for QMP or pidfile?
            time.sleep(0.5)
        if args.run_cmd:
            r = ssh_call(self._sshport, "root", args.run_cmd)
            qemup.kill()
            return r
        return 0

class QMPCommand(SubCommand):
    name = "qmp"
    want_argv = True
    help = "Execute QMP command"

    def args(self, parser):
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

    def args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        return ssh_call(i.sshport, "root", *argv)

class ListCommand(SubCommand):
    name = "list"
    want_argv = True
    help = "List managed QEMU instances"

    def args(self, parser):
        pass

    def do(self, args, argv):
        for i in get_all_qemu_instances():
            print(i.name)

class SSHCopyIdCommand(SubCommand):
    name = "ssh-copy-id"
    want_argv = False
    help = "Execute ssh-copy-id command"

    def args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        return subprocess.call(["ssh-copy-id", "-p", str(i.sshport), "root@127.0.0.1"])

class HMPCommand(SubCommand):
    name = "hmp"
    want_argv = True

    def args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        print(argv)
        r = i.do_qmp('human-monitor-command',
                     **{'command-line': " ".join(argv)})
        print(r)
        return 0

class GDBCommand(SubCommand):
    name = "gdb"
    want_argv = True

    def args(self, parser):
        parser.add_argument("--name", type=str, help="QEMU instance name")

    def do(self, args, argv):
        i = get_qemu_instance(args.name)
        return subprocess.call(["gdb", "-p", str(i.pid)])

class PidCommand(SubCommand):
    name = "pid"
    help = "Get PID of QEMU process"

    def args(self, parser):
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

class BuildCommand(SubCommand):
    name = "build"
    aliases = ["b"]
    want_argv = True
    help = "Build QEMU"
    def args(self, parser):
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

    def args(self, parser):
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

class VMCreateCommand(SubCommand):
    name = "vmcreate"
    want_argv = False
    help = "Create VM guests"

    def args(self, parser):
        parser.add_argument("-f", "--flavor", default="ubuntu",
                            help="Guest VM flavor to create. "
                                 "Supported: fedora")
        parser.add_argument("--force", "-F", action="store_true",
                            help="Force overwrite the image")
        parser.add_argument("image", help="Image file")

    def _create_image(self, flavor, url, args):
        if os.path.exists(flavor):
            cloudimg = flavor
        else:
            cloudimg = os.path.join(self._cache_dir, flavor + ".img")
            if not os.path.exists(cloudimg):
                cloudimg_tmp = cloudimg + ".tmp"
                subprocess.check_call(["wget", "-O", cloudimg_tmp, url])
                subprocess.check_call(["mv", cloudimg_tmp, cloudimg])
        subprocess.check_call(["cp", cloudimg, args.image])
        subprocess.check_call(["qemu-img", 'resize', args.image, '50G'])
        subprocess.check_call(['virt-customize',
            '--run-command', '/bin/bash /bin/growpart /dev/sda 1',
            '--run-command', 'resize2fs /dev/sda1 || xfs_growfs /dev/sda1',
            '--run-command', 'ssh-keygen -A',
            '--run-command', 'echo SELINUX=disabled > /etc/selinux/config || true',
            '--root-password', 'password:testpass',
            '--ssh-inject', 'root',
            '-a', args.image])

    def do(self, args, argv):
        self._cache_dir = os.path.join(Q_RUNDIR, ".vmcreate")
        if os.path.exists(args.image) and not args.force:
            logging.error("File %s exists but --force is not specified" % args.image)
            return 1
        if not os.path.exists(self._cache_dir):
            os.makedirs(self._cache_dir)
        if args.flavor in ['ubuntu', 'ubuntu2004']:
            url = "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"
            self._create_image('ubuntu', url, args)
            subprocess.check_call(['virt-customize',
                '--uninstall', 'cloud-init,snap',
                '--install', 'dhcpcd5',
                '-a', args.image])
        if args.flavor in ['buster']:
            url = 'https://cloud.debian.org/images/cloud/buster/20210329-591/debian-10-generic-amd64-20210329-591.qcow2'
            self._create_image('buster', url, args)
        elif args.flavor in ['stretch']:
            url = "https://cloud.debian.org/images/cloud/buster/latest/debian-10-generic-amd64.qcow2"
            self._create_image('buster', url, args)
        elif args.flavor in ['centos']:
            url = "https://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2"
            self._create_image('centos', url, args)
        else:
            self._create_image(args.flavor, None, args)

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
        if hasattr(cmd, "args"):
            cmd.args(p)
        p.set_defaults(func=cmd.do, cmdobj=cmd, all=False)
    args, argv = parser.parse_known_args()
    if not hasattr(args, "cmdobj"):
        parser.print_usage()
        return 1
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    if argv and not args.cmdobj.want_argv:
        raise Exception("Unrecognized arguments:\n" + argv[0])
    r = args.func(args, argv)
    return r

if __name__ == '__main__':
    sys.exit(main())

