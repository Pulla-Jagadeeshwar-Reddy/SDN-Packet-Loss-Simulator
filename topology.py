#!/usr/bin/env python3
"""
SDN Packet Drop Simulator - Mininet Topology
=============================================
Creates a tree topology with 4 hosts connected via 2 switches,
all managed by a remote Ryu SDN controller.

Topology:
         [Ryu Controller]
               |
            [s1] (core switch)
           /     \
        [s2]     [s3]  (edge switches)
        / \       / \
      h1  h2   h3  h4

Author: SDN Lab
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
import time
import subprocess
import sys


class PacketDropTopo(Topo):
    """
    Custom tree topology for packet drop simulation.
    2 levels deep, branching factor 2 => 4 hosts, 3 switches.
    """

    def build(self):
        # --- Core switch ---
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        # --- Edge switches ---
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')

        # --- Hosts with static IPs ---
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # --- Links (with bandwidth / delay parameters) ---
        # Core uplinks
        self.addLink(s1, s2, bw=100, delay='2ms')
        self.addLink(s1, s3, bw=100, delay='2ms')

        # Host downlinks
        self.addLink(s2, h1, bw=50, delay='1ms')
        self.addLink(s2, h2, bw=50, delay='1ms')
        self.addLink(s3, h3, bw=50, delay='1ms')
        self.addLink(s3, h4, bw=50, delay='1ms')


def run_topology():
    """Main entry-point: build net, attach remote controller, start CLI."""
    setLogLevel('info')

    topo = PacketDropTopo()

    # Connect to remote Ryu controller (must be started before this script)
    controller = RemoteController(
        'ryu',
        ip='127.0.0.1',
        port=6633
    )

    net = Mininet(
        topo=topo,
        controller=controller,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,   # we set MACs explicitly in the topo
        autoStaticArp=False,  # pre-populate ARP so ping measures SDN, not ARP
        waitConnected=False
    )

    net.start()
    
    # ADD this after net.start() — wait for all switches manually
    info('\n*** Waiting for switches to connect...\n')
    time.sleep(10)

    info('\n*** Topology started\n')
    info('*** Hosts: h1=10.0.0.1  h2=10.0.0.2  h3=10.0.0.3  h4=10.0.0.4\n')
    info('*** Waiting 8 s for controller to populate initial flows...\n')
    time.sleep(8)

    # -----------------------------------------------------------------
    # Quick sanity-check: baseline ping between all host pairs
    # -----------------------------------------------------------------
    info('\n*** Running baseline ping test (all pairs)...\n')
    net.pingAll()

    info('\n*** SDN Packet Drop Topology is ready.\n')
    info('*** Open Mininet CLI.  Type "exit" to stop.\n\n')
    info('Useful CLI commands:\n')
    info('  h1 ping h2              # ICMP test\n')
    info('  h1 iperf -u -c 10.0.0.2 -b 10M -t 10  # UDP throughput (h2 must run iperf -s -u)\n')
    info('  sh ovs-ofctl dump-flows s1 -O OpenFlow13\n')
    info('  py net.get("h1").cmd("iperf -s -u &")\n\n')

    CLI(net)

    net.stop()
    info('*** Network stopped\n')


if __name__ == '__main__':
    # Ensure OVS is clean before starting
    subprocess.call(['mn', '--clean'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run_topology()