"""
SDN Packet Drop Simulator - Ryu Controller
===========================================
OpenFlow 1.3 controller that:
  1. Learns MAC addresses and installs unicast forwarding rules (L2 switch).
  2. Exposes an /drop_rules REST API to install selective DROP rules.
  3. Exposes a /clear_drops REST API to remove all drop rules.
  4. Maintains a log of every packet_in event for analysis.

Run with:
    ryu-manager --ofp-tcp-listen-port 6633 packet_drop_controller.py

REST endpoints (WSGI on port 8080):
    POST /drop_rules          body: {"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","proto":"udp"}
    DELETE /drop_rules        removes all drop flows from every switch
    GET  /flow_stats          dumps flow tables across all connected switches
    GET  /event_log           returns the packet_in event log as JSON

Author: SDN Lab
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

import json
import logging
import time
from collections import defaultdict

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
DROP_PRIORITY    = 200   # higher than forwarding (100) → drop wins
FORWARD_PRIORITY = 100
TABLE_ID         = 0
DROP_HARD_TIMEOUT = 0    # permanent until explicitly removed
IDLE_TIMEOUT      = 30   # forwarding rules expire after 10 s of inactivity

APP_NAME = 'packet_drop_app'

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# ═══════════════════════════════════════════════════════════════════
# Main Application
# ═══════════════════════════════════════════════════════════════════
class PacketDropController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # mac_table[dpid][mac] = out_port
        self.mac_table: dict[int, dict[str, int]] = defaultdict(dict)

        # datapath registry
        self.datapaths: dict[int, object] = {}

        # Event log: list of dicts for REST export
        self.event_log: list[dict] = []

        # FIX 1: Track installed drop rules so we can delete them precisely
        # Each entry: (dpid, match_fields_tuple) → the OFPMatch used
        self.active_drop_rules: list[dict] = []
        self.flow_stats = []
        
        self.mac_to_ip = {
            "00:00:00:00:00:01": "10.0.0.1",
            "00:00:00:00:00:02": "10.0.0.2",
            "00:00:00:00:00:03": "10.0.0.3",
            "00:00:00:00:00:04": "10.0.0.4"
        }

        # Register REST API
        wsgi: WSGIApplication = kwargs['wsgi']
        wsgi.register(DropRulesAPI, {APP_NAME: self})

        logger.info("PacketDropController started – listening for switches")
	

    # ──────────────────────────────────────────
    # Switch handshake
    # ──────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        logger.info("Switch connected: dpid=%016x", dp.id)
        self._install_table_miss(dp)

    def _install_table_miss(self, dp):
        """Send all unmatched packets to the controller (table-miss)."""
        ofp  = dp.ofproto
        parser = dp.ofproto_parser
        match  = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                           ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, priority=0, match=match, actions=actions,
                       idle_timeout=0, hard_timeout=0)
        logger.debug("Table-miss flow installed on dpid=%016x", dp.id)

    # ──────────────────────────────────────────
    # Packet-In handler  (L2 learning switch)
    # ──────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg    = ev.msg
        dp     = msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        dpid    = dp.id

        pkt      = packet.Packet(msg.data)
        eth_pkt  = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst
        ethertype = eth_pkt.ethertype

        # ── Log the event ──────────────────────────────────────────
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "dpid": "%016x" % dpid,
            "in_port": in_port,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            log_entry["src_ip"]   = ip_pkt.src
            log_entry["dst_ip"]   = ip_pkt.dst
            log_entry["ip_proto"] = ip_pkt.proto
        self.event_log.append(log_entry)
        # keep log bounded
        if len(self.event_log) > 5000:
            self.event_log = self.event_log[-5000:]

        # ── MAC learning ───────────────────────────────────────────
        self.mac_table[dpid][src_mac] = in_port
        logger.debug("Learned  dpid=%016x  mac=%s  port=%d", dpid, src_mac, in_port)

        # ── Determine output port ──────────────────────────────────
        if dst_mac in self.mac_table[dpid]:
            out_port = self.mac_table[dpid][dst_mac]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # ── Install unicast forwarding flow (not for floods) ────────
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst_mac,
                                    eth_src=src_mac)
            self._add_flow(dp,
                           priority=FORWARD_PRIORITY,
                           match=match,
                           actions=actions,
                           idle_timeout=IDLE_TIMEOUT,
                           hard_timeout=0)

        # ── Send the buffered packet ───────────────────────────────
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)
        
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.flow_stats = []

        for stat in body:
            entry = {
                "match": stat.match,
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "priority": stat.priority
            }
            self.flow_stats.append(entry)

    # ──────────────────────────────────────────
    # Flow helpers
    # ──────────────────────────────────────────
    def _add_flow(self, dp, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, table_id=TABLE_ID):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod    = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            table_id=table_id
        )
        dp.send_msg(mod)

    def _add_drop_flow(self, dp, priority, match,
                       idle_timeout=0, hard_timeout=DROP_HARD_TIMEOUT):
        """Install a flow with an empty action list → DROP."""
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,[])]
        mod    = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            table_id=TABLE_ID
        )
        dp.send_msg(mod)
        logger.info("DROP rule installed on dpid=%016x  match=%s", dp.id, match)

    def request_flow_stats(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp)
        dp.send_msg(req)

    # ──────────────────────────────────────────
    # Public API used by the REST layer
    # ──────────────────────────────────────────
    def install_drop_rule(self, rule: dict) -> dict:
        """
        Install a selective DROP rule on ALL connected switches.

        FIX 1 - Directional drop: rule only applies in the direction specified
        by src_ip → dst_ip. Reverse direction is NOT affected.

        Supported rule keys (all optional, combine freely):
            src_ip  / dst_ip   – IPv4 addresses
            src_mac / dst_mac  – Ethernet MAC
            proto              – "tcp" | "udp" | "icmp"
            src_port / dst_port – TCP/UDP port (requires proto)

        Returns a status dict.
        """
        results = {}
        for dpid, dp in self.datapaths.items():
            parser = dp.ofproto_parser
            match_fields = {}

            # Layer-2 fields
            if 'src_mac' in rule:
                match_fields['eth_src'] = rule['src_mac']
            if 'dst_mac' in rule:
                match_fields['eth_dst'] = rule['dst_mac']

            # Layer-3 + Layer-4 fields
            proto_str = rule.get('proto', '').lower()
            ip_proto  = None
            if 'src_ip' in rule or 'dst_ip' in rule or proto_str:
                match_fields['eth_type'] = 0x0800  # IPv4
                if 'src_ip' in rule:
                    match_fields['ipv4_src'] = rule['src_ip']
                if 'dst_ip' in rule:
                    match_fields['ipv4_dst'] = rule['dst_ip']

                if proto_str == 'tcp':
                    ip_proto = 6
                    match_fields['ip_proto'] = ip_proto
                    if 'src_port' in rule:
                        match_fields['tcp_src'] = int(rule['src_port'])
                    if 'dst_port' in rule:
                        match_fields['tcp_dst'] = int(rule['dst_port'])
                elif proto_str == 'udp':
                    ip_proto = 17
                    match_fields['ip_proto'] = ip_proto
                    if 'src_port' in rule:
                        match_fields['udp_src'] = int(rule['src_port'])
                    if 'dst_port' in rule:
                        match_fields['udp_dst'] = int(rule['dst_port'])
                elif proto_str == 'icmp':
                    ip_proto = 1
                    match_fields['ip_proto'] = ip_proto

            if not match_fields:
                return {"error": "No match fields specified – refusing to install a catch-all drop."}

            match = parser.OFPMatch(**match_fields)
            self._add_drop_flow(dp, priority=DROP_PRIORITY, match=match)
            results["%016x" % dpid] = "installed"

            # FIX 1: Track this rule so clear can delete it precisely
            self.active_drop_rules.append({
                "dpid": dpid,
                "match_fields": match_fields
            })

        return {"status": "ok", "switches": results, "rule": rule}

    def clear_drop_rules(self) -> dict:
        """
        FIX 2: Delete ONLY drop rules by replaying each stored match with
        OFPFC_DELETE_STRICT (which respects priority), instead of using a
        wildcard OFPFC_DELETE that wipes the entire flow table.

        After deleting, the forwarding rules and table-miss are untouched.
        """
        results = {}

        for entry in self.active_drop_rules:
            dpid = entry["dpid"]
            match_fields = entry["match_fields"]

            if dpid not in self.datapaths:
                continue

            dp     = self.datapaths[dpid]
            ofp    = dp.ofproto
            parser = dp.ofproto_parser

            match = parser.OFPMatch(**match_fields)

            # OFPFC_DELETE_STRICT respects priority — only deletes flows that
            # match BOTH the match fields AND the priority exactly.
            # This means forwarding rules (priority 100) and table-miss
            # (priority 0) are completely untouched.
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE_STRICT,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                priority=DROP_PRIORITY,
                match=match,
                table_id=TABLE_ID
            )
            dp.send_msg(mod)
            results["%016x" % dpid] = "cleared"
            logger.info("Cleared drop rule on dpid=%016x match=%s", dpid, match)

        # Clear the tracking list
        self.active_drop_rules.clear()

        return {"status": "ok", "switches": results}

    def get_event_log(self) -> list:
        return self.event_log


# ═══════════════════════════════════════════════════════════════════
# REST API Controller  (WSGI)
# ═══════════════════════════════════════════════════════════════════
class DropRulesAPI(ControllerBase):
    """Thin REST layer wrapping PacketDropController methods."""

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app: PacketDropController = data[APP_NAME]

    # POST /drop_rules  – install a new drop rule
    @route('drop_rules', '/drop_rules', methods=['POST'])
    def add_drop_rule(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as e:
            return self._json_response({"error": str(e)}, status=400)

        result = self.app.install_drop_rule(body)
        return self._json_response(result)

    # DELETE /drop_rules – remove all drop rules
    @route('drop_rules_delete', '/drop_rules', methods=['DELETE'])
    def remove_drop_rules(self, req, **kwargs):
        result = self.app.clear_drop_rules()
        return self._json_response(result)

    # GET /event_log – return packet_in history
    @route('event_log', '/event_log', methods=['GET'])
    def event_log(self, req, **kwargs):
        return self._json_response(self.app.get_event_log())
       
    @route('metrics', '/metrics', methods=['GET'])
    def get_metrics(self, req, **kwargs):
        app = self.app
    
        app.flow_stats = []
    
        # request stats
        for dp in app.datapaths.values():
            app.request_flow_stats(dp)
    
        import time
        time.sleep(2)
    
        flows = {}
    
        for stat in app.flow_stats:
            match = stat["match"]
            packets = stat["packet_count"]
            priority = stat["priority"]
    
            # extract MACs from string
            match = stat["match"]
            packets = stat["packet_count"]
            priority = stat["priority"]

            src_mac = match.get('eth_src')
            dst_mac = match.get('eth_dst')

            src_ip = match.get('ipv4_src')
            dst_ip = match.get('ipv4_dst')

            if src_ip and dst_ip:
                key = f"{src_ip}->{dst_ip}"
            elif src_mac and dst_mac:
                src_ip = app.mac_to_ip.get(src_mac, src_mac)
                dst_ip = app.mac_to_ip.get(dst_mac, dst_mac)
                key = f"{src_ip}->{dst_ip}"
            else:
                continue
    
            src_ip = app.mac_to_ip.get(src_mac, src_mac)
            dst_ip = app.mac_to_ip.get(dst_mac, dst_mac)
    
            key = f"{src_ip}->{dst_ip}"
    
            if key not in flows:
                flows[key] = {"forwarded": 0, "dropped": 0}
   
            if priority == 200:
                flows[key]["dropped"] += packets
            elif priority == 100:
                flows[key]["forwarded"] += packets
    
        # compute loss per flow
        result = []
    
        for key, data in flows.items():
            total = data["forwarded"] + data["dropped"]

            if total == 0:
                loss = 0
            else:
                loss = (data["dropped"] / total) * 100
    
            src, dst = key.split("->")

            result.append({
                "src": src,
                "dst": dst,
                "forwarded_packets": data["forwarded"],
                "dropped_packets": data["dropped"],
                "loss_percent": round(loss, 2)
            })

        return self._json_response({
            "flow_metrics": result
        })

    # ── helper ──
    @staticmethod
    def _json_response(data, status=200):
        from webob import Response
        body = json.dumps(data, indent=2).encode('utf-8')
        return Response(content_type='application/json',
                        body=body,
                        status=status)