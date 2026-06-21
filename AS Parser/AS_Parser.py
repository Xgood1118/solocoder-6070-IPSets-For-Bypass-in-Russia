#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

ASN_LIST_DEFAULT = {
    "Scaleway": "AS12876",
    "Hetzner": "AS24940",
    "Hetzner 2": "AS213230",
    "Hetzner 3": "AS212317",
    "Hetzner 4": "AS215859",
    "Akamai": "AS20940",
    "Akamai 2": "AS16625",
    "Akamai 3": "AS12222",
    "Akamai 4": "AS33905",
    "Akamai 5": "AS21342",
    "Akamai 6": "AS32787",
    "Akamai 7": "AS35994",
    "Akamai 8": "AS12400",
    "Akamai 9": "AS15802",
    "Akamai 10": "AS18209",
    "Akamai 11": "AS24319",
    "Akamai 12": "AS25019",
    "Akamai 13": "AS26008",
    "Akamai 14": "AS31108",
    "Akamai 15": "AS34164",
    "Akamai 16": "AS49846",
    "Akamai 17": "AS17204",
    "Akamai 18": "AS213120",
    "Akamai 19": "AS393234",
    "Akamai 20": "AS393560",
    "Akamai Cloud (Linode)": "AS63949",
    "DigitalOcean": "AS14061",
    "DigitalOcean 2": "AS46652",
    "DigitalOcean 3": "AS393406",
    "Datacamp, CDN77": "AS60068",
    "Datacamp, CDN77 2": "AS212238",
    "Contabo": "AS51167",
    "Contabo 2": "AS141995",
    "Contabo 3": "AS40021",
    "OVH": "AS16276",
    "OVH 2": "AS35540",
    "Vultr (Constant)": "AS20473",
    "Cloudflare": "AS13335",
    "Cloudflare 2": "AS14789",
    "Cloudflare 3": "AS132892",
    "Cloudflare 4": "AS395747",
    "Cloudflare 5": "AS209242",
    "Clouvider": "AS62240",
    "CreaNova": "AS51765",
    "Oracle Cloud": "AS31898",
    "Oracle 2": "AS1219",
    "Amazon": "AS16509",
    "Amazon 2": "AS14618",
    "Amazon 3": "AS8987",
    "G-Core": "AS199524",
    "G-Core 2": "AS202422",
    "Fellowship": "AS46461",
    "Fastly": "AS54113",
    "FranTech": "AS53667",
    "LogicForge": "AS208621",
    "Hostinger": "AS47583",
    "Hostinger 2": "AS204915",
    "Ionos": "AS8560",
    "Ionos 2": "AS15418",
    "DreamHost": "AS29873",
    "GoDaddy": "AS26496",
    "GoDaddy 2": "AS398101",
    "HostGator, BlueHost": "AS46606",
    "Cogent": "AS174",
    "Riot Games, Inc": "AS6507",
    "I3DNET (Discord)": "AS49544",
    "IOMART": "AS20860",
    "IOMART 2": "AS21130",
    "Google Cloud": "AS15169",
    "Microsoft Azure": "AS8075",
    "Melbicom": "AS8849",
    "Melbicom 2": "AS56630",
    "M247 Europe SRL": "AS9009",
    "M247 Europe SRL 2": "AS39675",
    "HostPapa, ColoCrossing": "AS36352",
    "Hurricane Electric": "AS6939",
    "GTT Communications": "AS3257",
    "NTT Global": "AS2914",
    "Telia Carrier": "AS1299",
    "Firstcolo": "AS44066",
    "Hosteur": "AS20773",
    "ITL DC": "AS210403",
    "TELECOM ITALIA SPARKLE S.p.A": "AS6762",
    "Orange (FTRSI)": "AS5511",
    "GlobeNet": "AS52320",
    "Lumen": "AS3356",
    "Tata Communications": "AS6453",
    "Verizon Business": "AS701",
    "Scalaxy": "AS58061",
    "Zenlayer": "AS21859",
    "BunnyCDN": "AS5065",
    "Edgio": "AS15133",
    "Edgio 2": "AS22843",
    "StackPath": "AS33438",
    "StackPath 2": "AS202384",
    "KeyCDN": "AS199653",
    "CacheFly": "AS30081",
    "Imperva_Incapsula": "AS19551",
}

HIGH_PRIORITY_DOMAINS = {
    "Amazon": ["amazon.com", "aws.amazon.com"],
    "Cloudflare": ["cloudflare.com"],
    "Akamai": ["akamai.com", "akamaitechnologies.com"],
    "Google Cloud": ["cloud.google.com", "googleapis.com"],
    "Microsoft Azure": ["azure.com", "microsoft.com"],
    "Hetzner": ["hetzner.com", "hetzner.de"],
    "DigitalOcean": ["digitalocean.com"],
    "OVH": ["ovh.com", "ovhcloud.com"],
}

API_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
TIMEOUT = 15


def extract_base_name(name):
    base = name.strip()
    if "," in base:
        base = base.split(",", 1)[0].strip()
    paren_match = re.match(r"^(.*?)(?:\s*\(.*\))?$", base)
    if paren_match:
        base = paren_match.group(1).strip()
    num_match = re.match(r"^(.*?)(?:\s*\d+)?$", base)
    if num_match:
        base = num_match.group(1).strip()
    return base.strip()


def load_asn_list(path):
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            print(f"[!] {path} 不是字典格式，使用内置 ASN_LIST", flush=True)
        except Exception as e:
            print(f"[!] 加载 {path} 失败：{e}，使用内置 ASN_LIST", flush=True)
    if not path:
        default_path = Path(__file__).resolve().parent.parent / "asn_list.json"
        if default_path.exists():
            try:
                with open(default_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    print(f"[i] 从 {default_path} 加载 ASN_LIST", flush=True)
                    return data
            except Exception as e:
                print(f"[!] 加载 {default_path} 失败：{e}，使用内置 ASN_LIST", flush=True)
    return ASN_LIST_DEFAULT


def fetch_asn_prefixes(name, asn, error_log):
    try:
        r = requests.get(
            API_URL,
            params={"resource": asn, "min_peers_seeing": 1},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json().get("data", {}).get("prefixes", [])
        v4_set = set()
        v6_set = set()
        count = 0
        for p in data:
            prefix = p.get("prefix")
            if not prefix:
                continue
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                if net.prefixlen == 0:
                    continue
                if not net.is_global:
                    continue
                if net.version == 4:
                    v4_set.add(net)
                else:
                    v6_set.add(net)
                count += 1
            except Exception:
                continue
        return (name, asn, True, v4_set, v6_set, count, None)
    except Exception as e:
        error_log.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] RIPE {name} ({asn}): {e}")
        return (name, asn, False, set(), set(), 0, str(e))


def resolve_domain(domain, error_log):
    v4_ips = set()
    v6_ips = set()
    ok = False
    last_err = None
    for family, target_set in ((socket.AF_INET, v4_ips), (socket.AF_INET6, v6_ips)):
        try:
            results = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            for res in results:
                ip_str = res[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_global:
                        target_set.add(ip)
                        ok = True
                except Exception:
                    continue
        except Exception as e:
            last_err = str(e)
    if not ok:
        error_log.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] DNS {domain}: {last_err or 'no records'}")
        return (domain, False, set(), set())
    return (domain, True, v4_ips, v6_ips)


def sort_key(net):
    return (net.version, int(net.network_address), net.prefixlen)


def collapse_nets(nets):
    if not nets:
        return []
    sorted_nets = sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))
    return list(ipaddress.collapse_addresses(sorted_nets))


def parse_args():
    parser = argparse.ArgumentParser(description="ASN 前缀抓取与域名解析聚合工具")
    parser.add_argument(
        "--output",
        type=str,
        default=".",
        help="输出目录，存放 ipset-all.txt、domains-all.txt、ipset-and-domains.txt (默认: 当前脚本父目录的上一级)",
    )
    parser.add_argument(
        "--source",
        type=str,
        choices=["ripe", "file"],
        default="ripe",
        help="CIDR 数据来源：ripe 表示从 RIPE stat 拉取，file 表示从已有 ipset-all.txt 解析 (默认: ripe)",
    )
    parser.add_argument(
        "--asn-list",
        type=str,
        default=None,
        help="自定义 ASN_LIST JSON 文件路径 (默认: 查找项目根下 asn_list.json，不存在则用内置列表)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="并发线程池大小，用于 RIPE stat 抓取和 DNS 解析 (默认: 4，最大: 16)",
    )
    args = parser.parse_args()
    args.workers = max(1, min(16, args.workers))
    return args


def load_ipset_from_file(path):
    v4_set = set()
    v6_set = set()
    if not os.path.exists(path):
        return v4_set, v6_set
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.prefixlen == 0:
                    continue
                if not net.is_global:
                    continue
                if net.version == 4:
                    v4_set.add(net)
                else:
                    v6_set.add(net)
            except Exception:
                continue
    return v4_set, v6_set


def main():
    args = parse_args()

    script_dir = Path(__file__).resolve().parent
    if args.output == ".":
        output_dir = script_dir.parent
    else:
        output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    ipset_path = output_dir / "ipset-all.txt"
    domains_path = output_dir / "domains-all.txt"
    merged_path = output_dir / "ipset-and-domains.txt"
    errors_path = output_dir / "errors.log"

    error_log = []

    asn_list = load_asn_list(args.asn_list)

    v4_all = set()
    v6_all = set()

    seen_asns = set()
    seen_base_names = set()

    if args.source == "ripe":
        print(f"[i] 从 RIPE stat 拉取前缀，并发数 {args.workers}", flush=True)
        tasks = []
        for name, asn in asn_list.items():
            base_name = extract_base_name(name)
            if asn in seen_asns:
                print(f"[skip] {name} ({asn}) ASN 已处理", flush=True)
                continue
            seen_asns.add(asn)
            tasks.append((name, asn, base_name))

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_map = {}
            for name, asn, base_name in tasks:
                fut = executor.submit(fetch_asn_prefixes, name, asn, error_log)
                future_map[fut] = (name, asn, base_name)

            for fut in as_completed(future_map):
                name, asn, base_name = future_map[fut]
                try:
                    result = fut.result()
                    r_name, r_asn, success, r_v4, r_v6, count, err = result
                    if success:
                        if base_name in seen_base_names:
                            print(f"[+] {r_name} ({r_asn}) ... {count} 前缀 [base {base_name} 已聚合]", flush=True)
                        else:
                            seen_base_names.add(base_name)
                            print(f"[+] {r_name} ({r_asn}) ... {count} 前缀", flush=True)
                        v4_all.update(r_v4)
                        v6_all.update(r_v6)
                    else:
                        print(f"[!] {r_name} ({r_asn}) 失败：{err}", flush=True)
                except Exception as e:
                    print(f"[!] {name} ({asn}) 异常：{e}", flush=True)
                    error_log.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Worker {name} ({asn}): {e}")
    else:
        print(f"[i] --source=file：跳过网络拉取，从 {ipset_path} 加载 CIDR", flush=True)
        loaded_v4, loaded_v6 = load_ipset_from_file(str(ipset_path))
        v4_all.update(loaded_v4)
        v6_all.update(loaded_v6)
        print(f"    IPv4: {len(loaded_v4)} | IPv6: {len(loaded_v6)}", flush=True)

    v4_agg = collapse_nets(v4_all)
    v6_agg = collapse_nets(v6_all)
    ipset_v4_sorted = sorted(v4_agg, key=sort_key)
    ipset_v6_sorted = sorted(v6_agg, key=sort_key)

    with open(str(ipset_path), "w", encoding="utf-8") as f:
        for net in ipset_v4_sorted:
            f.write(str(net) + "\n")
        for net in ipset_v6_sorted:
            f.write(str(net) + "\n")
    print(f"\n[i] ipset-all.txt 写入完成：IPv4 {len(ipset_v4_sorted)} | IPv6 {len(ipset_v6_sorted)} | 总计 {len(ipset_v4_sorted) + len(ipset_v6_sorted)}", flush=True)

    print(f"\n[i] 开始域名解析，并发数 {args.workers}", flush=True)
    processed_bases = set()
    ordered_domains = []
    domain_resolve_tasks = []
    for name in asn_list.keys():
        base_name = extract_base_name(name)
        if base_name in processed_bases:
            continue
        processed_bases.add(base_name)
        if base_name in HIGH_PRIORITY_DOMAINS:
            for d in HIGH_PRIORITY_DOMAINS[base_name]:
                ordered_domains.append(d)
                domain_resolve_tasks.append(d)

    domain_results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {}
        for d in domain_resolve_tasks:
            fut = executor.submit(resolve_domain, d, error_log)
            future_map[fut] = d

        for fut in as_completed(future_map):
            d = future_map[fut]
            try:
                domain, ok, v4_ips, v6_ips = fut.result()
                if ok:
                    print(f"[d] {domain} ... A:{len(v4_ips)} AAAA:{len(v6_ips)}", flush=True)
                    domain_results[domain] = (v4_ips, v6_ips)
                else:
                    print(f"[d] {domain} ... 解析失败 (已记录 errors.log)", flush=True)
            except Exception as e:
                print(f"[d] {d} ... 异常：{e}", flush=True)
                error_log.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] DNS Worker {d}: {e}")

    ordered_success = [d for d in ordered_domains if d in domain_results]

    domain_v4_aggregated = {}
    domain_v6_aggregated = {}
    all_domain_v4 = set()
    all_domain_v6 = set()
    for d in ordered_success:
        v4_ips, v6_ips = domain_results[d]
        v4_nets = set()
        v6_nets = set()
        for ip in v4_ips:
            v4_nets.add(ipaddress.ip_network(ip))
        for ip in v6_ips:
            v6_nets.add(ipaddress.ip_network(ip))
        v4_collapsed = collapse_nets(v4_nets)
        v6_collapsed = collapse_nets(v6_nets)
        domain_v4_aggregated[d] = sorted(v4_collapsed, key=sort_key)
        domain_v6_aggregated[d] = sorted(v6_collapsed, key=sort_key)
        all_domain_v4.update(v4_collapsed)
        all_domain_v6.update(v6_collapsed)

    with open(str(domains_path), "w", encoding="utf-8") as f:
        for d in ordered_success:
            v4_list = domain_v4_aggregated.get(d, [])
            v6_list = domain_v6_aggregated.get(d, [])
            if v4_list or v6_list:
                f.write(f"# domain: {d}\n")
                for net in v4_list:
                    f.write(str(net) + "\n")
                for net in v6_list:
                    f.write(str(net) + "\n")
    total_domain_v4 = sum(len(v) for v in domain_v4_aggregated.values())
    total_domain_v6 = sum(len(v) for v in domain_v6_aggregated.values())
    print(f"\n[i] domains-all.txt 写入完成：IPv4 {total_domain_v4} | IPv6 {total_domain_v6} | 域 {len(ordered_success)}", flush=True)

    merged_v4 = set(ipset_v4_sorted) | all_domain_v4
    merged_v6 = set(ipset_v6_sorted) | all_domain_v6
    merged_v4_sorted = sorted(collapse_nets(merged_v4), key=sort_key)
    merged_v6_sorted = sorted(collapse_nets(merged_v6), key=sort_key)

    with open(str(merged_path), "w", encoding="utf-8") as f:
        for net in merged_v4_sorted:
            f.write(str(net) + "\n")
        for net in merged_v6_sorted:
            f.write(str(net) + "\n")
    print(f"[i] ipset-and-domains.txt 写入完成：IPv4 {len(merged_v4_sorted)} | IPv6 {len(merged_v6_sorted)} | 总计 {len(merged_v4_sorted) + len(merged_v6_sorted)}", flush=True)

    if error_log:
        with open(str(errors_path), "w", encoding="utf-8") as f:
            for line in error_log:
                f.write(line + "\n")
        print(f"[i] errors.log 写入 {len(error_log)} 条错误记录", flush=True)
    elif errors_path.exists():
        try:
            errors_path.unlink()
        except Exception:
            pass

    print("\nГотово! / 完成!")
    print(f"  ipset-all.txt        -> {ipset_path}")
    print(f"  domains-all.txt      -> {domains_path}")
    print(f"  ipset-and-domains.txt-> {merged_path}")
    if error_log:
        print(f"  errors.log           -> {errors_path}")


if __name__ == "__main__":
    main()
