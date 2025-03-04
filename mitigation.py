import requests
import json
import time
targetedSwitch = '00:00:00:e0:4c:36:03:30'
sFlow_RT = 'http://10.1.20.10:8008'
floodlight = 'http://10.1.20.10:8080'
defense = {'icmp': True, 'syn': False, 'dns_amplifier': False, 'udp': True}
black_list_icmp = []
block_time = 1200
fw_priority = '32767'
groups = {'external': ['0.0.0.0/0'], 'internal': ['0.0.0.0/0']} # value = 'bytes' # set to 'bytes' and multiply 8 to get bits/second
# define ICMP flood attack attributes #
icmp_flood_keys = 'inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination'
icmp_flood_metric_name = 'icmp_flood'
icmp_flood_threshold_value = 50000
#icmp_flood_filter = 'group:ipsource:lf=external&group:ipdestination:lf=internal&outputif index!=discard&ipprotocol=1'
icmp_flood_flows = {'keys': icmp_flood_keys, 'value': 'bytes'} # No filter, the script will monitor every host
icmp_flood_threshold = {'metric': icmp_flood_metric_name, 'value': icmp_flood_threshold_value}
# définir UDP invite attack attributes #
sip_invite_keys = 'inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination'
sip_invite_metric_name = 'udp_invite'
sip_invite_threshold_value = 50000
sip_invite_flows = {'keys': sip_invite_keys, 'value': 'bytes'} # No filter, the script will monitor every host
sip_invite_threshold = {'metric': sip_invite_metric_name, 'value': sip_invite_threshold_value}
black_list_sip = []
while True:
    r = -1
    #r = requests.put(sFlow_RT + '/group/json', data=json.dumps(groups))
    r = requests.put(sFlow_RT + '/group/lf/json', data=json.dumps(groups))
    if defense['icmp']:
        # define flows and threshold of ICMP flood
        r = requests.put(sFlow_RT + '/flow/' + icmp_flood_metric_name + '/json',data=json.dumps(icmp_flood_flows))
        r = requests.put(sFlow_RT + '/threshold/' + icmp_flood_metric_name + '/json',data=json.dumps(icmp_flood_threshold))
        event_url = sFlow_RT + '/events/json?maxEvents=10&timeout=60'
        eventID = -1
        print('black list icmp:',black_list_icmp)
        if black_list_icmp.__len__() > 0 and black_list_icmp[0][0] < time.time():
            r = requests.delete(floodlight + '/wm/staticflowpusher/json', data=black_list_icmp.pop(0)[1])
            print(r.json()['status'])
        r = requests.get(event_url + '&eventID=' + str(eventID)) 
        events = r.json()
        if events.__len__() > 0:
            eventID = events[0]["eventID"] 
            events.reverse()
            for e in events:
                if e['metric'] == icmp_flood_metric_name:
                    r = requests.get(sFlow_RT + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
                    metrics = r.json()
                    if metrics and metrics.__len__() > 0:
                        metric = metrics[0]
                        if metric.__contains__("metricValue") and metric['metricValue'] > icmp_flood_threshold_value and metric['topKeys'] and metric['topKeys'].__len__() > 0:
                            for topKey in metric['topKeys']:
                                if topKey['value'] > icmp_flood_threshold_value:
                                    key = topKey['key'] 
                                    parts = key.split(',')
                                    message = {'switch':targetedSwitch,'name': 'ICMP_block_'+str(parts[5]), "cookie":"0","priority": fw_priority,'ipv4_src': str(parts[5]),'ipv4_dst': str(parts[6]), "active":"true","eth_type":"0x0800", } # pas d'action = drop
                                    print(message)
                                    push_data = json.dumps(message) 
                                    r = requests.post(floodlight + '/wm/staticflowpusher/json', data=push_data)
                                    black_list_icmp.append([time.time()+block_time, push_data])
                                    result = r.json()
                                    print({result['status']}) 
                                    break
                                else:
                                    continue
                    break

    if defense['udp']:
        r = requests.put(sFlow_RT + '/flow/' + sip_invite_metric_name + '/json',data=json.dumps(sip_invite_flows))
        r = requests.put(sFlow_RT + '/threshold/' + sip_invite_metric_name + '/json',data=json.dumps(sip_invite_threshold))
        event_url = sFlow_RT + '/events/json?maxEvents=10&timeout=60'
        eventID = -1
        print('black list sip udp:',black_list_sip)
        if black_list_sip.__len__() > 0 and black_list_sip[0][0] < time.time():
            r = requests.delete(floodlight + '/wm/staticflowpusher/json', data=black_list_sip.pop(0)[1])
            print(r.json()['status'])
        r = requests.get(event_url + '&eventID=' + str(eventID)) 
        events = r.json()
        if events.__len__() > 0:
            eventID = events[0]["eventID"] 
            events.reverse()
            for e in events:
                if e['metric'] == sip_invite_metric_name:
                    r = requests.get(sFlow_RT + '/metric/' + e['agent'] + '/' + e['dataSource'] + '.' + e['metric'] + '/json')
                    metrics = r.json()
                    if metrics and metrics.__len__() > 0:
                        metric = metrics[0]
                        if metric.__contains__("metricValue") and metric['metricValue'] > sip_invite_threshold_value and metric['topKeys'] and metric['topKeys'].__len__() > 0:
                            for topKey in metric['topKeys']:
                                if topKey['value'] > sip_invite_threshold_value:
                                    key = topKey['key'] 
                                    parts = key.split(',')
                                    message = {'switch':targetedSwitch,'name': 'SIP_block_'+str(parts[5]), "cookie":"0","priority": fw_priority,'ipv4_src': str(parts[5])+'/24','ipv4_dst': str(parts[6])+'/24', "active":"true","eth_type":"0x0800", } # pas d'action = drop
                                    print(message)
                                    print("========================")
                                    push_data = json.dumps(message) 
                                    r = requests.post(floodlight + '/wm/staticflowpusher/json', data=push_data)
                                    black_list_sip.append([time.time()+block_time, push_data])
                                    result = r.json()
                                    print({result['status']}) 
                                    break
                                else:
                                    continue
                    break


    time.sleep(3)
