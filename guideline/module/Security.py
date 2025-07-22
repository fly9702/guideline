import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from util.Static_util import util
from vo.Host import Host
from vo.Info import Info
import datetime
import re


class Security:
#    def S_00(host):
#        command = "ip a"
#        is_safe = False
#        score = 0

        #명령어가 여러 줄일 때만 수정 필요
#        time = 10

        #1. host 정보를 받아서 paramiko/netmiko로 특정 명령어를 전송한다.
#        response = util.para_connect(host,command,time)
        #print(reponse)
        #2. 응답(response)에서 필요한 결과값을 뽑아낸다.
#        result = response
        #3. 정보값을 바탕으로 지키고 있는지 안 지키고 있는지 판단한다. -> 지켰으면 is_safe, score 값을 바꿔준다.
#        if "ens160" in result :
#            is_safe = True
#            score = 3
#        else :
#            print("no")
        #4. 정보 객체 생성 - 날짜, 호스트, 영역, 점검코드, 결과/ 점수(중요도)
            # date(날짜 정보) 생성
#        date = datetime.datetime.now().strftime("%Y-%m-%d")
        #print(date)
#        info = Info(host.id,date,"W_01",command,result,is_safe,score)
        #5. 정보 객체 반환
#        return info

    def S_01(host):
        command = ""
        is_safe = False
        score = 0

        time = 10

        category = host.category.lower()

        if category == "pfsense":
            command = "cat /etc/passwd | grep admin"
        elif category == "securityonion":
            command = "cat /etc/sudoers | grep root"
        else:
            print("잘못된 호스트 입니다.")

        response = util.para_connect(host,command,time)
        result = response
        result = re.sub(r'\s+', ' ', result)

        if "admin" in result or "root" in result:
            print("취약")
        else :
            is_safe = True
            score = 3
            print("양호")
        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id,date,"S_01",command,result,is_safe,score)

        return info
    
    def S_07(host):
        command = ""
        is_safe = False
        score = 0

        time = 10

        category = host.category.lower()

        print("점검 기준은 180초 입니다.")

        if category == "pfsense":
            command = 'grep -B 5 -A 5 "<statetimeout>" /conf/config.xml'
            response = util.para_connect(host,command,time)
            result = response
            m = re.search(r'<statetimeout><!\[CDATA\[(\d+)\]\]></statetimeout>', result)
            if m:
                timeout_val = int(m.group(1))
                if 1 <= timeout_val <= 180:
                    is_safe = True
                    score = 3
                    print("양호")
                else :
                    print("취약")
            else:
                print("취약")  
        elif category == "securityonion":
            command = "cat /etc/ssh/sshd_config | grep ClientAlive"
            response = util.para_connect(host,command,time)
            result = response
            lines = result.splitlines()
            interval = None
            countmax = None
            for line in lines:
                if line.startswith("ClientAliveInterval"):
                    interval = int(line.split()[1])
                elif line.startswith("ClientAliveCountMax"):
                    countmax = int(line.split()[1])

            if interval is None or countmax is None:
                print("취약 - 설정값 누락")
            else:
                total = interval * countmax
                if 1 <= total <= 180:
                    is_safe = True
                    score = 3
                    print(f"양호 : 설정 값은 {interval} * {countmax} 총 {total}입니다.")
                else:
                    print("취약")

        else:
            print("잘못된 호스트 입니다.")

        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id,date,"S_07",command,result,is_safe,score)

        return info
    
    def S_08(host):
        time = 10
        category = host.category.lower()
        is_safe = True
        score = 3
        messages = []

        if category == "pfsense":
            command = "cat /etc/version && snort --version 2>&1"
            result = util.para_connect(host, command, time)

            pf_latest_version = "2.7.2-RELEASE"
            if pf_latest_version in result:
                messages.append(f"pfSense 버전은 최신버전입니다. ({pf_latest_version})")
            else:
                is_safe = False
                score = 0
                messages.append(f"pfSense 구형 버전입니다. ({result.strip()})")

            cleaned_result = re.sub(r'\s+', ' ', result)
            m = re.search(r'Version\s+(\d+\.\d+\.\d+)', cleaned_result, re.IGNORECASE)
            snort_latest_version = "2.9.20"
            if m:
                snort_version = m.group(1)
                if snort_version >= snort_latest_version:
                    messages.append(f"Snort 버전은 최신버전입니다. ({snort_version})")
                else:
                    is_safe = False
                    score = 0
                    messages.append(f"Snort 버전은 구형버전입니다. ({snort_version})")
            else:
                is_safe = False
                score = 0
                messages.append("Snort 버전 정보를 확인할 수 없습니다.")

        elif category == "securityonion":
            command = "cat /etc/os-release && snort --version 2>&1"
            result = util.para_connect(host, command, time)

            cleaned_result = re.sub(r'\s+', ' ', result)
            if re.search(r'VERSION_ID="?Security Onion 2\.3"?', cleaned_result):
                messages.append("SecurityOnion 버전은 최신버전입니다. (2.3)")
            else:
                is_safe = False
                score = 0
                messages.append(f"SecurityOnion 구형 버전입니다. ({cleaned_result.strip()})")

            m = re.search(r'Version\s+(\d+\.\d+\.\d+)', cleaned_result, re.IGNORECASE)
            snort_latest_version = "2.9.17.1"
            if m:
                snort_version = m.group(1)
                if snort_version >= snort_latest_version:
                    messages.append(f"Snort 버전은 최신버전입니다. ({snort_version})")
                else:
                    is_safe = False
                    score = 0
                    messages.append(f"Snort 버전은 구형버전입니다. ({snort_version})")
            else:
                is_safe = False
                score = 0
                messages.append("Snort 버전 정보를 확인할 수 없습니다.")

        else:
            print("잘못된 호스트입니다.")
            return None

        for msg in messages:
            print(msg)

        if is_safe:
            print("최종 결과: 양호")
        else:
            print("최종 결과: 취약")

        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id, date, "S_08", command, result, is_safe, score)
        return info
    
    def S_15(host):
        category = host.category.lower()
        is_safe = False
        score = 0

        time = 10

        if category == "pfsense":
            command = "service snmpd onestatus"
            response = util.para_connect(host,command,time)
            result = response

            if "snmpd is not running" in result:
                is_safe = True
                score = 3
                print("SNMP가 실행 중이지 않습니다. = 양호")
            else :
                print("SNMP가 실행 중 입니다. = 취약")
        
        elif category == "securityonion":
            command = "systemctl status snmpd"
            response = util.para_connect(host,command,time)
            result = response

            if "Active: inactive" in result:
                is_safe = True
                score = 3
                print("SNMP가 실행 중이지 않습니다. = 양호")
            else:
                print("SNMP가 실행 중 입니다. = 취약")
        
        else:
            print("잘못된 호스트입니다.")


        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id,date,"S_15",command,result,is_safe,score)

        return info 
    def S_20(host):
        category = host.category.lower()
        is_safe = True
        score = 2
        time = 10

        vulnerable_count = 0
        safe_count = 0

        
        if category == "pfsense":
            command = "cat /var/etc/newsyslog.conf.d/pfSense.conf"
            response = util.para_connect(host,command,time)

            result = response.strip()
            result = re.sub(r'\s+', ' ', result)

            lines = result.splitlines()
            
            ll = []

            for line in lines:
                if line.startswith("/var/log"):
                    parts = line.split()
                    filename = os.path.basename(parts[0])
                    if len(parts) >= 4 :
                        try:
                            period = int(parts[3])
                            ll.append((filename, period))
                        except ValueError:
                            pass
            
            max_len = max(len(f[0]) for f in ll) if ll else 0

            for filename, period in ll:
                if period < 30:
                    print(f"파일명: {filename:<{max_len}} 보존 기간: {period}일 == 결과: 취약!!!")
                    is_safe = False
                    score = 0
                    vulnerable_count += 1
                else:
                    print(f"파일명: {filename:<{max_len}} 보존 기간: {period}일 == 결과: 양호!!!")
                    safe_count += 1
            
            print("점검 기준은 30일 입니다.")
            
            if vulnerable_count > 0:
                
                print(f"취약 {vulnerable_count}개, 양호 {safe_count}개 → 최종 결과: 취약")
            else:
                print(f"양호 {safe_count}개 → 최종 결과: 전부 양호")
        
        elif category == "securityonion":
            command = "grep -E 'rotate|daily|weekly|monthly' /etc/logrotate.d/*"
            response = util.para_connect(host,command,time)
            result = response.strip()
            files = {}

            for line in result.splitlines():
                line = line.strip()
                if not line or ':' not in line:
                    continue

                filepath, val = line.split(':', 1)
                filename = os.path.basename(filepath.strip())
                val = val.strip()

                if filename not in files:
                    files[filename] = {'unit': None, 'rotate': None}
                
                if val in ['daily', 'weekly', 'monthly']:
                    files[filename]['unit'] = val

                elif val.startswith('rotate'):
                    parts = val.split()
                    if len(parts) == 2 and parts[1].isdigit():
                        files[filename]['rotate'] = int(parts[1])

        max_len = max(len(f) for f in files)

        for filename, info in files.items():
            unit = info['unit']
            rotate = info['rotate']

            if unit == 'daily':
                period_days = 1 * (rotate if rotate else 0)
            elif unit == 'weekly':
                period_days = 7 * (rotate if rotate else 0)
            elif unit == 'monthly':
                period_days = 30 * (rotate if rotate else 0)
            else:
                period_days = 0

            if period_days == 0:
                print(f"파일명: {filename:<{max_len}} 보존 기간 정보 부족 == 결과: 취약!!!")
                is_safe = False
                score = 0
                vulnerable_count += 1
            elif period_days < 30:
                print(f"파일명: {filename:<{max_len}} 보존 기간: {period_days:<5}일 == 결과: 취약!!!")
                is_safe = False
                score = 0
                vulnerable_count += 1
            else:
                print(f"파일명: {filename:<{max_len}} 보존 기간: {period_days:<5}일 == 결과: 양호!!!")
                safe_count += 1

        print("점검 기준은 30일 입니다.")
        if vulnerable_count > 0:
            print(f"취약 {vulnerable_count}개, 양호 {safe_count}개 → 최종 결과: 취약")
        else:
            print(f"양호 {safe_count}개 → 최종 결과: 전부 양호")
                        

        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id,date,"S_20",command,result,is_safe,score)

        return info

    def S_22(host):
        command = "cat /var/etc/syslog.d/pfSense.conf | grep @"
        is_safe = False
        score = 0

        time = 10

        response = util.para_connect(host,command,time)

        result = response.strip()
        result = re.sub(r'\s+', ' ', result)

        if result:
            is_safe = True
            score = 2
            print("로그 서버 설정이 있습니다. : 양호")
        else :
            print("로그 서버 설정이 없습니다. : 취약")

        date = datetime.datetime.now().strftime("%Y-%m-%d")

        info = Info(host.id,date,"S_25",command,result,is_safe,score)

        return info 
    
security = Security()
    
    



# Test
# 상황에 맞게 값 수정 가능
#hosta = Host(1,"pfsense","rocky17","172.16.13.250","root","asd123!@")
#hostb = Host(1,"securityonion","rocky17","172.16.13.150","root","asd123!@")

#info = security.S_15(hostb)
#print(vars(info))

