# SSH 기반 CTF 상호작용 패턴

## Origin
pwnable.kr Toddler's Bottle 20+ 문제를 풀면서 확립한 SSH 기반 챌린지 상호작용 패턴.
핵심 교훈: **pexpect은 SSH에서 불안정**. paramiko + nc 파이프가 가장 안정적.

---

## 패턴 분류 (난이도순)

### 패턴 1: One-shot 명령 실행 (가장 간단)
**적합**: 인자 전달만으로 풀리는 문제 (fd, collision, random, cmd1, cmd2)

```python
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('pwnable.kr', port=2222, username='USER', password='guest', timeout=10)

stdin, stdout, stderr = ssh.exec_command('./binary "argument"', timeout=10)
print(stdout.read().decode())
ssh.close()
```

**장점**: 가장 단순, 타임아웃 관리 쉬움
**한계**: stdin 상호작용 불가

### 패턴 2: nc 파이프 (간단한 상호작용)
**적합**: 포트 기반 서비스 + 입력 순서가 고정된 문제 (blackjack, memcpy)

```python
# 서버에서 nc로 입력을 파이프
cmd = r"""echo -e 'input1\ninput2\ninput3\n' | nc -w 5 localhost PORT 2>&1"""
stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
out = stdout.read().decode('latin-1')
```

**장점**: 상호작용 불필요한 고정 입력에 최적, 반복 실행 쉬움
**한계**: 동적 응답 기반 분기 불가 (이전 출력을 보고 다음 입력 결정 불가)
**팁**:
- `-w 5`로 타임아웃 설정 필수
- `2>&1`로 stderr 캡처
- `| tail -N`으로 큰 출력 필터링
- 반복 시도: bash for 루프로 감싸기

### 패턴 3: SSH 터널 + pwntools remote() (복잡한 상호작용)
**적합**: 동적 응답 기반 상호작용 필요 (horcruxes, asm)

```python
import paramiko, socket, threading, select

# 1. SSH 터널 설정
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('pwnable.kr', port=2222, username='USER', password='guest')
transport = ssh.get_transport()

# 로컬 포트 -> 원격 localhost:PORT 터널
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind(('127.0.0.1', LOCAL_PORT))
server_sock.listen(1)

def handle_client(client_sock):
    chan = transport.open_channel('direct-tcpip',
                                  ('localhost', REMOTE_PORT),
                                  client_sock.getpeername())
    while True:
        r, w, x = select.select([client_sock, chan], [], [], 1.0)
        if client_sock in r:
            data = client_sock.recv(4096)
            if not data: break
            chan.sendall(data)
        if chan in r:
            data = chan.recv(4096)
            if not data: break
            client_sock.sendall(data)
    chan.close()
    client_sock.close()

# 터널 스레드 시작
threading.Thread(target=lambda: ..., daemon=True).start()

# 2. pwntools로 연결
from pwn import *
p = remote('127.0.0.1', LOCAL_PORT)
p.recvuntil(b'prompt')
p.sendline(b'input')
# ... 동적 상호작용 ...
```

**장점**: pwntools의 모든 기능 사용 가능 (recvuntil, sendlineafter 등)
**한계**: 터널 설정 코드가 김, 포트 충돌 주의
**팁**: LOCAL_PORT를 20000+ 대역으로 설정 (충돌 방지)

### 패턴 4: 서버 업로드 스크립트 (복잡한 로컬 상호작용)
**적합**: 확률적 반복 필요 + 동적 응답 파싱 (lotto, coin1)

```python
# 1. Python 솔버 스크립트를 서버에 업로드
sftp = ssh.open_sftp()
sftp.put('/tmp/solver.py', '/tmp/solver.py')
sftp.close()

# 2. 서버에서 실행
stdin, stdout, stderr = ssh.exec_command('python3 /tmp/solver.py', timeout=120)
out = stdout.read().decode('latin-1')
```

**서버 스크립트에서 사용 가능한 방법**:
- `subprocess.Popen` + communicate() — 단순 상호작용
- `socket.connect(('localhost', PORT))` — 포트 기반 서비스
- `os.openpty()` + fork — 복잡한 터미널 상호작용 (주의: 일부 환경에서 불안정)

**장점**: 서버 내부에서 실행 → 네트워크 지연 없음, localhost 직접 접속
**한계**: 파이썬 버전/라이브러리 제약, 따옴표 이스케이프 주의
**팁**: heredoc이 아닌 **파일로 작성 후 sftp 업로드** (이스케이프 문제 방지)

---

## 패턴 선택 가이드

```
문제가 인자만으로 풀림?
  → Yes: 패턴 1 (paramiko exec_command)
  → No: 포트 기반 서비스?
    → Yes: 입력이 고정적?
      → Yes: 패턴 2 (nc 파이프)
      → No: pwntools 기능 필요?
        → Yes: 패턴 3 (SSH 터널)
        → No: 패턴 4 (서버 스크립트)
    → No: stdin 상호작용?
      → 단순: 패턴 2 (echo | ./binary)
      → 복잡: 패턴 4 (서버 스크립트)
```

---

## 안티패턴 (하지 말 것)

1. **pexpect SSH**: 터미널 제어문자(`\x01`, `\x1b[2J`)로 매칭 실패, 타임아웃 빈발
2. **paramiko invoke_shell**: sleep 기반 타이밍 → 불안정, 느림
3. **sshpass + bash**: 설치 안 된 환경 많음, paramiko가 범용적
4. **서버에서 os.openpty()**: 일부 제한 환경에서 `OSError: Input/output error`

---

## 에러 복구 전략

**에러 시 즉시 다음 패턴으로 전환. 멈추지 말 것.**

```
패턴 N 실패 → 패턴 N+1 시도 (최대 3초 내 전환)
3개 패턴 모두 실패 → 문제 구조 재분석
```

사용자 피드백: "에러뜰때마다 왜 멈추는겨?" → **에러 = 즉시 대안 시도**
