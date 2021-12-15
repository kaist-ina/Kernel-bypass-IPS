# 저지연을 위한 Kernel-bypass 기반 IPS

본 오픈소스 프로젝트는 기존 미들박스 OS(mOS)가 지원하는 kernel-bypass 네트워킹 스택을 활용하여 IPS(Intrusion Prevention System) 애플리케이션으로 확장한다.
미들박스 OS는 DPDK 라이브러리를 사용하여 고성능 패킷 I/O를 지원한다.
본 소프트웨어는 이 미들박스 OS 상에서 능동적으로 네트워크 트래픽을 분석 및 제어할 수 있도록 관련 API를 수정/추가 하여 제작되었다.

## System Requirements

### Hardware Requirements

Kernel-bypass 기반 IPS는 내부적으로 [DPDK](https://www.dpdk.org)를 사용한다.
따라서 DPDK를 지원하는 네트워크 카드가 필요하다.

### Software requirements

프로그램을 컴파일 하기 위해 다음 라이브러리를 설치해야한다.

* libpthread
* libnuma
* librt
* libglib2.0-0
* libhugetlbfs-dev
* Linux kernel headers

이 외에도 DPDK 설치 관련 라이브러리는 이 [링크](https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html)를 참고하며,
mOS-networking-stack 라이브러리 설치는 이 [링크](https://github.com/mos-stack/mOS-networking-stack)를 참고한다.

## 설치 과정

1. DPDK 설치

DPDK 18.11을 mOS/drivers 에 설치합니다. 디렉토리 이름은 dpdk/ 로 설정한다.


2. mOS 컴파일 및 DPDK 설정

```bash
$ ./setup --compile-dpdk
$ ./setup --run-dpdk
```

mOS 컴파일 및 DPDK 설정과 관련한 자세한 사항은 다음 [링크](https://mos.kaist.edu/guide/walkthrough/03_setup.html)를 참고한다.

3. Kernel-bypass IPS 컴파일

```bash
$ cd proj/kernel-bypass-IPS/
$ ./builder.sh
```

4. Kernel-bypass IPS 실행

Kernel-bypass IPS를 실행할 때 exact string pattern matching에 사용될 룰셋의 파일 경로를 지정한다.
(룰셋 파일은 각 줄마다 pattern matching에 사용될 string으로 구성한다.)
Kernel-bypass IPS를 루트권한으로 실행한다.

```bash
$ sudo ./ips -r "룰셋 파일 경로"
```